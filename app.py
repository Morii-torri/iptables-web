#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2025/7/23 16:55
# @Author  : lsy
# @FileName: app.py
# @Software: PyCharm
# @Function:
import random
from functools import wraps
import sqlite3
import re
import paramiko
from paramiko.client import AutoAddPolicy
import math
from io import StringIO
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session, g
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import time
import json
from flask_apscheduler import APScheduler
from datetime import datetime, timedelta
import pytz

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# 配置登录管理器
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '请先登录以访问该页面'

ssh = paramiko.SSHClient()
DATABASE = 'firewall_management.db'
# 确保静态文件目录正确配置
app.static_folder = 'static'

# 新增：初始化调度器
scheduler = APScheduler()


# 生成6位随机小写英文字母组成的名字
def random_name(length=6):
    # 定义小写英文字母范围（a-z对应的ASCII码是97-122）
    letters = [chr(i) for i in range(97, 123)]  # 等价于 ['a','b',...,'z']
    # 从letters中随机选6个字符，拼接成字符串
    return ''.join(random.choice(letters) for _ in range(length))

# 新增：日志清理任务
def clean_expired_logs():
    """清理过期日志"""
    # 【修复】添加应用上下文
    with app.app_context():
        db = get_db()
        try:
            cursor = db.cursor()

            # 获取日志保留时间配置
            cursor.execute('SELECT log_retention_time FROM system_config LIMIT 1')
            config = cursor.fetchone()

            # 日志保留时间为0或未配置，表示永久保留
            if not config or not config['log_retention_time'] or config['log_retention_time'] == '0':
                return

            # 计算过期日期
            retention_days = int(config['log_retention_time'])
            if retention_days <= 0:
                return

            # 计算需要保留的最早日期
            expire_date = (datetime.now() - timedelta(days=retention_days)).strftime('%Y-%m-%d %H:%M:%S')

            # 删除过期日志
            cursor.execute('DELETE FROM operation_logs WHERE operation_time < ?', (expire_date,))
            deleted_count = cursor.rowcount
            db.commit()

            app.logger.info(f"清理过期日志成功，共删除 {deleted_count} 条记录")

        except Exception as e:
            db.rollback()
            app.logger.error(f"清理过期日志失败: {str(e)}")


# 正确配置调度器（无需创建新的app实例）
scheduler.init_app(app)
scheduler.add_job(
    id='clean_expired_logs',
    func=clean_expired_logs,
    trigger='cron',
    hour=2,
    minute=0
)
scheduler.start()

DEFAULT_HOST_GROUP_NAME = '未分组'
DEFAULT_HOST_GROUP_COLOR = '#6b7280'
DEFAULT_TEMPLATE_GROUP_COLOR = '#6366f1'


def current_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def normalize_limit_value(limit_value):
    if limit_value is None:
        return ''
    text = str(limit_value).strip()
    return re.sub(r'(?i)(kb/s|mb/s|gb/s)$', '', text)


def build_rule_signature(rule_data):
    """为主机规则生成唯一签名"""
    return '|'.join([
        str(rule_data.get('target', '')).strip(),
        str(rule_data.get('prot') or rule_data.get('protocol', '')).strip(),
        str(rule_data.get('source') or rule_data.get('auth_object', '')).strip(),
        str(rule_data.get('destination', '')).strip(),
        str(rule_data.get('port', '')).strip(),
        str(rule_data.get('comment') or rule_data.get('description', '')).strip(),
        normalize_limit_value(rule_data.get('limit'))
    ])


def ensure_host_group(cursor, host_id, group_name, label_color=None, template_group_id=None, is_default=0):
    """确保主机分组存在"""
    cursor.execute(
        'SELECT id, label_color, template_group_id FROM host_rule_groups WHERE host_id = ? AND group_name = ?',
        (host_id, group_name)
    )
    existing = cursor.fetchone()
    now = current_timestamp()
    color = label_color or DEFAULT_HOST_GROUP_COLOR
    if existing:
        needs_update = False
        update_params = []
        if template_group_id and existing['template_group_id'] != template_group_id:
            needs_update = True
        if existing['label_color'] != color:
            needs_update = True
        if needs_update:
            cursor.execute(
                'UPDATE host_rule_groups SET label_color = ?, template_group_id = ?, updated_at = ? WHERE id = ?',
                (color, template_group_id, now, existing['id'])
            )
        return existing['id']

    cursor.execute(
        '''
        INSERT INTO host_rule_groups
        (host_id, group_name, label_color, template_group_id, is_default, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''',
        (host_id, group_name, color, template_group_id, is_default, now, now)
    )
    return cursor.lastrowid


def ensure_default_host_group(cursor, host_id):
    cursor.execute(
        'SELECT id, group_name, label_color FROM host_rule_groups WHERE host_id = ? AND is_default = 1',
        (host_id,)
    )
    group_row = cursor.fetchone()
    if group_row:
        return group_row
    group_id = ensure_host_group(cursor, host_id, DEFAULT_HOST_GROUP_NAME, DEFAULT_HOST_GROUP_COLOR, None, 1)
    return {'id': group_id, 'group_name': DEFAULT_HOST_GROUP_NAME, 'label_color': DEFAULT_HOST_GROUP_COLOR}


def fetch_host_groups(host_id):
    db = get_db()
    cursor = db.cursor()
    default_group = ensure_default_host_group(cursor, host_id)
    cursor.execute(
        'SELECT id, group_name, label_color, is_default FROM host_rule_groups WHERE host_id = ? ORDER BY is_default DESC, group_name',
        (host_id,)
    )
    rows = cursor.fetchall()
    if not rows:
        rows = [default_group]
    db.commit()
    result = []
    for row in rows:
        if isinstance(row, sqlite3.Row):
            result.append(dict(row))
        else:
            result.append(row)
    return result


def sync_host_rules(host_id, direction, parsed_rules):
    """同步主机规则信息到数据库"""
    db = get_db()
    cursor = db.cursor()
    default_group = ensure_default_host_group(cursor, host_id)
    cursor.execute(
        'SELECT id, signature FROM host_rules WHERE host_id = ? AND direction = ?',
        (host_id, direction)
    )
    existing_rows = cursor.fetchall()
    existing_map = {row['signature']: row['id'] for row in existing_rows}
    seen_signatures = set()
    now = current_timestamp()
    for rule in parsed_rules:
        signature = build_rule_signature(rule)
        seen_signatures.add(signature)
        cursor.execute(
            '''
            SELECT hr.id, hr.host_group_id, hrg.group_name, hrg.label_color
            FROM host_rules hr
            LEFT JOIN host_rule_groups hrg ON hr.host_group_id = hrg.id
            WHERE hr.host_id = ? AND hr.direction = ? AND hr.signature = ?
            ''',
            (host_id, direction, signature)
        )
        record = cursor.fetchone()
        if record:
            group_name = record['group_name'] or default_group['group_name']
            group_color = record['label_color'] or default_group['label_color']
            host_group_id = record['host_group_id'] or default_group['id']
            if not record['host_group_id']:
                cursor.execute(
                    'UPDATE host_rules SET host_group_id = ?, updated_at = ? WHERE id = ?',
                    (host_group_id, now, record['id'])
                )
            rule['group_name'] = group_name
            rule['group_color'] = group_color
            rule['host_rule_id'] = record['id']
            rule['host_group_id'] = host_group_id
        else:
            cursor.execute(
                '''
                INSERT INTO host_rules
                (host_id, direction, target, protocol, port, auth_object, description, limit, signature, template_rule_id, host_group_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
                ''',
                (
                    host_id,
                    direction,
                    rule.get('target'),
                    rule.get('prot'),
                    rule.get('port'),
                    rule.get('source'),
                    rule.get('comment'),
                    normalize_limit_value(rule.get('limit')),
                    signature,
                    default_group['id'],
                    now,
                    now
                )
            )
            new_id = cursor.lastrowid
            rule['group_name'] = default_group['group_name']
            rule['group_color'] = default_group['label_color']
            rule['host_rule_id'] = new_id
            rule['host_group_id'] = default_group['id']
    # 删除已不存在的规则
    stale = set(existing_map.keys()) - seen_signatures
    if stale:
        placeholders = ','.join('?' for _ in stale)
        sql = f'DELETE FROM host_rules WHERE host_id = ? AND direction = ? AND signature IN ({placeholders})'
        params = [host_id, direction]
        params.extend(stale)
        cursor.execute(sql, params)
    db.commit()


def render_host_rule_view(host_id, direction, data_list):
    sync_host_rules(host_id, direction, data_list)
    host_groups = fetch_host_groups(host_id)
    return render_template('rule.html', data_list=data_list, id=host_id, host_groups=host_groups)


def persist_host_rule_metadata(cursor, host_id, direction, rule_meta, template_groups_map):
    """保存模板规则与主机的关联信息"""
    group_name = rule_meta.get('group_name') or DEFAULT_HOST_GROUP_NAME
    template_group = template_groups_map.get(group_name)
    label_color = template_group['label_color'] if template_group else DEFAULT_HOST_GROUP_COLOR
    template_group_id = template_group['id'] if template_group else None
    host_group_id = ensure_host_group(cursor, host_id, group_name, label_color, template_group_id, 1 if not template_group else 0)
    now = current_timestamp()
    limit_value = normalize_limit_value(rule_meta.get('limit'))
    signature = build_rule_signature({
        'target': rule_meta.get('policy'),
        'prot': rule_meta.get('protocol'),
        'source': rule_meta.get('auth_object'),
        'destination': '',
        'port': rule_meta.get('port'),
        'comment': rule_meta.get('description'),
        'limit': limit_value
    })
    cursor.execute(
        '''
        INSERT INTO host_rules
        (host_id, direction, target, protocol, port, auth_object, description, limit, signature, template_rule_id, host_group_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(host_id, direction, signature) DO UPDATE SET
            target=excluded.target,
            protocol=excluded.protocol,
            port=excluded.port,
            auth_object=excluded.auth_object,
            description=excluded.description,
            limit=excluded.limit,
            template_rule_id=excluded.template_rule_id,
            host_group_id=excluded.host_group_id,
            updated_at=excluded.updated_at
        ''',
        (
            host_id,
            direction,
            rule_meta.get('policy'),
            rule_meta.get('protocol'),
            rule_meta.get('port'),
            rule_meta.get('auth_object'),
            rule_meta.get('description'),
            limit_value,
            signature,
            rule_meta.get('rule_id'),
            host_group_id,
            now,
            now
        )
    )


def permission_required(permission_code):
    """权限检查装饰器"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                # 未登录用户重定向到登录页
                return redirect(url_for('login'))

            # 检查用户是否有指定权限
            if not current_user.has_permission(permission_code):
                # 统一返回JSON格式的权限错误，包含403状态码
                return jsonify({
                    'success': False,
                    'message': '没有操作权限，请联系管理员获取权限'
                }), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


# 【新增】操作日志记录函数
def log_operation(user_id, username, operation_type, operation_object, operation_summary, operation_details, success):
    """
    记录操作日志
    :param user_id: 操作用户ID
    :param username: 操作用户名
    :param operation_type: 操作类型(添加/编辑/删除等)
    :param operation_object: 操作对象(用户/角色/主机等)
    :param operation_summary: 操作内容摘要
    :param operation_details: 操作详情(JSON格式)
    :param success: 操作结果(1成功,0失败)
    """
    # 获取东八区当前时间
    tz = pytz.timezone('Asia/Shanghai')
    operation_time = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
        INSERT INTO operation_logs 
        (user_id, username, operation_type, operation_object, operation_summary, operation_details, success, operation_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, username, operation_type, operation_object, operation_summary, operation_details, success,
              operation_time))
        db.commit()
    except Exception as e:
        app.logger.error(f"记录操作日志失败: {str(e)}")
        if 'db' in locals():
            db.rollback()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# 初始化数据库（创建表）
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


def pwd_shell_cmd(hostname, port, user, pwd, cmd):
    stdin = None
    stdout = None
    stderr = None
    try:
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=hostname, port=port, username=user, password=pwd, timeout=5)
        # stdin, stdout, stderr = ssh.exec_command('iptables -nL IN_public_allow --line-number -t filter -v')
        stdin, stdout, stderr = ssh.exec_command(cmd)
        # stdin, stdout, stderr = ssh.exec_command('iptables -nL INPUT --line-number -t filter -v')
        # 读取输出（确保数据被完全读取）
        output = stdout.read().decode()
        error = stderr.read().decode()
        return output
    except Exception as e:
        print(f"SSH 操作失败: {e}")
    finally:
        # 先关闭流对象（关键步骤）
        if stdin:
            stdin.close()
        if stdout:
            stdout.close()
        if stderr:
            stderr.close()
        # 再关闭 SSH 连接
        if ssh:
            ssh.close()


def sshkey_shell_cmd(hostname, port, user, private_key_str, cmd):
    try:
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        key_file = StringIO(private_key_str)  # 模拟文件对象
        pkey = paramiko.RSAKey.from_private_key(key_file)  # 转换为RSA密钥对象
        ssh.connect(hostname=hostname, port=port, username=user, pkey=pkey, timeout=5,
                    look_for_keys=False,
                    allow_agent=False)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read().decode()
        return output
    except Exception as e:
        print(f"SSH 操作失败: {e}")
    finally:
        # 再关闭 SSH 连接
        if ssh:
            ssh.close()


def get_rule(iptables_output):
    # 提取规则行（过滤掉非规则行）
    lines = [line.strip() for line in iptables_output.split('\n') if
             line.strip() and not line.startswith(('Chain', 'num'))]
    # 正确匹配完整字段顺序的正则表达式（包含in和out接口）
    pattern = re.compile(
        r'^(\d+)\s+'  # num（规则序号）
        r'(\w+)\s+'  # target
        r'(\w+)\s+'  # prot
        r'(--)\s+'  # opt
        r'([\d./*]+)\s+'  # source
        r'([\d./*]+)\s*'  # destination
        # 扩展端口匹配：支持单端口、端口范围和多端口
        r'(?:\s+(?:(?:tcp|udp)\s+(?:dpt|spt):(\d+)|'  # 单端口 (如 tcp dpt:80)
        r'(?:tcp|udp)\s+(?:dpts|spts):(\d+:\d+)|'  # 端口范围 (如 tcp dpts:90:100)
        r'multiport\s+(?:dports|sports)\s+([\d,]+)))?'  # 多端口 (如 multiport dports 90,91,92)
        r'(?:\s+limit: (?:up to|above) (\d+)[kmg]?b/s)?'  # 限速字段（可选：有则捕数字，无则不匹配）
        r'(?:\s+(?!/\*).*?)?'  # 排除注释的所有内容
        r'(?:\s+/\*\s*(.*?)\s*\*/)?$'  # 注释
    )
    data_list = []
    for line in lines:
        match = pattern.match(line)
        if match:
            num = match.group(1)
            target = match.group(2)
            prot = match.group(3)
            source = match.group(5)
            destination = match.group(6)
            port = match.group(7) or '-1/-1'
            port_range = match.group(8) or ''
            port_mul = match.group(9) or ''
            limit = match.group(10) or ''
            comment = match.group(11) or ''
            # 提取other内容（排除注释部分）
            # 先去掉注释，再取destination之后的内容
            line_without_comment = re.sub(r'/\*.*?\*/', '', line).strip()
            # 分割出前面的固定字段
            parts = re.split(r'\s+', line_without_comment, 9)  # 分割为10个部分
            other = ' '.join(parts[9:]) if len(parts) > 9 else ''
            if port_range != '':
                data = {'num': num,
                        "target": target,
                        "prot": prot,
                        "source": source,
                        "destination": destination,
                        "port": port_range,
                        "limit": limit,
                        "comment": comment
                        }
            elif port_mul != '':
                data = {'num': num,
                        "target": target,
                        "prot": prot,
                        "source": source,
                        "destination": destination,
                        "port": port_mul,
                        "limit": limit,
                        "comment": comment
                        }
            else:
                data = {'num': num,
                        "target": target,
                        "prot": prot,
                        "source": source,
                        "destination": destination,
                        "port": port,
                        "limit": limit,
                        "comment": comment
                        }
            data_list.append(data)
        else:
            print(f"无法匹配的规则: {line}")
    return data_list


# 根路径路由：重定向到 /hosts?page=1
@app.route('/')
def index():
    # 使用 url_for 生成 hosts 路由的 URL，指定 page=1
    return redirect(url_for('hosts', page=1))


# 查看规则
@app.route("/rules_in", methods=['GET'])
@login_required
def rules_in():
    all_params = dict(request.args)
    host_id = all_params['host_id']
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()
        # 查询所有主机数据
        cursor.execute('''
        SELECT ssh_port, username, ip_address, auth_method, password, private_key,operating_system
        FROM hosts where id = {}
        '''.format(host_id))
        # 获取所有记录
        # 1. 获取所有列名（从 cursor.description 中提取）
        columns = [column[0] for column in cursor.description]
        # 2. 将每行数据与列名配对，转换为字典
        hosts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        hostname = hosts[0]['ip_address']
        port = hosts[0]['ssh_port']
        user = hosts[0]['username']
        pwd = hosts[0]['password']
        auth_method = hosts[0]['auth_method']
        private_key = hosts[0]['private_key']
        if auth_method == 'password':
            iptables_output = pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                            cmd='iptables -nL INPUT --line-number -t filter')
        else:
            iptables_output = sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                               cmd='iptables -nL INPUT --line-number -t filter')
        data_list = get_rule(iptables_output)
        return render_host_rule_view(host_id, 'INPUT', data_list)
    except Exception as e:
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


@app.route("/rules_out", methods=['GET'])
@login_required
def rules_out():
    all_params = dict(request.args)
    host_id = all_params['host_id']
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()
        # 查询所有主机数据
        cursor.execute('''
        SELECT ssh_port, username, ip_address, auth_method, password, private_key,operating_system
        FROM hosts where id = {}
        '''.format(host_id))
        # 获取所有记录
        # 1. 获取所有列名（从 cursor.description 中提取）
        columns = [column[0] for column in cursor.description]
        # 2. 将每行数据与列名配对，转换为字典
        hosts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        hostname = hosts[0]['ip_address']
        port = hosts[0]['ssh_port']
        user = hosts[0]['username']
        pwd = hosts[0]['password']
        auth_method = hosts[0]['auth_method']
        private_key = hosts[0]['private_key']
        if auth_method == 'password':
            iptables_output = pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                            cmd='iptables -nL OUTPUT --line-number -t filter')
        else:
            iptables_output = sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                               cmd='iptables -nL OUTPUT --line-number -t filter')
        data_list = get_rule(iptables_output)
        return render_host_rule_view(host_id, 'OUTPUT', data_list)
    except Exception as e:
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


@app.route('/host_rules/<int:host_rule_id>/group', methods=['POST'])
@login_required
@permission_required('iptab_edit')
def update_host_rule_group(host_rule_id):
    data = request.get_json() or {}
    host_id = data.get('host_id')
    group_id = data.get('group_id')
    if not group_id:
        return jsonify({'success': False, 'message': '缺少分组信息'}), 400
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT host_id FROM host_rules WHERE id = ?', (host_rule_id,))
    rule_row = cursor.fetchone()
    if not rule_row:
        return jsonify({'success': False, 'message': '规则不存在'}), 404
    if host_id and int(host_id) != rule_row['host_id']:
        return jsonify({'success': False, 'message': '主机信息不匹配'}), 400
    cursor.execute('SELECT id, group_name, label_color FROM host_rule_groups WHERE id = ? AND host_id = ?',
                   (group_id, rule_row['host_id']))
    group_row = cursor.fetchone()
    if not group_row:
        return jsonify({'success': False, 'message': '分组不存在'}), 404
    cursor.execute('UPDATE host_rules SET host_group_id = ?, updated_at = ? WHERE id = ?',
                   (group_row['id'], current_timestamp(), host_rule_id))
    db.commit()
    return jsonify({'success': True, 'data': {'group_name': group_row['group_name'], 'label_color': group_row['label_color']}})


# 修改规则
@app.route("/rules_update", methods=['POST'])
@login_required
@permission_required('iptab_edit')  # 添加规则编辑权限
def rules_update():
    all_params = request.get_json()
    host_id = all_params['host_id']
    rule_id = all_params['rule_id']
    direction = all_params['direction'].upper()
    # 获取规则的具体数据
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()
        # 查询所有主机数据
        cursor.execute('''
        SELECT ssh_port, username, ip_address, auth_method, password, private_key,operating_system
        FROM hosts where id = {}
        '''.format(host_id))
        # 获取所有记录
        # 1. 获取所有列名（从 cursor.description 中提取）
        columns = [column[0] for column in cursor.description]
        # 2. 将每行数据与列名配对，转换为字典
        hosts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        hostname = hosts[0]['ip_address']
        port = hosts[0]['ssh_port']
        user = hosts[0]['username']
        pwd = hosts[0]['password']
        auth_method = hosts[0]['auth_method']
        private_key = hosts[0]['private_key']
        operating_system = hosts[0]['operating_system']
        if auth_method == 'password':
            # 删除
            pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                          cmd='iptables -D {} {}'.format(direction, rule_id))
            # 正常的tcp或udp规则
            if 'tcp' in all_params['protocol'] or 'udp' in all_params['protocol']:
                # 正常的端口
                if '-1/-1' not in all_params['port']:
                    # 添加规则中的：正常端口中的范围端口
                    if '-' in all_params['port']:
                        new_port = all_params['port'].replace("-", ":")
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    # 添加规则中的: 正常端口中的多个端口
                    elif ',' in all_params['port']:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m comment --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    else:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
                else:
                    if all_params['limit'] == '':
                        # tcp 或udp的所有端口
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['description'])
                    else:
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
            # ICMP 或 all 协议的规则
            else:
                if all_params['limit'] == '':
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m comment  --comment "{}"'.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['description'])
                else:
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

            # 添加
            pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                          cmd=cmd)
            if operating_system == 'centos' or operating_system == 'redhat':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/iptables/rules.v4')
            # 查看
            iptables_output = pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                            cmd='iptables -nL {} --line-number -t filter'.format(direction))

        else:
            sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                             cmd='iptables -D {} {}'.format(direction, rule_id))
            if operating_system == 'centos' or operating_system == 'redhat':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
            # 正常的tcp或udp规则
            if 'tcp' in all_params['protocol'] or 'udp' in all_params['protocol']:
                # 正常的端口
                if '-1/-1' not in all_params['port']:
                    # 添加规则中的：正常端口中的范围端口
                    if '-' in all_params['port']:
                        new_port = all_params['port'].replace("-", ":")
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    # 添加规则中的: 正常端口中的多个端口
                    elif ',' in all_params['port']:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m comment --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    else:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
                else:
                    if all_params['limit'] == '':
                        # tcp 或udp的所有端口
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['description'])
                    else:
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
            # ICMP 或 all 协议的规则
            else:
                if all_params['limit'] == '':
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m comment  --comment "{}"'.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['description'])
                else:
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

            # 添加
            sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                             cmd=cmd)
            if operating_system == 'centos' or operating_system == 'redhat':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
            # 查看
            iptables_output = sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                               cmd='iptables -nL {} --line-number -t filter'.format(direction))
        data_list = get_rule(iptables_output)
        return render_host_rule_view(host_id, direction, data_list)
    except Exception as e:
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


# 添加规则
@app.route("/rules_add", methods=['POST'])
@login_required
@permission_required('iptab_add')  # 添加规则添加权限
def rules_add():
    all_params = request.get_json()
    print(all_params)
    host_id = all_params['host_id']
    rule_id = all_params['rule_id']
    direction = all_params['direction'].upper()
    # 获取规则的具体数据
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()
        # 查询所有主机数据
        cursor.execute('''
        SELECT ssh_port, username, ip_address, auth_method, password, private_key, operating_system
        FROM hosts where id = {}
        '''.format(host_id))
        # 获取所有记录
        # 1. 获取所有列名（从 cursor.description 中提取）
        columns = [column[0] for column in cursor.description]
        # 2. 将每行数据与列名配对，转换为字典
        hosts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        hostname = hosts[0]['ip_address']
        port = hosts[0]['ssh_port']
        user = hosts[0]['username']
        pwd = hosts[0]['password']
        auth_method = hosts[0]['auth_method']
        private_key = hosts[0]['private_key']
        operating_system = hosts[0]['operating_system']
        if auth_method == 'password':
            # 正常的tcp或udp规则
            if 'tcp' in all_params['protocol'] or 'udp' in all_params['protocol']:
                # 正常的端口
                if '-1/-1' not in all_params['port']:
                    # 添加规则中的：正常端口中的范围端口
                    if '-' in all_params['port']:
                        new_port = all_params['port'].replace("-", ":")
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    # 添加规则中的: 正常端口中的多个端口
                    elif ',' in all_params['port']:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m comment --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    else:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
                else:
                    if all_params['limit'] == '':
                        # tcp 或udp的所有端口
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['description'])
                    else:
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
            # ICMP 或 all 协议的规则
            else:
                if all_params['limit'] == '':
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m comment  --comment "{}"'.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['description'])
                else:
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

            # 添加
            pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                          cmd=cmd)
            if operating_system == 'centos' or operating_system == 'redhat':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/iptables/rules.v4')

            # 查看
            iptables_output = pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                            cmd='iptables -nL {} --line-number -t filter'.format(direction))

        else:
            # 正常的tcp或udp规则
            if 'tcp' in all_params['protocol'] or 'udp' in all_params['protocol']:
                # 正常的端口
                if '-1/-1' not in all_params['port']:
                    # 添加规则中的：正常端口中的范围端口
                    if '-' in all_params['port']:
                        new_port = all_params['port'].replace("-", ":")
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    # 添加规则中的: 正常端口中的多个端口
                    elif ',' in all_params['port']:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m comment --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    else:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
                else:
                    # tcp 或udp的所有端口
                    if all_params['limit'] == '':
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['description'])
                    else:
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
            # ICMP 或 all 协议的规则
            else:
                if all_params['limit'] == '':
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m comment  --comment "{}"'.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['description'])
                else:
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'], )

            # 添加
            sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                             cmd=cmd)
            if operating_system == 'centos' or operating_system == 'redhat':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')

            # 查看
            iptables_output = sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                               cmd='iptables -nL {} --line-number -t filter'.format(direction))
        # 【修复】记录成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='防火墙规则',
            operation_summary=f"添加防火墙规则: {all_params['protocol']} {all_params['port']} ({direction})",
            operation_details=json.dumps({
                "host_id": host_id,
                "host_ip": hostname,
                "rule_id": rule_id,
                "direction": direction,
                "protocol": all_params['protocol'],
                "port": all_params['port'],
                "policy": all_params['auth_policy'],
                "source": all_params['auth_object'],
                "description": all_params['description'],
                "operating_system": operating_system,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )

        data_list = get_rule(iptables_output)
        return render_host_rule_view(host_id, direction, data_list)
    except Exception as e:
        # 【修复】记录失败日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='防火墙规则',
            operation_summary=f"添加防火墙规则失败: {all_params.get('protocol')} {all_params.get('port')}",
            operation_details=json.dumps({
                "host_id": host_id,
                "rule_id": rule_id,
                "direction": direction,
                "request_data": all_params,  # 完整请求参数
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


# 删除规则
@app.route("/rule_del", methods=['DELETE'])
@login_required
@permission_required('iptab_del')  # 添加规则删除权限
def del_rule():
    all_params = dict(request.args)
    host_id = all_params['host_id']
    rule_id = all_params['rule_id']
    direction = all_params['direction'].upper()
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
        SELECT ssh_port, username, ip_address, auth_method, password, private_key,operating_system
        FROM hosts where id = {}
        '''.format(host_id))
        # 获取所有记录
        # 1. 获取所有列名（从 cursor.description 中提取）
        columns = [column[0] for column in cursor.description]
        # 2. 将每行数据与列名配对，转换为字典
        hosts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        hostname = hosts[0]['ip_address']
        port = hosts[0]['ssh_port']
        user = hosts[0]['username']
        pwd = hosts[0]['password']
        auth_method = hosts[0]['auth_method']
        private_key = hosts[0]['private_key']
        operating_system = hosts[0]['operating_system']
        if auth_method == 'password':
            iptables_output = pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                            cmd='iptables -D {} {}'.format(direction, rule_id))
            if operating_system == 'centos' or operating_system == 'redhat':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/iptables/rules.v4')
        else:
            iptables_output = sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                               cmd='iptables -D {} {}'.format(direction, rule_id))
            if operating_system == 'centos' or operating_system == 'redhat':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
        data_list = get_rule(iptables_output)
        # 【修复】记录成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='防火墙规则',
            operation_summary=f"删除防火墙规则: ID {rule_id} (方向: {direction})",
            operation_details=json.dumps({
                "host_id": host_id,
                "host_ip": hostname,
                "rule_id": rule_id,
                "direction": direction,
                "operating_system": operating_system,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return render_host_rule_view(host_id, direction, data_list)
    except Exception as e:
        # 【修复】记录失败日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='防火墙规则',
            operation_summary=f"删除防火墙规则失败: ID {rule_id} (方向: {direction})",
            operation_details=json.dumps({
                "host_id": host_id,
                "rule_id": rule_id,
                "direction": direction,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


# 查看主机
# 主机管理页面路由 - 读取数据库并返回数据到前端
@app.route("/hosts", methods=['GET'])
@login_required
@permission_required('hosts_view')  # 添加主机查看权限
def hosts():
    all_params = dict(request.args)
    page = all_params.get('page', '1')  # 默认为第1页
    search_keyword = all_params.get('search', '')  # 获取搜索关键词
    page_size = 10
    start = (int(page) - 1) * page_size
    end = int(page) * page_size
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()

        # 搜索功能实现
        if search_keyword:
            # 带搜索条件的查询
            cursor.execute('''
            SELECT id, username, auth_method, host_name, host_identifier, ip_address, 
                   operating_system, created_at, ssh_port
            FROM hosts 
            WHERE host_name LIKE ? OR host_identifier LIKE ? OR ip_address LIKE ?
            ORDER BY created_at DESC
            ''', (f'%{search_keyword}%', f'%{search_keyword}%', f'%{search_keyword}%'))
        else:
            # 原有的无搜索条件查询
            cursor.execute('''
            SELECT id, username, auth_method, host_name, host_identifier, ip_address, 
                   operating_system, created_at, ssh_port
            FROM hosts 
            ORDER BY created_at DESC
            ''')

        # 获取所有记录
        hosts = cursor.fetchall()

        # 转换为字典列表，方便前端处理
        host_list = []
        for host in hosts:
            host_list.append({
                'id': host['id'],
                'ssh_port': host['ssh_port'],
                'username': host['username'],
                'auth_method': host['auth_method'],
                'host_name': host['host_name'],
                'host_identifier': host['host_identifier'],
                'ip_address': host['ip_address'],
                'operating_system': host['operating_system'],
                'created_at': host['created_at']
            })

        # 计算总页数（考虑搜索结果）
        total_items = len(host_list)
        total_pages = math.ceil(total_items / page_size)

        # 将主机数据和搜索关键词传递到模板
        return render_template('host.html',
                               host_list=host_list[start:end],
                               sum=total_items,
                               start=(start + 1),
                               end=min(end, total_items),  # 处理最后一页可能不足一页的情况
                               current_page=page,
                               total_pages=total_pages,
                               search_keyword=search_keyword)  # 传递搜索关键词到前端
    except Exception as e:
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


# 添加主机
@app.route('/host_add', methods=['POST'])
@login_required
@permission_required('hosts_add')  # 添加主机添加权限
def add_host():
    data = None
    try:
        # 【修改】提前获取并验证JSON数据
        data = request.get_json()
        if data is None:
            return jsonify({'success': False, 'message': '无效的JSON数据'}), 400

        # 验证必填字段
        required_fields = ['host_name', 'host_identifier', 'ip_address', 'operating_system']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'success': False, 'message': f'缺少必填字段: {field}'}), 400

        db = get_db()
        cursor = db.cursor()

        # 插入主机数据
        cursor.execute('''
        INSERT INTO hosts 
        (host_name, host_identifier, ip_address, operating_system, ssh_port, 
         username, auth_method, password, private_key, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['host_name'],
            data['host_identifier'],
            data['ip_address'],
            data['operating_system'],
            data.get('ssh_port', 22),
            data.get('username', ''),
            data.get('auth_method', 'password'),
            data.get('password', ''),
            data.get('private_key', ''),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ))

        db.commit()
        # 【修改】日志记录增加operation_summary和JSON格式的operation_details
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='主机',
            operation_summary=f"添加了主机: {data['host_name']} ({data['ip_address']})",  # 简短摘要
            operation_details=json.dumps({  # 详细JSON数据
                "host_name": data['host_name'],
                "ip_address": data['ip_address'],
                "operating_system": data['operating_system'],
                "ssh_port": data.get('ssh_port', 22),
                "auth_method": data.get('auth_method', 'password')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': '主机添加成功'})

    except sqlite3.IntegrityError:
        # 【修改】确保data已定义
        data = data or {}
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='主机',
            operation_summary=f"添加主机失败: {data.get('host_name', '未知主机')}",
            operation_details=json.dumps({
                "error": "主机标识已存在",
                "host_identifier": data.get('host_identifier')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': '主机标识已存在'}), 409
    except Exception as e:
        # 【修改】确保data已定义并提供默认值
        data = data or {}
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='主机',
            operation_summary=f"添加主机失败: {data.get('host_name', '未知主机')}",
            operation_details=json.dumps({
                "error": str(e),
                "host_data": {
                    "host_name": data.get('host_name'),
                    "ip_address": data.get('ip_address')
                }
            }),
            success=0
        )
        return jsonify({'success': False, 'message': str(e)}), 500


# 删除主机
@app.route('/host_del', methods=['DELETE'])
@login_required
@permission_required('hosts_del')  # 添加主机删除权限
def del_host():
    host = None
    host_id = request.args.get('id')
    try:
        db = get_db()
        cursor = db.cursor()

        # 【修复1】修改查询语句，获取所有需要的字段
        cursor.execute('SELECT host_name, ip_address, operating_system FROM hosts WHERE id = ?', (host_id,))
        host_row = cursor.fetchone()

        # 【修复2】将Row对象转换为字典
        if host_row:
            columns = [column[0] for column in cursor.description]
            host = dict(zip(columns, host_row))
        else:
            host = None

        if not host:
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='删除',
                operation_object='主机',
                operation_summary=f"删除主机失败: ID {host_id} (主机不存在)",
                operation_details=json.dumps({
                    "host_id": host_id,
                    "error": "主机不存在",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({'success': False, 'message': '主机不存在'}), 404

        # 删除主机
        cursor.execute('DELETE FROM hosts WHERE id = ?', (host_id,))
        db.commit()

        # 【修复3】现在可以安全访问所有字段
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='主机',
            operation_summary=f"删除主机: {host['host_name']} ({host['ip_address']})",
            operation_details=json.dumps({
                "host_id": host_id,
                "host_name": host['host_name'],
                "ip_address": host['ip_address'],
                "operating_system": host['operating_system'],
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': '主机删除成功'})
    except Exception as e:
        # 【修复4】确保host_info是可序列化的字典
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='主机',
            operation_summary=f"删除主机失败: ID {host_id}",
            operation_details=json.dumps({
                "host_id": host_id,
                "host_info": host,  # 现在是字典而非Row对象
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': str(e)}), 500


# 修改主机
@app.route('/host_update', methods=['POST'])
@permission_required('hosts_edit')  # 添加主机编辑权限
@login_required
def update_host():
    data = request.get_json()
    host_id = data['id']
    original_host_name = None
    try:
        db = get_db()
        cursor = db.cursor()
        # 【新增】获取主机原始信息用于日志
        cursor.execute('SELECT host_name, ip_address FROM hosts WHERE id = ?', (host_id,))
        host = cursor.fetchone()
        if not host:
            return jsonify({'success': False, 'message': '主机不存在'}), 404
        original_host_name = host['host_name']
        original_ip = host['ip_address']

        # 不修改密码
        if data['password'] is None and data['private_key'] == '':
            cursor.execute(
                'UPDATE hosts SET host_name = ?, host_identifier = ?, ip_address = ?, operating_system = ?, ssh_port = ?, username = ?, updated_at = ? WHERE id = ?;',
                (data['host_name'], data['host_identifier'], data['ip_address'], data['operating_system'],
                 data['ssh_port'], data['username'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), host_id))
            db.commit()
            if cursor.rowcount == 0:
                return jsonify({'success': False, 'message': '主机不存在'}), 404
            return jsonify({'success': True, 'message': '主机编辑成功'})
        # 修改密码
        else:
            cursor.execute(
                'UPDATE hosts SET host_name = ?, host_identifier = ?, ip_address = ?, operating_system = ?, ssh_port = ?, username = ?, auth_method = ?, password = ?, private_key = ? ,updated_at = ? WHERE id = ?;',
                (data['host_name'], data['host_identifier'], data['ip_address'], data['operating_system'],
                 data['ssh_port'], data['username'], data['auth_method'], data['password'], data['private_key'],
                 datetime.now().strftime('%Y-%m-%d %H:%M:%S'), host_id))
            db.commit()
        # 【修复】记录成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='编辑',
            operation_object='主机',
            operation_summary=f"编辑主机: {original_host_name} -> {data['host_name']}",
            operation_details=json.dumps({
                "host_id": host_id,
                "original": {
                    "host_name": original_host_name,
                    "ip_address": original_ip
                },
                "updated": {
                    "host_name": data['host_name'],
                    "ip_address": data['ip_address'],
                    "ssh_port": data['ssh_port'],
                    "operating_system": data['operating_system'],
                    "auth_method": data.get('auth_method')
                },
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        if cursor.rowcount == 0:
            return jsonify({'success': False, 'message': '主机不存在'}), 404
        return jsonify({'success': True, 'message': '主机编辑成功'})
    except Exception as e:
        # 【修复】记录失败日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='编辑',
            operation_object='主机',
            operation_summary=f"编辑主机失败: ID {host_id}",
            operation_details=json.dumps({
                "host_id": host_id,
                "update_data": data,
                "original_host_name": original_host_name if 'original_host_name' in locals() else None,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': str(e)}), 500


# 查看模板
@app.route("/templates", methods=['GET'])
@login_required
@permission_required('temp_view')
def templates():
    try:
        db = get_db()
        cursor = db.cursor()
        # 获取搜索关键词
        search_keyword = request.args.get('search', '').strip()

        # 根据是否有搜索关键词构建不同查询
        if search_keyword:
            # 带搜索条件的查询
            cursor.execute('''
            SELECT * FROM templates 
            WHERE template_name LIKE ? OR template_identifier LIKE ?
            ''', (f'%{search_keyword}%', f'%{search_keyword}%'))
        else:
            # 原有的无搜索条件查询
            cursor.execute('SELECT * FROM templates ;')

        result = cursor.fetchall()
        temp_info = []
        for res in result:
            template_id = res['id']

            cursor.execute('SELECT * FROM rules where template_id="{}" ;'.format(template_id))
            rules_data = cursor.fetchall()
            cursor.execute('SELECT id, group_name, label_color FROM rule_groups WHERE template_id = ? ORDER BY id ASC',
                           (template_id,))
            group_rows = cursor.fetchall()
            groups = [dict(row) for row in group_rows]

            # 这个循环是rule的规则内容了
            data_list = []
            for rule in rules_data:
                data_list.append({
                    # rules表中的数据信息
                    'rule_id': rule['id'],
                    'policy': rule['policy'],
                    'protocol': rule['protocol'],
                    'port': rule['port'],
                    'auth_object': rule['auth_object'],
                    'description': rule['description'],
                    'created_at': rule['created_at'],
                    'updated_at': rule['updated_at'],
                    'limit': rule['limit'],
                    'group_name': rule['group_name'],
                })

            temp_info.append({'template_id': template_id,
                              'template_name': res['template_name'],
                              'direction': res['direction'],
                              'template_identifier': res['template_identifier'],
                              'updated_at': res['updated_at'],
                              'rules': data_list,
                              'groups': groups,
                              })
            # print(temp_info)

        # 计算符合条件的模板总数
        total_templates = len(temp_info)

    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': '模板名称已存在'}), 409
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

    # 传递搜索关键词和总数到前端
    return render_template(
        'templates.html',
        data_list=temp_info,
        search_keyword=search_keyword,
        sum=total_templates
    )


# 添加模板
@app.route("/temp_add", methods=['POST'])
@login_required
@permission_required('temp_add')
def templates_add():
    data = None
    try:
        data = request.get_json()
        print(data)
        db = get_db()
        cursor = db.cursor()
        # 插入主机数据
        now_ts = current_timestamp()
        cursor.execute('''
        INSERT INTO templates
        (template_name, template_identifier, direction,created_at, updated_at)
        VALUES (?, ?, ?, ?,?)
        ''', (
            data['name'],
            data['description'],
            data['direction'],
            now_ts,
            now_ts
        ))
        # 查询templat_id
        cursor.execute('SELECT id FROM templates ORDER BY id DESC LIMIT 1;')
        result = cursor.fetchone()
        if result:
            # 结果是元组，取第一个元素（即 ID）
            template_id = result[0]
        else:
            # 表中没有数据时返回 None 或提示
            template_id = 1

        groups_payload = data.get('groups') or []
        if not groups_payload:
            groups_payload = [{'group_name': '默认分组', 'label_color': DEFAULT_TEMPLATE_GROUP_COLOR}]
        for group in groups_payload:
            cursor.execute('''
            INSERT INTO rule_groups (template_id, group_name, label_color, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ''', (
                template_id,
                group.get('group_name') or '默认分组',
                group.get('label_color') or DEFAULT_TEMPLATE_GROUP_COLOR,
                now_ts,
                now_ts
            ))

        for rule in data['rules']:
            if rule['policy'] == '允许':
                policy = 'ACCEPT'
            else:
                policy = 'DROP'
            cursor.execute('''
            INSERT INTO rules
            (template_id, policy, protocol, port, auth_object, description, created_at, updated_at, "limit", group_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                template_id,
                policy,
                rule['protocol'],
                rule['port'],
                rule['auth_object'],
                rule['description'],
                now_ts,
                now_ts,
                rule['limit'],
                rule.get('group_name') or groups_payload[0].get('group_name') or '默认分组'
            ))

        db.commit()

        # 获取规则数量用于日志
        rule_count = len(data['rules'])

        # 【修复】记录成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='模板',
            operation_summary=f"添加模板: {data['name']} (规则数: {rule_count})",
            operation_details=json.dumps({
                "template_id": template_id,
                "template_name": data['name'],
                "direction": data['direction'],
                "description": data['description'],
                "rule_count": rule_count,
                "rules": [
                    {
                        "protocol": rule['protocol'],
                        "port": rule['port'],
                        "policy": "允许" if rule['policy'] == 'ACCEPT' else "拒绝",
                        "source": rule['auth_object'],
                        "description": rule['description'],
                        "limit": rule['limit']
                    } for rule in data['rules']
                ],
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': '模板添加成功'})

    except sqlite3.IntegrityError:
        # 【修复】记录失败日志
        data = data or {}
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='模板',
            operation_summary=f"添加模板失败: {data.get('name', '未知模板')} (标识已存在)",
            operation_details=json.dumps({
                "template_name": data.get('name'),
                "description": data.get('description'),
                "error": "模板标识已存在",
                "error_type": "IntegrityError",
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': '模板名称已存在'}), 409
    except Exception as e:
        # 【修复】记录失败日志
        data = data or {}
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='模板',
            operation_summary=f"添加模板失败: {data.get('name', '未知模板')}",
            operation_details=json.dumps({
                "template_name": data.get('name'),
                "request_data": data,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': str(e)}), 500


# 删除模板
@app.route("/temp_del", methods=['DELETE'])
@login_required
@permission_required('temp_del')
def templates_del():
    template_id = request.args.get('temp_id')
    template = None  # 初始化template变量
    try:
        db = get_db()
        cursor = db.cursor()
        # 【新增】获取模板名称用于日志
        cursor.execute('SELECT template_name FROM templates WHERE id = ?', (template_id,))
        template = cursor.fetchone()
        if not template:
            return jsonify({'success': False, 'message': '模板不存在'}), 404
        template_name = template['template_name']
        # 查询该模板下的规则数量
        cursor.execute('SELECT COUNT(*) as rule_count FROM rules WHERE template_id = ?', (template_id,))
        rule_count = cursor.fetchone()['rule_count']

        # 删除主机
        cursor.execute('DELETE FROM templates WHERE id = ?', (template_id,))
        cursor.execute('DELETE FROM rules WHERE template_id = ?', (template_id,))
        db.commit()
        # 【修复】记录成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='模板',
            operation_summary=f"删除模板: {template_name} (规则数: {rule_count})",
            operation_details=json.dumps({
                "template_id": template_id,
                "template_name": template_name,
                "deleted_rules": rule_count,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )

        if cursor.rowcount == 0:
            return jsonify({'success': False, 'message': '模板不存在'}), 404
        return jsonify({'success': True, 'message': '模板删除成功'})
    except Exception as e:
        # 【修复】记录失败日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='模板',
            operation_summary=f"删除模板失败: ID {template_id}",
            operation_details=json.dumps({
                "template_id": template_id,
                "template_name": template['template_name'] if template else None,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': str(e)}), 500


# 修改模板
@app.route("/temp_edit", methods=['POST'])
@login_required
@permission_required('temp_edit')
def templates_edit():
    data = None
    original_template_name = None
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()

        # 【新增】获取原模板名称用于日志
        cursor.execute('SELECT template_name FROM templates WHERE id = ?', (data['temp_id'],))
        template = cursor.fetchone()
        if not template:
            return jsonify({'success': False, 'message': '模板不存在'}), 404
        original_template_name = template['template_name']

        # 获取修改前后的规则数量
        cursor.execute('SELECT COUNT(*) as old_count FROM rules WHERE template_id = ?', (data['temp_id'],))
        old_rule_count = cursor.fetchone()['old_count']
        new_rule_count = len(data['rules'])

        now_ts = current_timestamp()
        groups_payload = data.get('groups') or []
        if not groups_payload:
            groups_payload = [{'group_name': '默认分组', 'label_color': DEFAULT_TEMPLATE_GROUP_COLOR}]

        cursor.execute('SELECT id FROM rule_groups WHERE template_id = ?', (data['temp_id'],))
        existing_group_ids = {row['id'] for row in cursor.fetchall()}
        payload_group_ids = {grp.get('id') for grp in groups_payload if grp.get('id')}
        to_remove = existing_group_ids - payload_group_ids
        if to_remove:
            placeholders = ','.join('?' for _ in to_remove)
            cursor.execute(f'DELETE FROM rule_groups WHERE id IN ({placeholders})', tuple(to_remove))
            cursor.execute(f'UPDATE host_rule_groups SET template_group_id = NULL WHERE template_group_id IN ({placeholders})',
                           tuple(to_remove))

        for group in groups_payload:
            color = group.get('label_color') or DEFAULT_TEMPLATE_GROUP_COLOR
            if group.get('id'):
                cursor.execute(
                    'UPDATE rule_groups SET group_name = ?, label_color = ?, updated_at = ? WHERE id = ?',
                    (group.get('group_name') or '默认分组', color, now_ts, group['id'])
                )
                cursor.execute(
                    'UPDATE host_rule_groups SET group_name = ?, label_color = ?, updated_at = ? WHERE template_group_id = ?',
                    (group.get('group_name') or '默认分组', color, now_ts, group['id'])
                )
            else:
                cursor.execute(
                    'INSERT INTO rule_groups (template_id, group_name, label_color, created_at, updated_at) VALUES (?, ?, ?, ?, ?)',
                    (data['temp_id'], group.get('group_name') or '默认分组', color, now_ts, now_ts)
                )

        # 修改模板信息
        cursor.execute('''
        UPDATE  templates set template_name = ?, template_identifier = ?, direction = ?, updated_at =? WHERE id = ?;
        ''', (
            data['name'],
            data['description'],
            data['direction'],
            now_ts,
            data['temp_id']
        ))
        # 先删除旧规则
        cursor.execute('DELETE FROM rules WHERE template_id = ?', (data['temp_id'],))
        for rule in data['rules']:
            if rule['policy'] == '允许' or rule['policy'] == 'ACCEPT':
                policy = 'ACCEPT'
            else:
                policy = 'DROP'
            # 添加新规则
            cursor.execute('''
            INSERT INTO rules
            (template_id, policy, protocol, port, auth_object, description, created_at, updated_at, "limit", group_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data['temp_id'],
                policy,
                rule['protocol'],
                rule['port'],
                rule['auth_object'],
                rule['description'],
                now_ts,
                now_ts,
                rule.get('limit', ''),
                rule.get('group_name') or groups_payload[0].get('group_name') or '默认分组'
            ))
        db.commit()
        # 【修复】记录成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='编辑',
            operation_object='模板',
            operation_summary=f"编辑模板: {original_template_name} -> {data['name']} (规则数: {old_rule_count}→{new_rule_count})",
            operation_details=json.dumps({
                "template_id": data['temp_id'],
                "original": {
                    "name": original_template_name,
                    "rule_count": old_rule_count
                },
                "updated": {
                    "name": data['name'],
                    "description": data['description'],
                    "direction": data['direction'],
                    "rule_count": new_rule_count
                },
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': '模板修改成功'})

    except sqlite3.IntegrityError:
        # 【修复】记录失败日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='编辑',
            operation_object='模板',
            operation_summary=f"编辑模板失败: {original_template_name or '未知模板'}",
            operation_details=json.dumps({
                "template_id": data.get('temp_id'),
                "error": "模板名称已存在",
                "error_type": "IntegrityError",
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': '模板名称不存在'}), 409
    except Exception as e:
        # 【修复】记录失败日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='编辑',
            operation_object='模板',
            operation_summary=f"编辑模板失败: {original_template_name or '未知模板'}",
            operation_details=json.dumps({
                "template_id": data.get('temp_id'),
                "update_data": data,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': str(e)}), 500


# 应用模板获取主机列表
@app.route("/temp_host_api", methods=['GET'])
@login_required
def temp_host_api():
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()
        # 查询所有主机数据
        cursor.execute('''
        SELECT id, host_identifier
        FROM hosts 
        ORDER BY created_at DESC
        ''')
        # 获取所有记录
        hosts = cursor.fetchall()

        # 转换为字典列表，方便前端处理
        host_list = []
        for host in hosts:
            host_list.append({
                'id': host['id'],
                'host_name': host['host_identifier']
            })
        # 返回JSON格式数据
        return jsonify({
            'success': True,
            'data': host_list
        })
    except Exception as e:
        # 错误处理，同样返回JSON格式
        return jsonify({
            'success': False,
            'message': f"获取主机数据失败: {str(e)}"
        }), 500


# 应用模板
@app.route("/temp_to_hosts", methods=['POST'])
@login_required
@permission_required('iptab_add')
def temp_to_hosts():
    all_params = request.get_json()
    template_id = all_params['template_id']
    host_ids_list = all_params['host_ids']
    # 获取模板的规则
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()
        # 获取模板名称和主机名称列表
        cursor.execute('SELECT template_name FROM templates WHERE id = ?', (template_id,))
        template_name = cursor.fetchone()['template_name']

        # 修复：将整数ID转换为字符串后再拼接
        host_ids_str = [str(id) for id in host_ids_list]
        cursor.execute('SELECT id, host_name FROM hosts WHERE id IN ({})'.format(','.join(host_ids_str)))
        host_names = {str(h['id']): h['host_name'] for h in cursor.fetchall()}

        # 获取模板的方向
        cursor.execute(''' select direction from templates  where id = {} ;'''.format(template_id))
        direction_data = cursor.fetchone()
        direction = direction_data[0]
        # 查询所有主机数据
        cursor.execute('SELECT id, group_name, label_color FROM rule_groups WHERE template_id = ?', (template_id,))
        template_groups_map = {row['group_name']: dict(row) for row in cursor.fetchall()}
        cursor.execute('''SELECT * FROM  rules
        where template_id = {}
        '''.format(template_id))
        # 获取所有记录
        temp_data = cursor.fetchall()
        prepared_rules = []
        for rule in temp_data:
            rule_meta = {
                'rule_id': rule['id'],
                'policy': rule['policy'],
                'protocol': rule['protocol'],
                'port': rule['port'],
                'auth_object': rule['auth_object'],
                'description': rule['description'],
                'limit': rule['limit'],
                'group_name': rule['group_name'] or '默认分组'
            }
            # 正常的tcp或udp规则
            if 'tcp' in rule['protocol'].lower() or 'udp' in rule['protocol'].lower():
                # 正常的端口
                if '-1/-1' not in rule['port']:
                    # 添加规则中的：正常端口中的范围端口
                    if '-' in rule['port']:
                        new_port = rule['port'].replace("-", ":")
                        if rule['limit'] == '':
                            cmd = 'iptables -A {}  -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule['auth_object'], rule['protocol'], new_port,
                                rule['policy'], rule['description'])
                        else:
                            cmd = 'iptables -A {}  -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule['auth_object'], rule['protocol'], new_port,
                                rule['policy'], rule['limit'], random_name(), rule['description'])
                        prepared_rules.append({'command': cmd, 'metadata': rule_meta})
                    # 添加规则中的: 正常端口中的多个端口
                    elif ',' in rule['port']:
                        if rule['limit'] == '':
                            cmd = 'iptables -A {}  -s {} -p {} -m multiport --dports {} -j {} -m comment --comment "{}" '.format(
                                direction, rule['auth_object'], rule['protocol'],
                                rule['port'],
                                rule['policy'], rule['description'])
                        else:
                            cmd = 'iptables -A {}  -s {} -p {} -m multiport --dports {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment --comment "{}" '.format(
                                direction, rule['auth_object'], rule['protocol'],
                                rule['port'],
                                rule['policy'], rule['limit'], random_name(), rule['description'])
                        prepared_rules.append({'command': cmd, 'metadata': rule_meta})
                    else:
                        if rule['limit'] == '':
                            cmd = 'iptables -A {}  -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule['auth_object'], rule['protocol'],
                                rule['port'],
                                rule['policy'], rule['description'])
                        else:
                            cmd = 'iptables -A {}  -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule['auth_object'], rule['protocol'],
                                rule['port'],
                                rule['policy'], rule['limit'], random_name(), rule['description'])
                        prepared_rules.append({'command': cmd, 'metadata': rule_meta})
                else:
                    if rule['limit'] == '':
                        # tcp 或udp的所有端口
                        cmd = 'iptables -A {} -s {} -p {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule['auth_object'], rule['protocol'],
                            rule['policy'], rule['description'])
                    else:
                        # tcp 或udp的所有端口
                        cmd = 'iptables -A {} -s {} -p {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}"'.format(
                            direction, rule['auth_object'], rule['protocol'],
                            rule['policy'], rule['limit'], random_name(), rule['description'])
                    prepared_rules.append({'command': cmd, 'metadata': rule_meta})
            # ICMP 或 all 协议的规则
            else:
                if rule['limit'] == '':
                    cmd = 'iptables -A {}  -s {} -p {}  -j {} -m comment  --comment "{}"'.format(
                        direction, rule['auth_object'], rule['protocol'],
                        rule['policy'], rule['description'])
                else:
                    cmd = 'iptables -A {}  -s {} -p {}  -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}"'.format(
                        direction, rule['auth_object'], rule['protocol'],
                        rule['policy'], rule['limit'], random_name(), rule['description'])
                prepared_rules.append({'command': cmd, 'metadata': rule_meta})
        # 获取主机的信息
        for host_id in host_ids_list:
            # 查询所有主机数据
            cursor.execute('''
            SELECT ssh_port, username, ip_address, auth_method, password, private_key, operating_system
            FROM hosts where id = {}
            '''.format(host_id))
            # 获取所有记录
            # 1. 获取所有列名（从 cursor.description 中提取）
            columns = [column[0] for column in cursor.description]
            # 2. 将每行数据与列名配对，转换为字典
            hosts = [dict(zip(columns, row)) for row in cursor.fetchall()]
            hostname = hosts[0]['ip_address']
            port = hosts[0]['ssh_port']
            user = hosts[0]['username']
            pwd = hosts[0]['password']
            auth_method = hosts[0]['auth_method']
            private_key = hosts[0]['private_key']
            operating_system = hosts[0]['operating_system']
            if auth_method == 'password':
                for entry in prepared_rules:
                    cmd = entry['command']
                    pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                  cmd=cmd)
                    if operating_system == 'centos' or operating_system == 'redhat':
                        pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                      cmd='iptables-save > /etc/sysconfig/iptables')
                    elif operating_system == 'debian':
                        pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                      cmd='iptables-save > /etc/iptables/rules.v4')
                    elif operating_system == 'ubuntu':
                        pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                      cmd='iptables-save > /etc/iptables/rules.v4')
                    persist_host_rule_metadata(cursor, host_id, direction, entry['metadata'], template_groups_map)
            else:
                for entry in prepared_rules:
                    cmd = entry['command']
                    sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                     cmd=cmd)
                    if operating_system == 'centos' or operating_system == 'redhat':
                        sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                         cmd='iptables-save > /etc/sysconfig/iptables')
                    elif operating_system == 'debian':
                        sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                         cmd='iptables-save > /etc/iptables/rules.v4')
                    elif operating_system == 'ubuntu':
                        sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                         cmd='iptables-save > /etc/iptables/rules.v4')
                    persist_host_rule_metadata(cursor, host_id, direction, entry['metadata'], template_groups_map)

        db.commit()
        # 【修复】记录成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='应用',
            operation_object='模板',
            operation_summary=f"应用模板到主机: {template_name} ({len(host_ids_list)}台主机)",
            operation_details=json.dumps({
                "template_id": template_id,
                "template_name": template_name,
                "direction": direction,
                "applied_hosts": [
                    {"host_id": hid, "host_name": host_names.get(hid, "未知主机")}
                    for hid in host_ids_list
                ],
                "applied_rules": len(prepared_rules),
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        # 将规则添加到主机上
        return jsonify({
            'success': True,
            'message': "成功"
        })

    except Exception as e:
        # 【修复】记录失败日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='应用',
            operation_object='模板',
            operation_summary=f"应用模板失败: ID {template_id}",
            operation_details=json.dumps({
                "template_id": template_id,
                "host_ids": host_ids_list,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        # 错误处理，同样返回JSON格式
        return jsonify({
            'success': False,
            'message': f"获取主机数据失败: {str(e)}"
        }), 500


# 系统设置
@app.route("/systemseting", methods=['GET'])
@login_required
@permission_required('sys_view')  # 添加系统设置查看权限
def systemseting():
    return render_template('systemseting.html')


# 系统配置接口
@app.route('/api/system-config', methods=['GET', 'POST'])
@login_required  # 添加登录验证
def get_system_config():
    if request.method == "GET":
        @permission_required('sys_view')
        def get_config():
            try:
                db = get_db()
                config = db.execute('SELECT * FROM system_config ORDER BY id DESC LIMIT 1').fetchone()
                return jsonify(dict(config)) if config else jsonify({})
            except Exception as e:
                app.logger.error(f"获取系统配置失败: {str(e)}")
                return jsonify({'error': '获取系统配置失败'}), 500

        # 调用嵌套函数并返回结果
        return get_config()
    else:
        @permission_required('sys_edit')
        def update_config():
            data = None
            try:
                data = request.get_json()
                db = get_db()
                cursor = db.cursor()
                # 获取原始配置用于日志
                cursor.execute('SELECT * FROM system_config ORDER BY id DESC LIMIT 1')
                original_config = dict(cursor.fetchone())

                system_name = data['system_name']
                default_session_timeout = data['default_session_timeout']
                log_retention_time = data['log_retention_days']
                color_mode = data['color_mode']
                password_strategy = data['password_strategy']
                updated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                # 更新system_config 表
                cursor.execute(
                    ''' update system_config  set system_name = ?, session_timeout = ?, log_retention_time = ?, color_mode = ?,password_strategy = ?, updated_at = ?  where id=1; ''',
                    (
                        system_name, default_session_timeout, log_retention_time, color_mode, password_strategy,
                        updated_at
                    ))
                db.commit()
                # 【修复】记录成功日志
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='编辑',
                    operation_object='系统设置',
                    operation_summary=f"更新系统设置: {data['system_name']}",
                    operation_details=json.dumps({
                        "original": {
                            "system_name": original_config['system_name'],
                            "session_timeout": original_config['session_timeout'],
                            "log_retention": original_config['log_retention_time'],
                            "color_mode": original_config['color_mode']
                        },
                        "updated": {
                            "system_name": data['system_name'],
                            "session_timeout": data['default_session_timeout'],
                            "log_retention": data['log_retention_days'],
                            "color_mode": data['color_mode'],
                            "password_strategy": data['password_strategy']
                        },
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=1
                )
                return jsonify({'success': True, 'message': '保存系统配置成功'})
            except Exception as e:
                # 【修复】记录失败日志
                data = data or {}
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='编辑',
                    operation_object='系统设置',
                    operation_summary=f"更新系统设置失败",
                    operation_details=json.dumps({
                        "update_data": data,
                        "error": str(e),
                        "error_type": type(e).__name__,
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=0
                )
                app.logger.error(f"保存系统配置失败: {str(e)}")
                return jsonify({'error': '保存系统配置失败'}), 500

        # 调用嵌套函数并返回结果
        return update_config()


# 获取会话超时时间（从数据库）
def get_session_timeout():
    """从数据库获取会话超时时间（分钟），默认30分钟"""
    try:
        db = get_db()
        config = db.execute('SELECT session_timeout FROM system_config ORDER BY id DESC LIMIT 1').fetchone()
        if config and config['session_timeout'] is not None:
            return int(config['session_timeout'])
        return 30  # 默认值
    except Exception as e:
        app.logger.error(f"获取会话超时时间失败: {str(e)}")
        return 30  # 异常时使用默认值


# 添加请求前钩子，检查会话超时
@app.before_request
def check_session_timeout():
    """在每个请求前检查会话是否超时"""
    # 排除登录页面，避免循环重定向
    if request.path == '/login':
        return

    # 仅对已登录用户检查超时
    if current_user.is_authenticated:
        # 获取会话创建时间（首次访问时初始化）
        if 'created_at' not in session:
            session['created_at'] = time.time()  # <-- 添加默认值
        created_at = session['created_at']
        timeout_seconds = get_session_timeout() * 60
        current_time = time.time()

        # 检查是否超时
        if current_time - created_at > timeout_seconds:
            logout_user()
            session.clear()  # 清除会话数据
            flash('会话已超时，请重新登录', 'info')
            return redirect(url_for('login'))

        # 更新会话活动时间（实现"空闲超时"机制）
        session['created_at'] = current_time


# 用户类
class User(UserMixin):
    def __init__(self, user_id, username, roles=None):
        self.id = user_id
        self.username = username
        self.roles = roles or []  # 存储用户拥有的角色列表

    def has_permission(self, permission_code):
        """检查用户是否拥有指定权限"""
        db = get_db()
        try:
            cursor = db.cursor()
            # 通过三表关联查询用户是否拥有权限
            cursor.execute('''
            SELECT 1 FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            JOIN user_roles ur ON rp.role_id = ur.role_id
            WHERE ur.user_id = ? AND p.code = ?
            LIMIT 1
            ''', (self.id, permission_code))
            return cursor.fetchone() is not None
        except Exception as e:
            app.logger.error(f"权限检查失败: {str(e)}")
            return False


# 加载用户回调函数
@login_manager.user_loader
def load_user(user_id):
    """从数据库加载用户信息，包括用户角色"""
    db = get_db()
    try:
        # 查询用户基本信息
        user = db.execute('SELECT id, username, status FROM user WHERE id = ?',
                          (user_id,)).fetchone()
        if not user or user['status'] != 'active':
            return None

        # 查询用户角色
        roles = db.execute('''
        SELECT r.id, r.role_name FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?
        ''', (user_id,)).fetchall()

        return User(
            user_id=user['id'],
            username=user['username'],
            roles=[{'id': r['id'], 'name': r['role_name']} for r in roles]
        )
    except Exception as e:
        app.logger.error(f"加载用户失败: {str(e)}")
        return None


# 登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(success=True, redirect_url=url_for('hosts', page=1))
        return redirect(url_for('hosts', page=1))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'

        # 从数据库查询用户
        db = get_db()
        user_data = db.execute('SELECT id, username, password, status FROM user WHERE username = ?',
                               (username,)).fetchone()

        if not user_data:
            return jsonify(success=False, message='用户名不存在') if request.headers.get(
                'X-Requested-With') == 'XMLHttpRequest' else \
                render_template('login.html', error='用户名不存在')

        if user_data['status'] != 'active':
            return jsonify(success=False, message='用户已被禁用') if request.headers.get(
                'X-Requested-With') == 'XMLHttpRequest' else \
                render_template('login.html', error='用户已被禁用')

        if not check_password_hash(user_data['password'], password):
            return jsonify(success=False, message='密码不正确') if request.headers.get(
                'X-Requested-With') == 'XMLHttpRequest' else \
                render_template('login.html', error='密码不正确')

        # 加载用户角色信息
        user = load_user(user_data['id'])
        session['created_at'] = time.time()
        login_user(user, remember=remember)

        return jsonify(success=True, redirect_url=url_for('hosts', page=1)) if request.headers.get(
            'X-Requested-With') == 'XMLHttpRequest' else \
            redirect(url_for('hosts', page=1))

    return render_template('login.html')


@app.route('/users', methods=['GET', 'POST'])
@login_required
@permission_required('user_view')
def users():
    # 如果是查看用户管理页面
    if request.method == "GET":
        # 新增：如果是AJAX请求，返回用户列表JSON数据（用于日志筛选）
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            try:
                db = get_db()
                cursor = db.cursor()
                cursor.execute('SELECT DISTINCT username FROM operation_logs ORDER BY username')
                users = [{'username': row['username']} for row in cursor.fetchall()]
                return jsonify({"success": True, "users": users})
            except Exception as e:
                app.logger.error(f"获取用户列表失败: {str(e)}")
                return jsonify({"success": False, "message": "获取用户列表失败"}), 500

        @permission_required('user_view')
        def get_users():
            try:
                db = get_db()
                cursor = db.cursor()
                # 查询用户基本信息及关联的角色
                cursor.execute(''' 
                SELECT u.id, u.username, u.email, u.status, u.created_at,
                       GROUP_CONCAT(r.role_name, ', ') as roles
                FROM user u
                LEFT JOIN user_roles ur ON u.id = ur.user_id
                LEFT JOIN roles r ON ur.role_id = r.id
                GROUP BY u.id
                ''')
                data = cursor.fetchall()
                user_list = []
                for i in data:
                    user_dict = {
                        'id': i['id'],
                        'roles': i['roles'] if i['roles'] else 'None',
                        'username': i['username'],
                        'email': i['email'],
                        'status': i['status'],
                        'created_at': i['created_at']
                    }
                    user_list.append(user_dict)
                return render_template('systemseting.html', user_list=user_list)
            except Exception as e:
                # 添加异常情况下的响应
                return jsonify({
                    "success": False,
                    "message": f"获取用户列表失败: {str(e)}"
                }), 500

        # 调用嵌套函数并返回结果
        return get_users()
    # 如果是添加用户
    elif request.method == 'POST':
        db = get_db()

        @permission_required('user_add')
        def add_user():
            # 初始化可能在日志中使用的变量
            username = ""
            email = ""
            role_id = ""
            status = "active"
            user_data = None  # 初始化user_data变量
            try:
                # 获取JSON数据而非表单数据
                user_data = request.get_json()
                if not user_data:
                    return jsonify({
                        "success": False,
                        "message": "未收到数据，请检查请求格式"
                    }), 400

                cursor = db.cursor()
                # 从JSON数据中获取字段并验证
                username = user_data.get('username')
                password = user_data.get('password')
                email = user_data.get('email')
                status = user_data.get('status', 'active')  # 默认状态为active
                # 【新增】获取角色ID并验证
                role_id = user_data.get('role')
                if not role_id:
                    return jsonify({
                        "success": False,
                        "message": "角色为必填项"
                    }), 400
                try:
                    role_id = int(role_id)  # 转换为整数
                except ValueError:
                    return jsonify({
                        "success": False,
                        "message": "无效的角色ID格式"
                    }), 400

                # 验证必填字段
                if not username or not password or not email:
                    return jsonify({
                        "success": False,
                        "message": "用户名、密码和邮箱为必填项"
                    }), 400

                # 密码哈希处理
                hashed_password = generate_password_hash(password)
                cursor.execute(''' 
                INSERT INTO user
                (username, password, email, status, created_at)
                VALUES (?, ?, ?, ?, ?)
                 ''', (
                    username,
                    hashed_password,  # 使用哈希后的密码
                    email,
                    status,
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ))

                # 【新增】获取新创建用户的ID
                user_id = cursor.lastrowid

                # 【新增】插入用户-角色关联记录
                cursor.execute('''
                INSERT INTO user_roles (user_id, role_id)
                VALUES (?, ?)
                ''', (user_id, role_id))

                # 【修改】统一提交事务（用户表和关联表一起提交）
                db.commit()
                # 【修复】记录成功日志（添加summary和JSON格式details）
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='添加',
                    operation_object='用户',
                    operation_summary=f"添加用户: {username}",  # 简略摘要
                    operation_details=json.dumps({  # JSON格式详细信息
                        "user_id": user_id,
                        "username": username,
                        "email": email,
                        "status": status,
                        "role_id": role_id,
                        "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=1
                )

                return jsonify({
                    "success": True,
                    "message": "用户添加成功！"
                }), 200

            except sqlite3.IntegrityError as e:
                db.rollback()
                # 【修复】记录失败日志（添加summary和JSON格式details）
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='添加',
                    operation_object='用户',
                    operation_summary=f"添加用户失败: {username} (用户名/邮箱已存在)",  # 简略摘要
                    operation_details=json.dumps({  # JSON格式详细信息
                        "username": username,
                        "email": email,
                        "conflict_field": "用户名" if db.execute("SELECT 1 FROM user WHERE username = ?",
                                                                 (username,)).fetchone() else "邮箱",
                        "error": "用户名或邮箱已存在",
                        "error_type": "IntegrityError",
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=0
                )
                return jsonify({
                    "success": False,
                    "message": "用户名或邮箱已存在，请更换！"
                }), 409
            except Exception as e:
                # 【修复】记录失败日志（添加summary和JSON格式details）
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='添加',
                    operation_object='用户',
                    operation_summary=f"添加用户失败: {username}",  # 简略摘要
                    operation_details=json.dumps({  # JSON格式详细信息
                        "username": username,
                        "email": email,
                        "role_id": role_id,
                        "request_data": {
                            "username": username,
                            "email": email,
                            "status": status,
                            "role_id": role_id
                        },
                        "error": str(e),
                        "error_type": type(e).__name__,
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=0
                )

                if 'db' in locals():
                    db.rollback()
                return jsonify({
                    "success": False,
                    "message": f"添加失败：{str(e)}"
                }), 500

        # 调用嵌套函数并返回结果
        return add_user()


@app.route('/user_edit', methods=['GET', 'POST'])
@login_required
@permission_required('user_edit')
def user_edit():
    if request.method == 'GET':
        user_id = request.args.get('id')
        try:
            db = get_db()
            cursor = db.cursor()
            # 获取用户信息
            cursor.execute('SELECT id, username, email, status FROM user WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            if not user:
                return jsonify({'success': False, 'message': '用户不存在'}), 404
            # 获取所有角色
            cursor.execute('SELECT id, role_name FROM roles')
            roles = cursor.fetchall()
            # 获取用户已分配的角色
            cursor.execute('SELECT role_id FROM user_roles WHERE user_id = ?', (user_id,))
            user_roles = [row['role_id'] for row in cursor.fetchall()]
            return jsonify({
                'success': True,
                'user': dict(user),
                'roles': [dict(role) for role in roles],
                'user_roles': user_roles
            })
        except Exception as e:
            return jsonify({'success': False, 'message': f"获取用户信息失败: {str(e)}"}), 500
    elif request.method == 'POST':
        # 初始化可能在日志中使用的变量，避免"赋值前引用"
        data = request.get_json() or {}  # 确保data是字典，避免None
        user_id = data.get('id', 'unknown')  # 安全获取用户ID
        original_username = "未知用户"
        original_status = "unknown"
        username = "unknown"
        email = "unknown"
        status = "unknown"
        roles = []
        operation_type = "编辑"

        db = get_db()
        try:
            cursor = db.cursor()
            # 获取用户当前信息，用于处理部分更新情况（添加status字段）
            # 【修改】重命名变量，避免与Flask-Login的current_user冲突
            cursor.execute('SELECT username, email, status FROM user WHERE id = ?', (user_id,))
            user_data = cursor.fetchone()  # 将变量名从current_user改为user_data
            if not user_data:
                # 记录用户不存在日志
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='编辑',
                    operation_object='用户',
                    operation_summary=f"编辑用户失败: ID {user_id} (用户不存在)",
                    operation_details=json.dumps({
                        "user_id": user_id,
                        "error": "用户不存在",
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=0
                )
                return jsonify({'success': False, 'message': '用户不存在'}), 404

            # 更新变量值（确保所有日志变量都已初始化）
            original_username = user_data['username']
            original_status = user_data['status']
            username = data.get('username', original_username)
            email = data.get('email', user_data['email'])
            status = data.get('status', user_data['status'])
            roles = data.get('role', [])
            operation_type = '禁用' if status == 'inactive' and original_status == 'active' else '编辑'

            # 更新用户基本信息
            if 'password' in data and data['password']:
                # 如果提供了新密码，则更新密码
                hashed_password = generate_password_hash(data['password'])
                cursor.execute('''
                        UPDATE user SET username = ?, email = ?, status = ?, password = ? 
                        WHERE id = ?
                        ''', (username, email, status, hashed_password, user_id))
            else:
                # 不更新密码
                cursor.execute('''
                        UPDATE user SET username = ?, email = ?, status = ? 
                        WHERE id = ?
                        ''', (username, email, status, user_id))
            # 处理角色分配（如果提供了角色数据）
            if 'role' in data:
                # 删除用户现有角色
                cursor.execute('DELETE FROM user_roles WHERE user_id = ?', (user_id,))
                # 分配新角色
                roles = data.get('role', [])
                if roles:
                    cursor.executemany('''
                            INSERT INTO user_roles (user_id, role_id)
                            VALUES (?, ?)
                            ''', [(user_id, role_id) for role_id in roles])
            db.commit()
            # 【新增】记录成功日志
            details = f"用户名: {original_username}, 状态变更: {original_status}→{status}"
            if 'role' in data:
                details += f", 角色变更: {data.get('role')}"
            # 记录成功日志（标准化格式）
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type=operation_type,
                operation_object='用户',
                operation_summary=f"{operation_type}用户: {original_username}",  # 简略摘要
                operation_details=json.dumps({  # JSON详细信息
                    "user_id": user_id,
                    "original_info": {
                        "username": original_username,
                        "email": user_data['email'],
                        "status": original_status
                    },
                    "updated_info": {
                        "username": username,
                        "email": email,
                        "status": status,
                        "roles": roles,
                        "password_updated": 'password' in data and bool(data['password'])
                    },
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=1
            )
            return jsonify({'success': True, 'message': '用户更新成功'})
        except sqlite3.IntegrityError:
            db.rollback()
            # 【新增】记录失败日志
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='编辑',
                operation_object='用户',
                operation_summary=f"编辑用户失败: {original_username} (用户名/邮箱已存在)",  # 简略摘要
                operation_details=json.dumps({  # JSON详细信息
                    "user_id": user_id,
                    "conflict_info": {
                        "username": username,
                        "email": email,
                        "conflict_field": "用户名" if db.execute("SELECT 1 FROM user WHERE username = ?",
                                                                 (username,)).fetchone() else "邮箱"
                    },
                    "error": "用户名或邮箱已存在",
                    "error_type": "IntegrityError",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({'success': False, 'message': '用户名或邮箱已存在'}), 409
        except Exception as e:
            db.rollback()
            # 【新增】记录失败日志
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='编辑',
                operation_object='用户',
                operation_summary=f"编辑用户失败: {original_username}",  # 简略摘要
                operation_details=json.dumps({  # JSON详细信息
                    "user_id": user_id,
                    "user_info": {
                        "original_username": original_username,
                        "target_username": username,
                        "email": email
                    },
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({'success': False, 'message': f"更新用户失败: {str(e)}"}), 500


@app.route('/user_del', methods=['DELETE'])
@login_required
@permission_required('user_del')
def user_del():
    user_id = request.args.get('id')
    # 防止删除自己
    if int(user_id) == current_user.id:
        return jsonify({'success': False, 'message': '不能删除当前登录用户'}), 400
    db = get_db()
    # 初始化变量，避免赋值前引用问题
    username = "未知用户"  # <-- 添加默认值
    cursor = None  # <-- 初始化cursor
    try:
        cursor = db.cursor()

        # 【新增】获取用户名用于日志
        cursor.execute('SELECT username FROM user WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user:
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='删除',
                operation_object='用户',
                operation_summary=f"删除用户失败: ID {user_id} (用户不存在)",
                operation_details=json.dumps({
                    "user_id": user_id,
                    "error": "用户不存在",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        username = user['username']
        # 删除用户角色关联
        cursor.execute('DELETE FROM user_roles WHERE user_id = ?', (user_id,))
        # 删除用户
        cursor.execute('DELETE FROM user WHERE id = ?', (user_id,))
        if cursor.rowcount == 0:
            db.rollback()
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='删除',
                operation_object='用户',
                operation_summary=f"删除用户失败: ID {user_id} (用户不存在)",
                operation_details=json.dumps({
                    "user_id": user_id,
                    "error": "用户不存在",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        db.commit()
        # 【新增】记录成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='用户',
            operation_summary=f"删除用户: {username}",
            operation_details=json.dumps({
                "user_id": user_id,
                "username": username,
                "deleted_roles": cursor.rowcount,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': '用户删除成功'})
    except Exception as e:
        db.rollback()
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='用户',
            operation_summary=f"删除用户: {username}",
            operation_details=json.dumps({
                "user_id": user_id,
                "username": username,
                "deleted_roles": cursor.rowcount,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': False, 'message': f"删除用户失败: {str(e)}"}), 500


@app.route('/user/<int:user_id>/roles', methods=['POST'])
@login_required
@permission_required('user_assign')
def assign_user_roles(user_id):
    data = request.get_json()
    roles = data['roles']
    db = get_db()
    try:
        cursor = db.cursor()
        # 先删除现有角色
        cursor.execute('DELETE FROM user_roles WHERE user_id = ?', (user_id,))
        # 分配新角色
        if roles:
            cursor.executemany('''
            INSERT INTO user_roles (user_id, role_id)
            VALUES (?, ?)
            ''', [(user_id, role_id) for role_id in roles])
        db.commit()
        return jsonify({'success': True, 'message': '角色分配成功'})
    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': f"角色分配失败: {str(e)}"}), 500


@app.route('/roles', methods=['GET', 'POST'])
@login_required
@permission_required('role_view')  # 角色管理需要role_view权限
def roles():
    if request.method == 'GET':
        db = get_db()
        try:
            # 获取所有角色
            cursor = db.cursor()
            cursor.execute(''' SELECT id, role_name, role_description, created_at, updated_at FROM roles''')
            roles = cursor.fetchall()

            role_list = []
            for role in roles:
                # 获取角色拥有的权限
                cursor.execute('''
                SELECT p.code FROM permissions p
                JOIN role_permissions rp ON p.id = rp.permission_id
                WHERE rp.role_id = ?
                ''', (role['id'],))
                permissions = [row['code'] for row in cursor.fetchall()]

                # 新增：查询角色关联的用户数量
                cursor.execute('''
                SELECT COUNT(DISTINCT ur.user_id) as user_count
                FROM user_roles ur
                LEFT JOIN user u ON ur.user_id = u.id
                WHERE ur.role_id = ?
                ''', (role['id'],))
                user_count = cursor.fetchone()['user_count'] or 0

                role_list.append({
                    'id': role['id'],
                    'role_name': role['role_name'],
                    'role_description': role['role_description'],
                    'permissions': permissions,  # 返回角色拥有的权限列表
                    'user_count': user_count,  # 新增：角色关联用户数量
                    'created_at': role['created_at'],
                    'updated_at': role['updated_at']
                })
            # 【新增】根据请求头判断返回 JSON 还是渲染页面
            if request.headers.get('Accept') == 'application/json':
                return jsonify({
                    'success': True,
                    'roles': role_list  # 返回角色列表 JSON 数据
                })
            else:
                # 原逻辑：渲染角色管理页面
                return render_template('systemseting.html', role_list=role_list)
        except Exception as e:
            return jsonify({"success": False, "message": f"获取角色失败：{str(e)}"}), 500

    elif request.method == 'POST':
        # 添加新角色 (需要role_add权限)
        if not current_user.has_permission('role_add'):
            return jsonify(success=False, message='没有添加角色权限'), 403
        db = get_db()
        # 【修复】提前初始化role_data变量，确保所有代码路径都能访问
        role_data = None  # <-- 添加此行，在try块外初始化变量
        try:
            # 获取JSON数据（而非表单数据）
            role_data = request.get_json()
            if not role_data:
                return jsonify({"success": False, "message": "请求数据格式错误，应为JSON"}), 400
            cursor = db.cursor()

            # 创建角色 - 使用role_data而非request.form
            role_name = role_data.get('role_name')
            role_description = role_data.get('role_description', '')

            cursor.execute(''' 
                INSERT INTO roles (role_name, role_description, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                 ''', (
                role_name,  # <-- 修复：从JSON数据获取
                role_description,  # <-- 修复：从JSON数据获取，提供默认值
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ))
            role_id = cursor.lastrowid
            # 分配权限 - 同样从JSON数据获取
            permissions = role_data.get('permissions', [])  # <-- 修复：从JSON数据获取

            if permissions:
                cursor.executemany('''
                    INSERT INTO role_permissions (role_id, permission_id)
                    VALUES (?, ?)
                    ''', [(role_id, p) for p in permissions])
            # 获取权限名称列表用于日志
            permission_names = []
            if permissions:
                placeholders = ', '.join(['?'] * len(permissions))
                cursor.execute(f'SELECT code FROM permissions WHERE id IN ({placeholders})', permissions)
                permission_names = [row['code'] for row in cursor.fetchall()]
            db.commit()
            # 【新增】记录成功日志
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='添加',
                operation_object='角色',
                operation_summary=f"添加角色: {role_name}",  # 简略摘要
                operation_details=json.dumps({  # JSON格式详细信息
                    "role_id": role_id,
                    "role_name": role_name,
                    "role_description": role_description,
                    "permissions": {
                        "count": len(permissions),
                        "permission_ids": permissions,
                        "permission_codes": permission_names
                    },
                    "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=1
            )
            return jsonify({"success": True, "message": "角色添加成功！"}), 200
        except sqlite3.IntegrityError as e:
            db.rollback()
            # 【修复】记录失败日志，确保role_data已初始化
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='添加',
                operation_object='角色',
                operation_summary=f"添加角色失败: {(role_data.get('role_name') if role_data else '未知角色')} (角色名称已存在)",
                # 安全获取角色名
                operation_details=json.dumps({
                    "role_name": role_data.get('role_name') if role_data else None,
                    "role_description": role_data.get('role_description', '') if role_data else '',
                    "permissions": {
                        "count": len(role_data.get('permissions', [])) if role_data else 0,
                        "permission_ids": role_data.get('permissions', []) if role_data else []
                    },
                    "error": "角色名称已存在",
                    "error_type": "IntegrityError",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({"success": False, "message": f"错误：{str(e)}"}), 500
        except Exception as e:
            db.rollback()
            # 【修复】确保role_data已初始化，避免赋值前引用
            role_data = role_data or {}  # <-- 添加此行确保role_data是字典
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='添加',
                operation_object='角色',
                operation_summary=f"添加角色失败: {role_data.get('role_name', '未知角色')}",  # 现在安全了
                operation_details=json.dumps({
                    "role_name": role_data.get('role_name'),
                    "role_description": role_data.get('role_description', ''),
                    "permissions": {
                        "count": len(role_data.get('permissions', [])),
                        "permission_ids": role_data.get('permissions', [])
                    },
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({"success": False, "message": f"错误：{str(e)}"}), 500


@app.route('/role_edit', methods=['GET', 'POST'])
@login_required
@permission_required('role_edit')
def role_edit():
    if request.method == 'GET':
        role_id = request.args.get('id')
        try:
            db = get_db()
            cursor = db.cursor()

            # 获取角色信息
            cursor.execute('SELECT id, role_name, role_description FROM roles WHERE id = ?', (role_id,))
            role = cursor.fetchone()

            if not role:
                return jsonify({'success': False, 'message': '角色不存在'}), 404

            # 获取角色权限
            cursor.execute('''
            SELECT p.id FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role_id = ?
            ''', (role_id,))
            permissions = [row['id'] for row in cursor.fetchall()]

            return jsonify({
                'success': True,
                'role': dict(role),
                'permissions': permissions
            })
        except Exception as e:
            return jsonify({'success': False, 'message': f"获取角色信息失败: {str(e)}"}), 500

    elif request.method == 'POST':
        data = request.get_json()
        role_id = data.get('id')
        db = get_db()
        # 初始化变量，避免赋值前引用
        original_role_name = "未知角色"
        permissions = []
        permission_codes = []

        try:
            cursor = db.cursor()
            # 获取原角色名称用于日志
            cursor.execute('SELECT role_name FROM roles WHERE id = ?', (role_id,))
            role = cursor.fetchone()
            if not role:
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='编辑',
                    operation_object='角色',
                    operation_summary=f"编辑角色失败: 角色ID {role_id} (角色不存在)",
                    operation_details=json.dumps({
                        "role_id": role_id,
                        "error": "角色不存在",
                        "error_type": "NotFoundError",
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=0
                )
                return jsonify(success=False, message='角色不存在'), 404
            original_role_name = role['role_name']

            # 初始化权限变量
            permissions = data.get('permissions', [])

            # 更新角色信息
            cursor.execute('''
            UPDATE roles SET role_name = ?, role_description = ?, updated_at = ?
            WHERE id = ?
            ''', (
                data['role_name'],
                data['role_description'],
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                role_id
            ))

            # 如果有提交权限，则更新权限
            if 'permissions' in data:
                cursor.execute('DELETE FROM role_permissions WHERE role_id = ?', (role_id,))
                permissions = data['permissions']
                if permissions:
                    cursor.executemany('''
                    INSERT INTO role_permissions (role_id, permission_id)
                    VALUES (?, ?)
                    ''', [(role_id, p) for p in permissions])

                # 获取权限名称用于日志详情
                if permissions:
                    placeholders = ', '.join(['?'] * len(permissions))
                    cursor.execute(f'SELECT code FROM permissions WHERE id IN ({placeholders})', permissions)
                    permission_codes = [row['code'] for row in cursor.fetchall()]

            db.commit()
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='编辑',
                operation_object='角色',
                operation_summary=f"编辑角色: {original_role_name} → {data['role_name']}",
                operation_details=json.dumps({
                    "role_id": role_id,
                    "original_role_name": original_role_name,
                    "new_role_name": data['role_name'],
                    "role_description": data['role_description'],
                    "permissions": {
                        "count": len(permissions),
                        "permission_ids": permissions,
                        "permission_codes": permission_codes
                    },
                    "updated_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=1
            )
            return jsonify({'success': True, 'message': '角色更新成功'})

        except Exception as e:
            db.rollback()
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='编辑',
                operation_object='角色',
                operation_summary=f"编辑角色失败: {original_role_name}",
                operation_details=json.dumps({
                    "role_id": role_id,
                    "original_role_name": original_role_name,
                    "request_data": {
                        "new_role_name": data.get('role_name'),
                        "role_description": data.get('role_description'),
                        "permission_count": len(permissions)
                    },
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({'success': False, 'message': f"更新角色失败: {str(e)}"}), 500


@app.route('/role_del', methods=['DELETE'])
@login_required
@permission_required('role_del')
def role_del():
    role_id = request.args.get('id')
    # 防止删除管理员角色
    if int(role_id) == 1:
        return jsonify({'success': False, 'message': '不能删除默认管理员角色'}), 400
    db = get_db()
    # 初始化变量避免赋值前引用
    role_name = "未知角色"
    deleted_permissions_count = 0

    try:
        cursor = db.cursor()
        # 获取角色名称用于日志
        cursor.execute('SELECT role_name FROM roles WHERE id = ?', (role_id,))
        role = cursor.fetchone()
        if not role:
            # 【优化】角色不存在日志
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='删除',
                operation_object='角色',
                operation_summary=f"删除角色失败: 角色ID {role_id} (角色不存在)",  # 简略摘要
                operation_details=json.dumps({  # JSON详细信息
                    "role_id": role_id,
                    "error": "角色不存在",
                    "error_type": "NotFoundError",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify(success=False, message='角色不存在'), 404
        role_name = role['role_name']

        # 检查是否有关联用户
        cursor.execute('SELECT COUNT(*) as count FROM user_roles WHERE role_id = ?', (role_id,))
        count = cursor.fetchone()['count']
        if count > 0:
            # 【新增】关联用户存在时记录日志
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='删除',
                operation_object='角色',
                operation_summary=f"删除角色失败: {role_name} (已分配给{count}个用户)",  # 简略摘要
                operation_details=json.dumps({  # JSON详细信息
                    "role_id": role_id,
                    "role_name": role_name,
                    "user_count": count,
                    "error": "角色已分配给用户，无法删除",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            db.rollback()
            return jsonify({'success': False, 'message': f'该角色已分配给{count}个用户，请先移除用户关联'}), 400

        # 删除角色权限关联
        cursor.execute('DELETE FROM role_permissions WHERE role_id = ?', (role_id,))
        deleted_permissions_count = cursor.rowcount  # 记录删除的权限关联数量

        # 删除角色
        cursor.execute('DELETE FROM roles WHERE id = ?', (role_id,))
        deleted_role_count = cursor.rowcount

        if deleted_role_count == 0:
            db.rollback()
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='删除',
                operation_object='角色',
                operation_summary=f"删除角色失败: 角色ID {role_id} (角色不存在)",
                operation_details=json.dumps({
                    "role_id": role_id,
                    "error": "角色不存在",
                    "error_type": "NotFoundError",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({'success': False, 'message': '角色不存在'}), 404

        db.commit()
        # 【优化】删除成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='角色',
            operation_summary=f"删除角色: {role_name} (ID: {role_id})",  # 简略摘要
            operation_details=json.dumps({  # JSON详细信息
                "role_id": role_id,
                "role_name": role_name,
                "deleted_permissions_count": deleted_permissions_count,
                "deleted_role_count": deleted_role_count,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': '角色删除成功'})

    except Exception as e:
        db.rollback()
        # 【优化】异常日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='角色',
            operation_summary=f"删除角色失败: {role_name}",  # 简略摘要
            operation_details=json.dumps({  # JSON详细信息
                "role_id": role_id,
                "role_name": role_name,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': f"删除角色失败: {str(e)}"}), 500


@app.route('/roles/<int:role_id>/permissions', methods=['GET', 'POST'])
@login_required
@permission_required('role_assign')  # 分配权限需要role_assign权限
def role_permissions(role_id):
    db = get_db()
    if request.method == 'GET':
        # 获取角色当前拥有的权限
        cursor = db.cursor()
        cursor.execute('''
        SELECT p.id, p.code, p.name, 
               (SELECT 1 FROM role_permissions rp WHERE rp.role_id = ? AND rp.permission_id = p.id) as has_perm
        FROM permissions p
        ''', (role_id,))
        permissions = cursor.fetchall()
        return jsonify({
            "success": True,
            "permissions": [dict(perm) for perm in permissions]
        })


    elif request.method == 'POST':
        # 更新角色权限
        permissions = request.json.get('permissions', [])
        cursor = db.cursor()
        # 初始化变量避免赋值前引用
        role_name = "未知角色"
        old_permissions = []
        permission_codes = []
        try:
            # 获取角色名称和现有权限用于日志
            cursor.execute('SELECT role_name FROM roles WHERE id = ?', (role_id,))
            role = cursor.fetchone()
            if not role:
                # 【优化】角色不存在日志
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='分配',
                    operation_object='角色权限',
                    operation_summary=f"分配角色权限失败: 角色ID {role_id} (角色不存在)",  # 简略摘要
                    operation_details=json.dumps({  # JSON详细信息
                        "role_id": role_id,
                        "error": "角色不存在",
                        "error_type": "NotFoundError",
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=0
                )
                return jsonify({"success": False, "message": "角色不存在"}), 404
            role_name = role['role_name']
            # 获取原权限列表用于变更对比
            cursor.execute('SELECT permission_id FROM role_permissions WHERE role_id = ?', (role_id,))
            old_permissions = [row['permission_id'] for row in cursor.fetchall()]
            # 先删除现有权限
            cursor.execute('DELETE FROM role_permissions WHERE role_id = ?', (role_id,))
            # 添加新权限
            if permissions:
                cursor.executemany('''
                INSERT INTO role_permissions (role_id, permission_id)
                VALUES (?, ?)
                ''', [(role_id, p) for p in permissions])
                # 获取权限代码用于日志详情
                placeholders = ', '.join(['?'] * len(permissions))
                cursor.execute(f'SELECT id, code FROM permissions WHERE id IN ({placeholders})', permissions)
                permission_codes = {row['id']: row['code'] for row in cursor.fetchall()}
            db.commit()
            # 【优化】分配成功日志
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='分配',
                operation_object='角色权限',
                operation_summary=f"分配角色权限: {role_name} (权限数量: {len(permissions)})",  # 简略摘要
                operation_details=json.dumps({  # JSON详细信息
                    "role_id": role_id,
                    "role_name": role_name,
                    "permission_changes": {
                        "old_count": len(old_permissions),
                        "new_count": len(permissions),
                        "added": list(set(permissions) - set(old_permissions)),
                        "removed": list(set(old_permissions) - set(permissions)),
                        "total_changed": abs(len(permissions) - len(old_permissions))
                    },
                    "current_permissions": {
                        "count": len(permissions),
                        "permission_ids": permissions,
                        "permission_codes": permission_codes  # 权限代码映射
                    },
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=1
            )
            return jsonify({"success": True, "message": "权限分配成功！"})
        except Exception as e:
            db.rollback()
            # 【优化】分配失败日志
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='分配',
                operation_object='角色权限',
                operation_summary=f"分配角色权限失败: {role_name}",  # 简略摘要
                operation_details=json.dumps({  # JSON详细信息
                    "role_id": role_id,
                    "role_name": role_name,
                    "requested_permissions": {
                        "count": len(permissions),
                        "permission_ids": permissions
                    },
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({"success": False, "message": f"权限分配失败：{str(e)}"}), 500


# 操作日志
@app.route("/logs", methods=['GET'])
@login_required
@permission_required('log_view')
def logs():
    # 新增：如果请求操作类型列表参数，返回操作类型数据
    if request.args.get('get_operation_types') == 'true':
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute('SELECT DISTINCT operation_type FROM operation_logs ORDER BY operation_type')
            types = [row['operation_type'] for row in cursor.fetchall()]
            return jsonify({"success": True, "types": types})
        except Exception as e:
            app.logger.error(f"获取操作类型失败: {str(e)}")
            return jsonify({"success": False, "message": "获取操作类型失败"}), 500

    # 如果是API请求（带X-Requested-With头），返回JSON数据
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # 获取分页参数，默认第1页，每页10条
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        offset = (page - 1) * per_page

        # 初始化查询条件
        query_conditions = []
        query_params = []

        # 处理搜索和筛选参数
        operation_type = request.args.get('operation_type')
        operation_object = request.args.get('operation_object')
        success = request.args.get('success')  # 不再立即转换为整数
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        # 新增：获取搜索关键词
        search_keyword = request.args.get('search', '').strip()

        if operation_type:
            # 处理多个操作类型（逗号分隔）
            if ',' in operation_type:
                types = operation_type.split(',')
                placeholders = ', '.join(['?'] * len(types))
                query_conditions.append(f"operation_type IN ({placeholders})")
                query_params.extend(types)
            else:
                query_conditions.append("operation_type = ?")
                query_params.append(operation_type)
        if operation_object:
            # 处理多个操作对象（逗号分隔）
            if ',' in operation_object:
                objects = operation_object.split(',')
                placeholders = ', '.join(['?'] * len(objects))
                query_conditions.append(f"operation_object IN ({placeholders})")
                query_params.extend(objects)
            else:
                query_conditions.append("operation_object = ?")
                query_params.append(operation_object)

        if success is not None and success != '':
            # 修复：处理多个success值（逗号分隔）
            if ',' in success:
                # 分割逗号并转换为整数列表
                success_values = [int(s.strip()) for s in success.split(',') if s.strip().isdigit()]
                if success_values:
                    placeholders = ', '.join(['?'] * len(success_values))
                    query_conditions.append(f"success IN ({placeholders})")
                    query_params.extend(success_values)
            else:
                # 单个值情况
                try:
                    query_conditions.append("success = ?")
                    query_params.append(int(success))
                except ValueError:
                    # 忽略无效的success参数
                    pass
        # 新增：处理操作用户筛选
        username = request.args.get('username')
        if username:
            query_conditions.append("username = ?")
            query_params.append(username)
        if start_time:
            # 修复：转换前端时间格式为数据库格式
            start_time = start_time.replace('T', ' ')
            query_conditions.append("operation_time >= ?")
            query_params.append(start_time)
        if end_time:
            # 修复：转换前端时间格式为数据库格式并添加秒数
            end_time = end_time.replace('T', ' ')
            # 如果没有秒数部分，添加默认秒数
            if len(end_time) <= 16:  # "YYYY-MM-DD HH:MM"长度为16
                end_time += ":00"
            query_conditions.append("operation_time <= ?")
            query_params.append(end_time)
        # 新增：搜索关键词条件 (支持用户名、操作摘要和操作详情的模糊搜索)
        if search_keyword:
            query_conditions.append("(username LIKE ? OR operation_summary LIKE ? OR operation_details LIKE ?)")
            search_param = f'%{search_keyword}%'
            query_params.extend([search_param, search_param, search_param])

        # 构建查询SQL
        where_clause = "WHERE " + " AND ".join(query_conditions) if query_conditions else ""
        query_params_count = query_params.copy()

        try:
            db = get_db()
            cursor = db.cursor()

            # 查询总记录数
            cursor.execute(f"SELECT COUNT(*) as total FROM operation_logs {where_clause}", query_params_count)
            total = cursor.fetchone()['total']

            # 查询当前页数据
            query_params_paginated = query_params.copy()
            query_params_paginated.extend([per_page, offset])
            cursor.execute(f"""
                SELECT id, user_id, username, operation_type, operation_object, 
                       operation_summary, operation_details, success, operation_time
                FROM operation_logs 
                {where_clause}
                ORDER BY operation_time DESC 
                LIMIT ? OFFSET ?
            """, query_params_paginated)

            logs = cursor.fetchall()

            # 转换为字典列表
            log_list = []
            for log in logs:
                log_dict = dict(log)
                # print(log_dict)
                # 将operation_details从JSON字符串解析为对象（如果存在）
                if log_dict['operation_details']:
                    try:
                        log_dict['operation_details'] = json.loads(log_dict['operation_details'])
                    except json.JSONDecodeError:
                        pass  # 保持原始字符串格式
                log_list.append(log_dict)

            # 返回分页数据
            return jsonify({
                'success': True,
                'data': log_list,
                'pagination': {
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'pages': (total + per_page - 1) // per_page  # 总页数
                }
            })

        except Exception as e:
            app.logger.error(f"日志查询失败: {str(e)}")
            return jsonify({
                'success': False,
                'message': f"日志查询失败: {str(e)}"
            }), 500

    # 非API请求，返回日志页面
    return render_template('logs.html')


# 注销路由
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功注销', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=2025)
