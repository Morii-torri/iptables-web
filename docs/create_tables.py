#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2025/7/25 17:05
# @Author  : lsy
# @FileName: 创建主机表.py
# @Software: PyCharm
# @Function:
import sqlite3
from sqlite3 import Error
from werkzeug.security import generate_password_hash


def create_connection(db_file):
    """创建数据库连接"""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)
    return conn


def create_hosts_table(conn):
    """创建主机表"""
    try:
        sql_create_hosts_table = """
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_name TEXT NOT NULL,           -- 主机名称
            host_identifier TEXT UNIQUE NOT NULL, -- 主机标识，唯一
            ip_address TEXT NOT NULL,          -- IP地址
            operating_system TEXT,             -- 操作系统
            ssh_port INTEGER DEFAULT 22,       -- SSH端口，默认22
            username TEXT NOT NULL,            -- 用户名
            auth_method TEXT NOT NULL,         -- 认证方式：password或key
            password TEXT,                     -- 密码，当auth_method为password时使用
            private_key TEXT,                  -- 私钥，当auth_method为key时使用
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_hosts_table)
        print("主机表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_template_table(conn):
    """创建模板表"""
    try:
        sql_create_hosts_table = """
        CREATE TABLE IF NOT EXISTS templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            template_name TEXT UNIQUE NOT NULL,   -- 模板名称
            template_identifier TEXT NOT NULL, -- 模板简介，唯一
            direction TEXT DEFAULT 'INPUT',   -- 方向
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_hosts_table)
        print("模板表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_rule_table(conn):
    """创建规则表"""
    try:
        sql_create_hosts_table = """
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            template_id TEXT  NOT NULL,   -- 模板ID
            policy TEXT  NOT NULL,   -- 授权策略
            protocol TEXT NOT NULL, -- 协议
            port TEXT DEFAULT '-1/-1',        -- 单端口
            auth_object TEXT DEFAULT '0.0.0.0/0',        -- 授权对象
            description TEXT ,        -- 注释
            limit TEXT ,        -- 限流
            group_name TEXT,          -- 规则所属分组
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_hosts_table)
        print("规则表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_rule_groups_table(conn):
    """创建模板规则分组表"""
    try:
        sql_create_rule_groups_table = """
        CREATE TABLE IF NOT EXISTS rule_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            template_id INTEGER NOT NULL,
            group_name TEXT NOT NULL,
            label_color TEXT DEFAULT '#6366f1',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(template_id, group_name)
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_rule_groups_table)
        print("模板规则分组表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_host_rule_groups_table(conn):
    """创建主机规则分组表"""
    try:
        sql_create_host_rule_groups_table = """
        CREATE TABLE IF NOT EXISTS host_rule_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            group_name TEXT NOT NULL,
            label_color TEXT DEFAULT '#6b7280',
            template_group_id INTEGER,
            is_default INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(host_id, group_name)
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_host_rule_groups_table)
        print("主机规则分组表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_host_rules_table(conn):
    """创建主机规则表"""
    try:
        sql_create_host_rules_table = """
        CREATE TABLE IF NOT EXISTS host_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            direction TEXT NOT NULL,
            target TEXT,
            protocol TEXT,
            port TEXT,
            auth_object TEXT,
            description TEXT,
            limit TEXT,
            signature TEXT NOT NULL,
            template_rule_id INTEGER,
            host_group_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(host_id, direction, signature)
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_host_rules_table)
        print("主机规则表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_user_table(conn):
    """创建用户表（RBAC版）"""
    try:
        sql_create_user_table = """
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,    -- 用户名（唯一）
            password TEXT NOT NULL,           -- 密码哈希
            email TEXT UNIQUE,                -- 邮箱（唯一，用于找回密码）
            status TEXT NOT NULL DEFAULT 'active',  -- 状态：active/inactive
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_user_table)
        print("用户表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_system_config_table(conn):
    """创建系统设置表"""
    try:
        sql_create_system_config_table = """
        CREATE TABLE IF NOT EXISTS system_config (
            id TEXT  NOT NULL,   -- id
            system_name TEXT  NOT NULL,   -- 系统名称
            session_timeout INTEGER NOT NULL DEFAULT 30,   -- 会话超时时间（分钟）
            log_retention_time TEXT  NOT NULL,   -- 日志保留时间
            color_mode TEXT NOT NULL DEFAULT 'light',   -- 色调模式：light或dark
            password_strategy TEXT  NOT NULL,   -- 密码策略
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_system_config_table)
        print("系统设置表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_role_table(conn):
    """创建角色表（RBAC版，移除硬编码权限字段）"""
    try:
        sql_create_role_table = """
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role_name TEXT NOT NULL UNIQUE,        -- 角色名称（唯一）
            role_description TEXT,                 -- 角色描述
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_role_table)
        print("角色表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_permissions_table(conn):
    """创建权限表（RBAC核心表）"""
    try:
        sql_create_permissions_table = """
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,                    -- 权限显示名称
            code TEXT NOT NULL UNIQUE,             -- 权限标识（代码中使用）
            description TEXT,                      -- 权限描述
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_permissions_table)
        print("权限表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_role_permissions_table(conn):
    """创建角色-权限关联表（多对多关系）"""
    try:
        sql_create_role_permissions_table = """
        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            PRIMARY KEY (role_id, permission_id),  -- 复合主键
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_role_permissions_table)
        print("角色-权限关联表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_user_roles_table(conn):
    """创建用户-角色关联表（多对多关系）"""
    try:
        sql_create_user_roles_table = """
        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, role_id),       -- 复合主键
            FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_user_roles_table)
        print("用户-角色关联表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def init_default_permissions(conn):
    """初始化默认权限数据"""
    try:
        permissions = [
            # 系统管理权限
            ('查看系统设置', 'sys_view', '查看系统配置页面'),
            ('编辑系统设置', 'sys_edit', '修改系统配置参数'),

            # 用户管理权限
            ('查看用户列表', 'user_view', '查看所有用户信息'),
            ('添加用户', 'user_add', '创建新用户'),
            ('编辑用户', 'user_edit', '修改用户信息'),
            ('删除用户', 'user_del', '删除用户'),

            # 角色管理权限
            ('查看角色列表', 'role_view', '查看所有角色信息'),
            ('添加角色', 'role_add', '创建新角色'),
            ('编辑角色', 'role_edit', '修改角色信息'),
            ('分配角色权限', 'role_assign', '为角色分配权限'),
            ('删除角色', 'role_del', '删除角色'),

            # 模板管理权限
            ('查看模板列表', 'temp_view', '查看所有模板信息'),
            ('添加模板', 'temp_add', '添加新模板'),
            ('编辑模板', 'temp_edit', '修改模板信息'),
            ('删除模板', 'temp_del', '删除模板'),

            # 主机管理权限
            ('查看主机列表', 'hosts_view', '查看所有服务器信息'),
            ('添加主机', 'hosts_add', '添加新服务器'),
            ('编辑主机', 'hosts_edit', '修改服务器信息'),
            ('删除主机', 'hosts_del', '从系统中删除服务器'),

            # 防火墙规则权限
            ('查看规则', 'iptab_view', '查看防火墙规则'),
            ('添加规则', 'iptab_add', '创建新防火墙规则'),
            ('编辑规则', 'iptab_edit', '修改现有防火墙规则'),
            ('删除规则', 'iptab_del', '删除防火墙规则'),

            # 日志权限
            ('查看操作日志', 'log_view', '查看系统操作日志')
        ]

        cursor = conn.cursor()
        cursor.executemany("""
            INSERT INTO permissions (name, code, description) 
            VALUES (?, ?, ?)
        """, permissions)
        conn.commit()
        print("默认权限数据初始化成功")
    except Error as e:
        conn.rollback()
        print(f"初始化权限数据出错: {e}")


# 【新增】创建操作日志表
def create_operation_logs_table(conn):
    """创建操作日志表"""
    try:
        sql_create_operation_logs_table = """
        CREATE TABLE IF NOT EXISTS operation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,                      -- 操作用户ID
            username TEXT NOT NULL,               -- 操作用户名
            operation_type TEXT NOT NULL,         -- 操作类型：添加/编辑/删除等
            operation_object TEXT NOT NULL,       -- 操作对象：用户/角色/主机等
            operation_summary TEXT NOT NULL,      -- 操作内容摘要（新增字段）
            operation_details TEXT,               -- 操作详情
            success INTEGER NOT NULL,             -- 操作结果：1成功，0失败
            operation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP  -- 操作时间
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_operation_logs_table)
        print("操作日志表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def main():
    database = "firewall_management.db"  # 数据库文件名

    # 创建数据库连接
    conn = create_connection(database)

    if conn is not None:
        try:
            # 创建核心业务表（保持不变）
            create_hosts_table(conn)
            create_template_table(conn)
            create_rule_table(conn)
            create_rule_groups_table(conn)
            create_host_rule_groups_table(conn)
            create_host_rules_table(conn)
            create_system_config_table(conn)

            # 创建RBAC相关表（新增和修改）
            create_user_table(conn)  # 修改：移除role_id字段
            create_role_table(conn)  # 修改：移除硬编码权限字段
            create_permissions_table(conn)  # 新增：权限表
            create_role_permissions_table(conn)  # 新增：角色-权限关联表
            create_user_roles_table(conn)  # 新增：用户-角色关联表

            # 【新增】创建操作日志表
            create_operation_logs_table(conn)

            # 初始化默认权限数据
            init_default_permissions(conn)

            # ====================== 新增管理员初始化代码 ======================
            cursor = conn.cursor()

            # 1. 创建管理员角色
            admin_role_id = None
            cursor.execute('''
                INSERT INTO roles (role_name, role_description, created_at, updated_at)
                VALUES (?, ?, ?, ?)
            ''', ('admin', '系统管理员，拥有所有权限', '2025-10-01 00:00:00', '2025-10-01 00:00:00'))
            admin_role_id = cursor.lastrowid
            print("管理员角色创建成功")

            # 2. 获取所有权限ID
            cursor.execute('SELECT id FROM permissions')
            permission_ids = [row[0] for row in cursor.fetchall()]

            # 3. 为管理员角色分配所有权限
            if permission_ids and admin_role_id:
                role_perm_data = [(admin_role_id, perm_id) for perm_id in permission_ids]
                cursor.executemany('''
                    INSERT INTO role_permissions (role_id, permission_id)
                    VALUES (?, ?)
                ''', role_perm_data)
                print("管理员角色权限分配成功")

            # 4. 创建admin用户（密码admin123，已哈希）
            admin_user_id = None
            hashed_password = generate_password_hash('admin123')  # 密码哈希处理
            cursor.execute('''
                INSERT INTO user (username, password, email, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', ('admin', hashed_password, 'admin@example.com', 'active',
                  '2025-10-01 00:00:00', '2025-10-01 00:00:00'))
            admin_user_id = cursor.lastrowid
            print("admin用户创建成功")

            # 5. 将admin用户关联到管理员角色
            if admin_user_id and admin_role_id:
                cursor.execute('''
                    INSERT INTO user_roles (user_id, role_id)
                    VALUES (?, ?)
                ''', (admin_user_id, admin_role_id))
                print("管理员用户角色关联成功")

            # 提交所有更改
            conn.commit()
            # ====================== 管理员初始化代码结束 ======================

            conn.close()
            print("数据库初始化完成，已创建默认管理员用户")
        except Error as e:
            conn.rollback()
            print(f"初始化过程出错: {e}")
            if conn:
                conn.close()
    else:
        print("无法创建数据库连接")


if __name__ == '__main__':
    main()
