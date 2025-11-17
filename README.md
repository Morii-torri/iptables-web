
## iptables-web - 防火墙规则管理系统
一个基于Flask和iptables的Web界面防火墙管理系统，支持通过Web界面配置和管理Linux服务器的iptables规则。

## 功能特点
- 主机管理：添加和管理多台Linux服务器
- 模板管理：创建、编辑和删除iptables规则模板
- 规则管理：可视化配置防火墙规则，支持TCP/UDP协议、端口范围和多端口设置
- 批量应用：将规则模板批量应用到多台主机
- 操作日志：记录所有系统操作，支持日志查询和审计
- 权限控制：基于角色的访问控制
- 主题切换：支持亮色/暗色主题切换

## 安装部署
### 环境要求
- Python 3.9+
- Flask 2.0+
- iptables 1.8+
- 操作系统：Linux（推荐CentOS 7+/Debian 10+/Ubuntu 20.04+）

## Docker部署(推荐)
```shell
# 克隆仓库
git clone https://gitee.com/shiya_liu/iptables-web.git
cd iptables-web

# 构建镜像
docker build -t iptables_web:latest .

# 运行容器
docker run --net=host -d   --name iptables-web iptables_web:latest 
```

## 使用指南
### 初始登录

- 初始用户名：admin
- 默认密码: admin123
- 首次登录后请立即修改密码

## 基本流程

1. 添加主机：在"主机管理"页面添加需要管理的Linux服务器
2. 创建模板：在"模板管理"页面创建规则模板
3. 配置规则：为模板添加具体的iptables规则
4. 应用模板：将模板应用到目标主机

## 规则配置说明
- TCP/UDP协议的单端口、端口范围和多端口设置
- 源IP地址限制
- 允许(ACCEPT)和拒绝(DROP)策略
- 规则描述和注释

## 技术栈
- 前端：Tailwind CSS, Font Awesome, JavaScript
- 后端：Python, Flask, SQLite3
- 网络：Paramiko (SSH连接), iptables命令

## 注意事项
- 配置完成后，请立即测试规则是否生效
- 建议在测试环境先配置规则，再应用到生产环境
- 操作日志记录所有系统操作，建议定期备份

## 扩展资源
- [iptables扩展模块文档](https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [Flask官方文档](https://flask.palletsprojects.com/en/2.0.x/)
- [Tailwind CSS文档](https://tailwindcss.com/docs)

## 截图
![login.png](docs%2Fscreenshots%2Flogin.png)
![hosts.png](docs%2Fscreenshots%2Fhosts.png)
![rules.png](docs%2Fscreenshots%2Frules.png)
![templates.png](docs%2Fscreenshots%2Ftemplates.png)
![users.png](docs%2Fscreenshots%2Fusers.png)
![logs.png](docs%2Fscreenshots%2Flogs.png)




## 注意事项
- debina、ubuntu持久化规则需要安装iptables-persistent（apt install iptables-persistent）
- 建议仅在受信任的网络环境中使用
- 生产环境中应启用HTTPS并加强安全配置
- 定期备份数据库和配置文件


## 贡献
欢迎提交issue和pull request改进系统功能。