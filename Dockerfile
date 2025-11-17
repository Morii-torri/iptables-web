FROM crpi-op3zvwuk4p823yir.cn-hangzhou.personal.cr.aliyuncs.com/lsy_linux/python:alpine3.21
RUN mkdir -p /iptables-web
ADD . /iptables-web
WORKDIR /iptables-web
RUN ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN pip install --no-cache-dir -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/
ENTRYPOINT ["/usr/local/bin/python3.13", "/iptables-web/app.py"]