# 控制面与边缘代理共用镜像：纯 Python 标准库，无需联网安装依赖。
FROM python:3.11-slim

WORKDIR /app
COPY app/ /app/

# 默认启动控制面；边缘节点通过 command 覆盖为 agent.py
ENV CONTROLLER_HOST=0.0.0.0 \
    CONTROLLER_PORT=8080 \
    CONTROLLER_DB=/data/controller.db \
    PYTHONUNBUFFERED=1

RUN mkdir -p /data && adduser --disabled-password --gecos "" appuser \
    && chown -R appuser /data /app
USER appuser
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status==200 else 1)"

CMD ["python3", "/app/server.py"]
