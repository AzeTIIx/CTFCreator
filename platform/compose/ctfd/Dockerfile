# Image CTFd de cours — base epinglee + deps plugin challenge_containers (0xfbad)
FROM ctfd/ctfd:3.8.6

USER root
RUN /opt/venv/bin/pip install --no-cache-dir \
    "docker==7.1.0" \
    "paramiko==3.5.1" \
    "APScheduler==3.10.4" \
    "tzdata==2025.1" \
    "markupsafe==3.0.2"
USER 1001
