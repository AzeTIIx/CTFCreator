# syntax=docker/dockerfile:1.7
FROM python:3.12-alpine
RUN adduser -D -u 10001 -H -s /sbin/nologin ctf && mkdir -p /app && chown 10001:10001 /app
COPY --chown=10001:10001 src/ /app/
# Flag statique : même valeur que challenge.yml (publication avec allow_static_flags).
ENV FLAG="CCTF{local_test_only}" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
USER 10001
EXPOSE 1337
CMD ["python", "/app/server.py"]
