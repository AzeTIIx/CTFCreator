# syntax=docker/dockerfile:1.7
FROM python:3.12-alpine AS builder
WORKDIR /build
COPY src/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-alpine AS runtime
RUN adduser -D -u 10001 -H -s /sbin/nologin ctf \
    && mkdir -p /app \
    && chown -R 10001:10001 /app

COPY --from=builder /install /usr/local
COPY --chown=10001:10001 src/ /app/

# Flag statique : même valeur que challenge.yml (publication avec allow_static_flags).
# Le plugin CTFd ne transmet pas de variable d'environnement par challenge.
ENV FLAG="CCTF{local_test_only}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp

WORKDIR /app
USER 10001
EXPOSE 1337
CMD ["python", "/app/app.py"]
