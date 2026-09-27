FROM python:3.12-slim
WORKDIR /app
COPY . /app/
RUN useradd -m appuser
USER appuser
EXPOSE 9090
CMD ["python", "-m", "http.server", "9090"]
