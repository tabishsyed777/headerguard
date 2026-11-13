FROM python:3.12-slim
WORKDIR /app
COPY headerguard.py /app/headerguard.py
RUN useradd --create-home --uid 10001 appuser
USER appuser
ENTRYPOINT ["python", "/app/headerguard.py"]
