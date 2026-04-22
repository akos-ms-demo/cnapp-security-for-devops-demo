# Intentionally insecure Dockerfile for the demo.
# Issues Defender for Containers / MSDO (Trivy) will flag:
#  - old base image tag
#  - running as root
#  - no HEALTHCHECK
#  - ADD over HTTP
FROM python:3.8.0

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8080

# No USER directive -> runs as root
CMD ["python", "-u", "app.py"]
