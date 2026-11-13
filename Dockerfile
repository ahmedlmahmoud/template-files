FROM python:3.12-alpine
WORKDIR /app
COPY server.py /app/server.py
CMD ["python", "-u", "server.py"]
