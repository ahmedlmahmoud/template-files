FROM python:3.12-alpine
WORKDIR /app
COPY server.py .
# The platform injects PORT; the server binds 0.0.0.0:$PORT.
ENV PORT=8080
EXPOSE 8080
CMD ["python3", "-u", "server.py"]
