FROM python:3.8

WORKDIR /app

COPY app.py .

CMD ["python", "app.py"]
