FROM python:3.9

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY storage_service.py .

EXPOSE 5003

CMD ["python", "storage_service.py"]
