FROM python:3.8-slim-buster

WORKDIR /app
ADD . /app
RUN pip3 install --no-cache-dir -r requirements.txt

CMD ["python3", "main.py"]
