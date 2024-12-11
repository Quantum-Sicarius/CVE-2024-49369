FROM python:3.13

RUN mkdir /app
COPY requirements.txt /app/requirements.txt
COPY main.py /app/main.py

RUN pip install -r /app/requirements.txt

ENTRYPOINT [ "python", "/app/main.py" ]