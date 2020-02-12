FROM python:3

WORKDIR /usr/src/app

RUN pip install PyQt5

COPY . .

CMD [ "python", "./idarling_server.py", "--no-ssl", "-h", "0.0.0.0" ]
