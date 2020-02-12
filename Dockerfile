FROM python:3-buster

WORKDIR /usr/src/app

COPY setup.py ./
RUN pip install PyQt5

COPY . .

CMD [ "python", "./idarling_server.py", "--no-ssl" ]
