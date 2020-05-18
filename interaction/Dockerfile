FROM python:2.7-alpine

ENV TERM linux


# For example:
run apk update && apk add --no-cache netcat-openbsd bash openssl-dev libffi-dev g++ linux-headers make
COPY requirements.txt /requirements.txt
run pip install -r requirements.txt



#COPY exploit1.sh /

COPY check.py /
COPY check.sh /
COPY kemlx.bz2 /
COPY exploit.py /
