FROM python:3.7
ADD ./requirements.txt /tmp/requirements.txt
RUN pip install --cache-dir=/tmp --upgrade pip \
    && pip install --cache-dir=/tmp -r /tmp/requirements.txt \
    && rm -rvf /tmp/*
ENV MULTIDICT_NO_EXTENSIONS=1
ENV YARL_NO_EXTENSIONS=1
COPY asyncio_scanner.py /
#COPY init.sql /docker-entrypoint-initdb.d/
EXPOSE 8888
ENTRYPOINT python3 asyncio_scanner.py
