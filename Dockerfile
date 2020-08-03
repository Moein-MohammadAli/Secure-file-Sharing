FROM python:3.7

WORKDIR "/var/www"

RUN mkdir "src"

COPY requirements.txt /var/www/
#RUN apt-get update && apt-get install -y cron uwsgi uwsgi-plugin-python3 --no-install-recommends && apt-get autoremove --purge
RUN pip3 install uwsgi
RUN pip3 install -r requirements.txt

ADD core/ /var/www/src/core/
ADD backend/ /var/www/src/backend/
COPY manage.py /var/www/src/
COPY uwsgi.ini /var/www/

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR "/var/www/src"

CMD ["uwsgi", "--ini", "/var/www/uwsgi.ini"]

