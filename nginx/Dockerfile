FROM nginx:latest
RUN apt-get -y update && apt-get install -y nano fail2ban

COPY ./local.conf /etc/nginx/conf.d/default.conf
COPY ./nginx.conf /etc/nginx/nginx.conf

COPY entrypoint.sh entrypoint.sh
RUN chmod a+x entrypoint.sh
RUN touch /var/log/auth.log
RUN touch /var/log/nginx/fail.log

COPY ./jail.conf /etc/fail2ban/jail.local

RUN service fail2ban restart && fail2ban-client status

CMD ["./entrypoint.sh"]
