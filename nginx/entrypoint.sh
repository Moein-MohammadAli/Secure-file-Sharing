#!/bin/bash
service fail2ban start
nginx -g 'daemon off;'
