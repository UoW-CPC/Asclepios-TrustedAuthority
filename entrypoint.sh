#!/bin/bash

# Prepare log files and start outputting logs to stdout
#touch ./logs/sse.log
#touch ./logs/sse-access.log
#tail -n 0 -f ./logs/sse*.log &

#export DJANGO_SETTINGS_MODULE=sse.settings
# Apply database migrations
echo "Apply database migrations"
python3 manage.py makemigrations
python3 manage.py migrate --run-syncdb

exec gunicorn TA.wsgi:application \
    --name TA \
    --bind 0.0.0.0:8000 \
    --workers 3
    # --limit-request-line 0 # configure to allow long-line requests
    # \
    #--log-level=info \
    #--log-file=./logs/sse.log \
    #--access-logfile=./logs/sse-access.log \
#"$@"
