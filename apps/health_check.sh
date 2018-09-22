#!/bin/bash

webserver="127.0.0.1:6688"
response="PONG"

if curl -s "$webserver" | grep "$response"
then
    # TODO: push to aws cloudwatch put-metric-data --namespace "cpyher_heart_beat" --metric-data file://metric.json
    echo "beep" >> /home/ubuntu/cloudwatch_data/health.txt
fi
