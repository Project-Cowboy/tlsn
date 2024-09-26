#!/bin/sh
docker build -t nitronotary .
docker run -v /var/run/docker.sock:/var/run/docker.sock  -p 7047:7047 nitronotary
