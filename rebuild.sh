#!/bin/bash

echo "Stopping service nickelcobaltproxy"
docker compose down

echo "Updating repo with git pull (nickelcobaltproxy)"
git fetch origin
git reset --hard origin/$(git symbolic-ref --short HEAD)

echo "Service updated restarting! (nickelcobaltproxy)"
docker compose up --build -d

echo "Prune docker images! (nickelcobaltproxy)"
docker image prune -f

echo "Done! (nickelcobaltproxy)"