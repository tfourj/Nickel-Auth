#!/bin/bash

echo "Stopping service (nickel-auth)"
docker compose down

echo "Updating repo with git pull (nickel-auth)"
git fetch origin
git reset --hard origin/$(git symbolic-ref --short HEAD)

echo "Service updated restarting! (nickel-auth)"
docker compose up --build -d

echo "Prune docker images! (nickel-auth)"
docker image prune -f

echo "Done! (nickel-auth)"