# systemd.user

User-level systemd units that start local Docker containers at login.

| Unit | Does |
|------|------|
| `local-containers.service` | `docker compose up` for `~/Documents/gt-dp/uni-services/docker-compose.yml` |
| `postgres-docker-container.service` | starts existing container `postgres-local` |
| `redis-docker-container.service` | starts existing container `redis-local` |

## Create the containers (once)

The units only *start* existing containers, so create them first. `--restart` is left off because systemd handles restarts.

```sh
docker run -d --name postgres-local -e POSTGRES_PASSWORD=<password> -p 5432:5432 -v postgres-local-data:/var/lib/postgresql/data postgres:16
docker run -d --name redis-local -p 6379:6379 -v redis-local-data:/data redis:7 redis-server --appendonly yes
```

Adjust image tags, ports and password to match your setup. `local-containers.service` needs no setup beyond the compose file.

## Install

```sh
mkdir -p ~/.config/systemd/user
cp *.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now local-containers postgres-docker-container redis-docker-container
```

## Check

```sh
systemctl --user status postgres-docker-container
journalctl --user -u local-containers -f
```
