# systemd.user

User-level systemd units that start local Docker containers at login.

| Unit | Does |
|------|------|
| `local-containers.service` | `docker compose up` for `~/Documents/gt-dp/uni-services/docker-compose.yml` |
| `postgres-docker-container.service` | starts existing container `postgres-local` |
| `redis-docker-container.service` | starts existing container `redis-local` |

The `postgres-local` / `redis-local` containers must already exist (`docker run --name ...`).

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
