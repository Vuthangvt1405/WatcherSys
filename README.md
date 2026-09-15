# WatcherSys

WatcherSys contains lab components for FleetDM and PacketFence recovery workflows.

## Components

```text
WatcherSys/
├── recovery-watcher/        # Fleet policy/CVE recovery watcher
├── cvss-proxy/              # Fleet CVE webhook CVSS enrichment proxy
├── vulnerability-test/      # Controlled Windows 7-Zip CVE test scripts
├── compose.example.yaml     # Docker Compose example
├── .env.example             # Compose host-side placeholder values
├── mysql-password.example   # Fleet MySQL password placeholder
└── pf-recovery.env.example  # PacketFence API credential placeholders
```

## Configure placeholders

Copy the example files and replace all placeholder values for your environment.

```bash
cp .env.example .env
cp mysql-password.example mysql-password
cp pf-recovery.env.example pf-recovery.env
cp recovery-watcher/recovery-watcher.env.example recovery-watcher/recovery-watcher.env
cp cvss-proxy/.env.example cvss-proxy/.env
chmod 600 .env mysql-password pf-recovery.env recovery-watcher/recovery-watcher.env cvss-proxy/.env
```

Example values to replace:

```dotenv
FLEET_DOCKER_NETWORK=your-fleet-docker-network
MYSQL_CA_FILE=/absolute/path/to/mysql-ca.pem
PACKETFENCE_CA_FILE=/absolute/path/to/packetfence-ca.crt
PACKETFENCE_HOST=packetfence.example
FLEET_HOST=fleet.example
PF_BASE_URL=https://packetfence.example:9999
PACKETFENCE_URL=https://packetfence.example:9999/api/v1/fleetdm-events/cve
PF_RECOVERY_USER=watcher-recovery
PF_RECOVERY_PASSWORD=replace-with-packetfence-api-password
MYSQL_PASSWORD=replace-with-fleet-mysql-password
```

Do not commit real `.env`, password, private key, or runtime state files.

## Run

```bash
docker compose -f compose.example.yaml config
docker compose -f compose.example.yaml up -d --build
docker compose -f compose.example.yaml ps
```

## Logs

```bash
docker compose -f compose.example.yaml logs --tail=50 recovery-watcher
docker compose -f compose.example.yaml logs --tail=50 cvss-proxy
```

## Test recovery watcher

```bash
python3 -m unittest discover -s tests -t recovery-watcher -v
```

## Stop

```bash
docker compose -f compose.example.yaml stop
```
