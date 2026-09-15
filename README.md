# WatcherSys

Independent FleetDM/PacketFence lab components. Each folder runs separately; do not deploy everything together unless you intentionally need that workflow.

## Repository layout

Root keeps only shared docs/config:

```text
WatcherSys/
├── README.md
├── .gitignore
├── packetfence-lab-ca.crt
├── recovery-watcher/
├── cvss-proxy/
└── vulnerability-test/
```

## recovery-watcher

Purpose: watches Fleet MySQL for policy/CVE recovery transitions and closes matching open PacketFence security events.

```bash
cd recovery-watcher
cp .env.example .env
cp mysql-password.example mysql-password
cp pf-recovery.env.example pf-recovery.env
cp recovery-watcher.env.example recovery-watcher.env
chmod 600 .env mysql-password pf-recovery.env recovery-watcher.env

docker compose -f compose.example.yaml config
docker compose -f compose.example.yaml up -d --build
docker compose -f compose.example.yaml logs --tail=50 recovery-watcher
```

Tests:

```bash
cd recovery-watcher
python3 -m unittest discover -s tests -t . -v
```

## cvss-proxy

Purpose: receives Fleet CVE webhooks, looks up CVSS from NVD, and forwards the enriched event to PacketFence.

```bash
cd cvss-proxy
cp .env.example .env
chmod 600 .env

docker compose -f compose.example.yaml config
docker compose -f compose.example.yaml up -d --build
docker compose -f compose.example.yaml logs --tail=50 cvss-proxy
```

## vulnerability-test

Purpose: controlled Windows scripts for testing vulnerable/remediated 7-Zip CVE behavior in the lab.

Use only on disposable lab hosts.

## Secrets

Do not commit real `.env`, password, private key, or runtime state files. Example files contain placeholders only.
