# WatcherSys

WatcherSys is a Dockerized recovery controller for FleetDM and PacketFence. It watches Fleet's MySQL data for Windows policy and CVE recovery transitions, closes the matching open PacketFence security event, and asks PacketFence to reevaluate network access.

The controller is recovery-only:

- Fleet and PacketFence handle detection and isolation.
- WatcherSys handles a real `fail -> pass` or `vulnerable -> clean` transition.
- It does not generate CVE findings, send the initial violation webhook, assign an isolation VLAN, or replace PacketFence CoA configuration.

Additional lab components in this repository:

- `cvss-proxy/` enriches Fleet CVE webhooks with an NVD CVSS score and forwards them to PacketFence. PacketFence retains ownership of the severity threshold.
- `vulnerability-test/` contains the controlled 7-Zip CVE-2018-10115 test and remediation harness. Its current workflow does not restart Fleet osquery, Orbit, or osqueryd.
- `packetfence-lab-ca.crt` is the public PacketFence lab CA certificate used for TLS verification. It contains no private key.

## Tested environment

- FleetDM 4.90.1
- PacketFence REST API on HTTPS port 9999
- MySQL 8
- Docker Compose
- Windows endpoints with a non-empty Fleet `primary_mac`

Fleet database schemas can change between releases. Validate the SQL queries in `recovery.py` before using another Fleet version.

## How it works

Every polling cycle WatcherSys:

1. Connects directly to Fleet's MySQL database.
2. Reads the selected Windows policy result.
3. Reads software and operating-system CVE associations matching `CVE_REGEX`.
4. Stores each host's last result in a persistent JSON state file.
5. Takes no recovery action on the first observation; the first result establishes a baseline.
6. When a stored result changes from `false` to `true`, it authenticates to PacketFence.
7. Searches for the exact open event matching both endpoint MAC and configured PacketFence event ID.
8. Closes only that event row.
9. Calls PacketFence `reevaluate_access` for the endpoint.
10. Saves the new state only after the recovery operation succeeds. A failed recovery is retried on a later poll.

State keys look like:

```json
{
  "1:2": true,
  "1:cve:^CVE-2018-10115$": false
}
```

`true` means passing or clean. `false` means failing or vulnerable.

## Requirements

- A running FleetDM deployment using MySQL.
- Network access from the watcher container to Fleet MySQL.
- Network access from the watcher container to PacketFence HTTPS API.
- A PacketFence CA certificate trusted by the watcher.
- A dedicated PacketFence API account allowed to:
  - log in;
  - search security events;
  - close the matching event;
  - reevaluate endpoint access.
- PacketFence must already be configured to open the violation event and send CoA to the access switch.
- The access switch must accept PacketFence dynamic authorization/CoA.

Do not use a personal administrator account for the watcher.

## Repository layout

```text
WatcherSys/
├── app.py                    # Runtime loop and environment configuration
├── recovery.py               # Fleet readers, state engine, and PacketFence client
├── tests/test_recovery.py    # Unit tests
├── Dockerfile
├── compose.example.yaml
├── .dockerignore
├── requirements.txt
├── .env.example
├── mysql-password.example
└── pf-recovery.env.example
```

## Configuration

| Variable | Required | Default | Description |
|---|---:|---|---|
| `MYSQL_HOST` | yes | `mysql` | Fleet MySQL hostname reachable from the container |
| `MYSQL_PORT` | no | `3306` | Fleet MySQL port |
| `MYSQL_DATABASE` | no | `fleet` | Fleet database name |
| `MYSQL_USER` | no | `fleet` | Read-only Fleet database user recommended |
| `MYSQL_PASSWORD_FILE` | yes (recommended) | none | File containing the Fleet database password |
| `MYSQL_PASSWORD` | alternative | none | Direct password value; less secure because container inspection can expose it |
| `MYSQL_SSL_CA` | strongly recommended | none | CA file for encrypted MySQL with certificate and hostname verification |
| `POLICY_ID` | no | `2` | Fleet policy ID watched for recovery |
| `PF_SECURITY_EVENT_ID` | no | `3500001` | PacketFence event template used for policy violations |
| `CVE_REGEX` | no | `.*` | Python regular expression selecting CVEs |
| `PF_CVE_SECURITY_EVENT_ID` | no | `3500002` | PacketFence event template used for CVE violations |
| `PF_BASE_URL` | no | `https://172.16.1.3:9999` | PacketFence API base URL; must use HTTPS |
| `PF_CA_FILE` | no | `/etc/ssl/packetfence/ca.crt` | CA certificate used to verify PacketFence TLS |
| `PF_ALLOW_LEGACY_CA` | no | `false` | Explicit compatibility mode for a legacy CA with invalid key usage; keep disabled normally |
| `PF_TIMEZONE` | no | unset | IANA timezone (e.g. `America/New_York`) of the PacketFence server; used to interpret timezone-naive `release_date` values. If unset, PacketFence timestamps are treated as UTC. |
| `PF_CREDENTIAL_FILE` | no | `/run/secrets/pf-recovery-env` | File containing PacketFence API credentials |
| `STATE_FILE` | no | `/var/lib/fleet-recovery/state.json` | Persistent transition-state file |
| `POLL_SECONDS` | no | `2` | Delay between polling cycles |

Use an anchored CVE expression for a controlled event, for example:

```text
^CVE-2018-10115$
```

Avoid `.*` unless one PacketFence event is intentionally meant to represent every CVE on the endpoint. Unrelated operating-system CVEs can otherwise prevent recovery.

## Credential files

Copy the examples, then edit the copies:

```bash
cp .env.example .env
cp mysql-password.example mysql-password
cp pf-recovery.env.example pf-recovery.env
chmod 600 .env mysql-password pf-recovery.env
```

`.env`:

```dotenv
FLEET_DOCKER_NETWORK=fleetdm-lab_fleet-internal
MYSQL_CA_FILE=/absolute/path/to/mysql-ca.pem
PACKETFENCE_CA_FILE=/absolute/path/to/packetfence-ca.crt
```

`mysql-password` contains only the Fleet MySQL password:

```text
replace-with-fleet-mysql-password
```

`pf-recovery.env`:

```dotenv
PF_RECOVERY_USER=watcher-recovery
PF_RECOVERY_PASSWORD=replace-with-packetfence-api-password
```

These files are ignored by Git. Never commit actual database passwords, PacketFence credentials, API tokens, CA private keys, RADIUS secrets, or Fleet enrollment secrets.

## Docker deployment

### 1. Find the Fleet Docker network

```bash
docker network ls
```

For a Compose project named `fleetdm-lab`, the network is commonly named:

```text
fleetdm-lab_fleet-internal
```

Set the exact network name in `.env`.

### 2. Set the CA paths

Set `MYSQL_CA_FILE` in `.env` to the CA certificate used by Fleet MySQL. The example enables encrypted MySQL with certificate and hostname verification.

Set `PACKETFENCE_CA_FILE` to the CA certificate that signed the PacketFence API certificate. The container keeps certificate and hostname verification enabled for both services. `PF_BASE_URL` must use HTTPS; non-HTTPS values are rejected at startup to prevent credentials from being sent in cleartext.

For a same-host lab where MySQL TLS is intentionally unavailable, remove the `MYSQL_SSL_CA` environment entry and MySQL CA volume from `compose.example.yaml`. Keep MySQL on a private Docker network and do not publish port 3306.

### 3. Review event IDs and CVE scope

Edit `compose.example.yaml`:

```yaml
POLICY_ID: "2"
PF_SECURITY_EVENT_ID: "3500001"
CVE_REGEX: "^CVE-2018-10115$"
PF_CVE_SECURITY_EVENT_ID: "3500002"
PF_BASE_URL: "https://packetfence.example:9999"
```

The CVE regex must match the scope used by the PacketFence/Fleet violation integration.

### 4. Build and start

```bash
docker compose -f compose.example.yaml up -d --build
```

### 5. Verify the container

```bash
docker compose -f compose.example.yaml ps
docker compose -f compose.example.yaml logs --tail=50 recovery-watcher
```

Expected startup message:

```text
Fleet recovery watcher started for policy_id=2 and CVE regex=^CVE-2018-10115$
```

### 6. Verify MySQL connectivity

```bash
docker compose -f compose.example.yaml exec recovery-watcher python -c 'import os,pymysql; from app import mysql_ssl_options,read_env_or_file; c=pymysql.connect(host=os.environ["MYSQL_HOST"],port=int(os.environ.get("MYSQL_PORT","3306")),user=os.environ["MYSQL_USER"],password=read_env_or_file("MYSQL_PASSWORD"),database=os.environ["MYSQL_DATABASE"],ssl=mysql_ssl_options()); c.close(); print("mysql=connected")'
```

### 7. Inspect state

```bash
docker compose -f compose.example.yaml exec recovery-watcher cat /var/lib/fleet-recovery/state.json
```

Do not edit the state file to force recovery. Reconcile Fleet's authoritative result, the exact PacketFence event, and live network state instead.

## Add to an existing Fleet Compose stack

Instead of using the example as a separate project, copy the `recovery-watcher` service into the existing Fleet Compose file. Attach it to the same internal network as MySQL and keep a persistent named volume. If you deliberately use a bind mount instead, create the directory first and make it writable by container UID/GID `1000:1000`.

Important dependency behavior:

```yaml
depends_on:
  mysql:
    condition: service_healthy
```

This avoids starting before MySQL is ready. The watcher also retries later polling failures without exiting.

## Test locally

The tests use Python's standard `unittest` runner:

```bash
python3 -m unittest discover -s tests -v
```

Or test against the built image while mounting the test suite read-only:

```bash
docker build -t watchersys:test .
docker run --rm \
  -v "$PWD/tests:/tests:ro" \
  --entrypoint python \
  watchersys:test -m unittest discover -s /tests -v
```

The production Dockerfile intentionally does not copy tests into the runtime image.

## End-to-end policy recovery test

1. Confirm the Windows endpoint is online and currently in the trusted network.
2. Confirm the selected Fleet policy currently passes.
3. Confirm no matching PacketFence event is open.
4. Start monitoring Fleet, watcher logs, PacketFence events, RADIUS audit logs, and the switch session.
5. Cause one real policy `pass -> fail` transition.
6. Wait for Fleet's scheduled policy evaluation and violation automation.
7. Verify PacketFence opens the configured policy event.
8. Verify PacketFence sends CoA and the switch applies the restricted role/VLAN.
9. Remediate the endpoint so Fleet changes `fail -> pass`.
10. Verify WatcherSys logs `Recovered PacketFence event ... source=policy`.
11. Verify the exact PacketFence event is closed.
12. Verify a new RADIUS authorization returns the trusted role and the switch applies the trusted VLAN.
13. Verify DHCP/IP and data-plane access independently.

Closing an event proves PacketFence state changed. It does not by itself prove the switch applied a VLAN change.

## End-to-end CVE recovery test

1. Use an anchored `CVE_REGEX` and the matching PacketFence CVE event ID.
2. Establish a clean baseline with no matching Fleet CVE association and no open PacketFence event.
3. Install the controlled vulnerable software on the test endpoint.
4. Wait for Fleet software inventory to show the vulnerable version.
5. Run Fleet vulnerability processing when immediate lab feedback is required:

```bash
fleetctl trigger --name vulnerabilities
```

6. Verify Fleet associates the target CVE with the endpoint. Software inventory alone is not a CVE finding.
7. Verify PacketFence opens the CVE event and the endpoint is restricted.
8. Upgrade or remove the vulnerable software.
9. Wait for Fleet software inventory to show the remediated version.
10. Trigger vulnerability processing again if required.
11. Verify Fleet removes the target CVE association.
12. Verify WatcherSys logs `Recovered PacketFence event ... source=CVE`.
13. Verify the exact PacketFence event closes and network access is reevaluated.
14. Verify the switch role/VLAN, endpoint DHCP address, and data plane.

Fleet vulnerability processing can take several minutes because it downloads or synchronizes vulnerability databases. Installing a vulnerable version does not immediately cause isolation if Fleet has not created the CVE association yet.

## Logs and operations

Follow logs:

```bash
docker compose -f compose.example.yaml logs -f recovery-watcher
```

Restart after configuration or credential changes:

```bash
docker compose -f compose.example.yaml restart recovery-watcher
```

Rebuild after changing Python code or dependencies:

```bash
docker compose -f compose.example.yaml up -d --build recovery-watcher
```

Stop without deleting state:

```bash
docker compose -f compose.example.yaml stop recovery-watcher
```

Remove the container while retaining the named state volume:

```bash
docker compose -f compose.example.yaml down
```

## Troubleshooting

### Vulnerable software is visible, but the IP/VLAN does not change

Check each boundary separately:

1. Fleet software inventory shows the vulnerable version.
2. Fleet has a matching `software_cve` or OS vulnerability association.
3. Fleet's CVE webhook was dispatched.
4. PacketFence accepted it and opened the exact event.
5. PacketFence sent CoA.
6. The switch acknowledged CoA and applied the restricted role/VLAN.
7. The endpoint renewed DHCP after the VLAN change.

WatcherSys is not involved in steps 1-7 of initial isolation. It only handles recovery after the matching CVE disappears.

### Watcher is running but does not recover

- Confirm the active state changed from `false` to `true`.
- Confirm `CVE_REGEX` exactly matches the intended finding.
- Confirm the PacketFence event ID and endpoint MAC match an open event.
- Confirm PacketFence credentials are valid and authorized.
- Confirm the CA file validates the PacketFence certificate.
- Confirm the container can reach both MySQL and PacketFence.
- Check logs for HTTP status, missing-event, TLS, or MySQL errors.

### MySQL authentication requires `cryptography`

The requirements use `PyMySQL[rsa]`, which installs the support needed for MySQL `caching_sha2_password` authentication. Rebuild the image after changing requirements.

### Event closes but endpoint stays restricted

Treat this as a downstream enforcement problem:

- Check PacketFence RADIUS audit logs for CoA ACK, reject, or timeout.
- Check the live switch authentication session and assigned VLAN.
- Confirm the switch listens for dynamic authorization on the configured UDP port.
- Confirm a fresh Access-Accept returns the trusted role.
- Confirm DHCP renewal and endpoint reachability separately.

## Security notes

- Use dedicated least-privilege MySQL and PacketFence accounts.
- Keep secrets outside the image and repository.
- Mount only the PacketFence CA certificate, never its private key.
- Restrict permissions on credential and state files.
- Do not disable TLS verification to work around certificate problems.
- Do not expose MySQL publicly for this watcher; use a private Docker or management network.
- Review PacketFence API permissions and logs regularly.
- The watcher queries all Windows hosts for the configured policy/CVE scope. Test in a lab before production use.

## Known limitations

- Direct Fleet database access ties the implementation to Fleet's schema.
- Only Windows hosts are selected.
- Recovery is edge-triggered from persisted state.
- If no matching open event or matching event closed within the previous hour exists, recovery fails and retries rather than acting on unrelated events.
- If the event was closed within the previous hour but reevaluation previously failed, the watcher treats closure as satisfied and retries `reevaluate_access`.
- Live switch/VLAN verification is outside this controller.
- The state file is local JSON and is intended for one active watcher instance, not concurrent replicas.

## GitHub push commands

After reviewing the repository:

```bash
git init
git add .
git commit -m "first commit"
git branch -M main
git remote add origin git@github.com:Vuthangvt1405/WatcherSys.git
git push -u origin main
```

For HTTPS authentication, configure Git to use a credential helper that retrieves the token from the system keyring at runtime rather than embedding credentials in the remote URL:

```bash
git config --global credential.helper store
git remote set-url origin https://github.com/Vuthangvt1405/WatcherSys.git
```

Then store the token once via a secure prompt or `gh auth login`. Never commit `.env`, `mysql-password`, `pf-recovery.env`, private keys, or the state file.
