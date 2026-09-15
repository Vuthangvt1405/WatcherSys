# WatcherSys

## 1. Clone

```bash
git clone https://github.com/Vuthangvt1405/WatcherSys.git
cd WatcherSys
```

## 2. PacketFence certificate

```bash
export PACKETFENCE_HOST=172.16.1.3
export PACKETFENCE_PORT=9999
export PACKETFENCE_CA_FILE="$PWD/packetfence-lab-ca.crt"

openssl x509 -in "$PACKETFENCE_CA_FILE" \
  -noout -subject -issuer -serial -dates -fingerprint -sha256

openssl s_client \
  -connect "${PACKETFENCE_HOST}:${PACKETFENCE_PORT}" \
  -servername "$PACKETFENCE_HOST" \
  -CAfile "$PACKETFENCE_CA_FILE" \
  -verify_return_error </dev/null
```

## 3. FleetDM certificate

On the FleetDM Docker host:

```bash
export FLEET_HOST=172.16.1.4
export FLEET_PORT=8080
export FLEET_CERT_FILE=/home/kali/fleetdm-lab/certs/server.crt

openssl x509 -in "$FLEET_CERT_FILE" \
  -noout -subject -issuer -serial -dates -fingerprint -sha256 -ext subjectAltName

openssl s_client \
  -connect "${FLEET_HOST}:${FLEET_PORT}" \
  -servername "$FLEET_HOST" \
  -CAfile "$FLEET_CERT_FILE" \
  -verify_return_error </dev/null
```

## 4. Windows Fleet osquery

Copy the FleetDM public certificate to Windows as `C:\Temp\fleet-server.crt`.

Run in Administrator PowerShell:

```powershell
Import-Certificate `
  -FilePath 'C:\Temp\fleet-server.crt' `
  -CertStoreLocation 'Cert:\LocalMachine\Root'

Get-ChildItem 'Cert:\LocalMachine\Root' |
  Where-Object Subject -eq 'CN=172.16.1.4' |
  Select-Object Subject, Issuer, Thumbprint, NotBefore, NotAfter

Restart-Service -Name 'Fleet osquery' -Force
Start-Sleep -Seconds 10

Get-CimInstance Win32_Service -Filter "Name='Fleet osquery'" |
  Select-Object Name, State, StartMode, PathName

Get-CimInstance Win32_Process |
  Where-Object Name -Match 'orbit|osqueryd' |
  Select-Object Name, ProcessId, ExecutablePath

Test-NetConnection 172.16.1.4 -Port 8080
```

## 5. Configure WatcherSys

```bash
cp .env.example .env
cp mysql-password.example mysql-password
cp pf-recovery.env.example pf-recovery.env
cp recovery-watcher/recovery-watcher.env.example recovery-watcher/recovery-watcher.env
chmod 600 .env mysql-password pf-recovery.env recovery-watcher/recovery-watcher.env
```

`.env`:

```dotenv
FLEET_DOCKER_NETWORK=fleetdm-lab_fleet-internal
MYSQL_CA_FILE=/absolute/path/to/mysql-ca.pem
PACKETFENCE_CA_FILE=/absolute/path/to/packetfence-lab-ca.crt
```

`mysql-password`:

```text
replace-with-fleet-mysql-password
```

`pf-recovery.env`:

```dotenv
PF_RECOVERY_USER=watcher-recovery
PF_RECOVERY_PASSWORD=replace-with-packetfence-api-password
```

Set in `compose.example.yaml`:

```yaml
POLICY_ID: "2"
PF_SECURITY_EVENT_ID: "3500001"
CVE_REGEX: "^CVE-2018-10115$"
PF_CVE_SECURITY_EVENT_ID: "3500002"
PF_BASE_URL: "https://172.16.1.3:9999"
PF_CA_FILE: /etc/ssl/packetfence/ca.crt
PF_TIMEZONE: "America/New_York"
STATE_FILE: /var/lib/fleet-recovery/state.json
POLL_SECONDS: "2"
```

## 6. Run

```bash
docker compose -f compose.example.yaml config
docker compose -f compose.example.yaml up -d --build
docker compose -f compose.example.yaml ps
docker compose -f compose.example.yaml logs --tail=50 recovery-watcher
```

## 7. Verify

```bash
docker compose -f compose.example.yaml exec recovery-watcher \
  python -c 'import os,pymysql; from app import mysql_ssl_options,read_env_or_file; c=pymysql.connect(host=os.environ["MYSQL_HOST"],port=int(os.environ.get("MYSQL_PORT","3306")),user=os.environ["MYSQL_USER"],password=read_env_or_file("MYSQL_PASSWORD"),database=os.environ["MYSQL_DATABASE"],ssl=mysql_ssl_options()); c.close(); print("mysql=connected")'

docker compose -f compose.example.yaml exec recovery-watcher \
  python -c 'from pathlib import Path; p=Path("/var/lib/fleet-recovery/state.json"); print(p.read_text() if p.exists() else "state=waiting-for-baseline")'

docker compose -f compose.example.yaml logs --since=10m recovery-watcher
```

## 8. Test

```bash
python3 -m unittest discover -s tests -t recovery-watcher -v
```

## 9. Restart

```bash
docker compose -f compose.example.yaml restart recovery-watcher
docker compose -f compose.example.yaml ps recovery-watcher
docker compose -f compose.example.yaml logs --tail=50 recovery-watcher
```

## 10. Stop

```bash
docker compose -f compose.example.yaml stop recovery-watcher
```
