import logging
import os
import time
from pathlib import Path

import pymysql

from recovery import (
    FleetRepository,
    FleetVulnerabilityRepository,
    HttpJsonTransport,
    JsonStateStore,
    PacketFenceClient,
    RecoveryEngine,
)


def read_secret(path):
    values = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


def read_env_or_file(name, environ=os.environ):
    direct = environ.get(name)
    file_path = environ.get(f"{name}_FILE")
    if direct is not None and file_path is not None:
        raise ValueError(f"Set only one of {name} or {name}_FILE")
    if file_path is not None:
        return Path(file_path).read_text(encoding="utf-8").rstrip("\r\n")
    if direct is not None:
        return direct
    raise KeyError(name)


def env_flag(name, environ=os.environ):
    value = environ.get(name, "false").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Invalid boolean value for {name}: {value}")


def mysql_ssl_options(environ=os.environ):
    ca_file = environ.get("MYSQL_SSL_CA")
    if not ca_file:
        return None
    return {"ca": ca_file, "check_hostname": True}


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    credentials = read_secret(os.environ.get("PF_CREDENTIAL_FILE", "/run/secrets/pf-recovery-env"))
    policy_id = int(os.environ.get("POLICY_ID", "2"))
    security_event_id = os.environ.get("PF_SECURITY_EVENT_ID", "3500001")
    cve_regex = os.environ.get("CVE_REGEX", ".*")
    cve_security_event_id = os.environ.get("PF_CVE_SECURITY_EVENT_ID", "3500002")

    def connect():
        return pymysql.connect(
            host=os.environ.get("MYSQL_HOST", "mysql"),
            port=int(os.environ.get("MYSQL_PORT", "3306")),
            user=os.environ.get("MYSQL_USER", "fleet"),
            password=read_env_or_file("MYSQL_PASSWORD"),
            database=os.environ.get("MYSQL_DATABASE", "fleet"),
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=10,
            ssl=mysql_ssl_options(),
        )

    repository = FleetRepository(connect, policy_id)
    vulnerability_repository = FleetVulnerabilityRepository(connect, cve_regex)
    transport = HttpJsonTransport(
        os.environ.get("PF_BASE_URL", "https://172.16.1.3:9999"),
        os.environ.get("PF_CA_FILE", "/etc/ssl/packetfence/ca.crt"),
        allow_legacy_ca=env_flag("PF_ALLOW_LEGACY_CA"),
    )
    from zoneinfo import ZoneInfo

    server_timezone = os.environ.get("PF_TIMEZONE")
    packetfence = PacketFenceClient(
        transport,
        credentials["PF_RECOVERY_USER"],
        credentials["PF_RECOVERY_PASSWORD"],
        server_timezone=ZoneInfo(server_timezone) if server_timezone else None,
    )
    store = JsonStateStore(Path(os.environ.get("STATE_FILE", "/var/lib/fleet-recovery/state.json")))
    engine = RecoveryEngine(store, packetfence, security_event_id)
    vulnerability_engine = RecoveryEngine(store, packetfence, cve_security_event_id)
    poll_seconds = float(os.environ.get("POLL_SECONDS", "2"))
    logging.info(
        "Fleet recovery watcher started for policy_id=%s and CVE regex=%s",
        policy_id,
        cve_regex,
    )

    while True:
        try:
            checks = (
                (repository, engine, security_event_id, "policy"),
                (vulnerability_repository, vulnerability_engine, cve_security_event_id, "CVE"),
            )
            for current_repository, current_engine, event_id, source in checks:
                rows = current_repository.rows()
                before = store.load()
                current_engine.handle(rows)
                after = store.load()
                for row in rows:
                    key = f"{row['host_id']}:{row['policy_id']}"
                    if before.get(key) is False and after.get(key) is True:
                        logging.info(
                            "Recovered PacketFence event %s for host_id=%s mac=%s source=%s",
                            event_id,
                            row["host_id"],
                            row["mac"],
                            source,
                        )
        except Exception:
            logging.exception("Recovery polling cycle failed; it will be retried")
        time.sleep(poll_seconds)


if __name__ == "__main__":
    main()
