import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


class HttpJsonTransport:
    def __init__(
        self,
        base_url,
        ca_file,
        opener=urllib.request.urlopen,
        timeout=10,
        allow_legacy_ca=False,
    ):
        if urllib.parse.urlparse(base_url).scheme != "https":
            raise ValueError("PF_BASE_URL must use HTTPS")
        self.base_url = base_url.rstrip("/")
        self.opener = opener
        self.timeout = timeout
        self.context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        if allow_legacy_ca:
            # Compatibility mode for older lab CAs with invalid keyUsage.
            # Chain and hostname verification remain enabled.
            self.context.verify_flags &= ~ssl.VERIFY_X509_STRICT

    def __call__(self, path, method="GET", payload=None, token=None):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = token
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with self.opener(request, context=self.context, timeout=self.timeout) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as error:
            raw = error.read()
            return error.code, json.loads(raw) if raw else {}


class FleetRepository:
    def __init__(self, connection_factory, policy_id):
        self.connection_factory = connection_factory
        self.policy_id = policy_id

    def rows(self):
        connection = self.connection_factory()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT h.id AS host_id, p.id AS policy_id,
                           pm.passes, h.primary_mac AS mac
                    FROM policy_membership pm
                    JOIN hosts h ON h.id = pm.host_id
                    JOIN policies p ON p.id = pm.policy_id
                    WHERE h.platform = 'windows'
                      AND p.id = %s
                      AND pm.passes IS NOT NULL
                      AND h.primary_mac <> ''
                    """,
                    (self.policy_id,),
                )
                return [
                    {
                        "host_id": row["host_id"],
                        "policy_id": row["policy_id"],
                        "passes": bool(row["passes"]),
                        "mac": row["mac"].lower(),
                    }
                    for row in cursor.fetchall()
                ]
        finally:
            connection.close()


class FleetVulnerabilityRepository:
    def __init__(self, connection_factory, cve_regex):
        self.connection_factory = connection_factory
        self.cve_regex = cve_regex
        self.matcher = re.compile(cve_regex)

    def rows(self):
        connection = self.connection_factory()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT h.id AS host_id, h.primary_mac AS mac, NULL AS cve
                    FROM hosts h
                    WHERE h.platform = 'windows' AND h.primary_mac <> ''
                    UNION ALL
                    SELECT h.id, h.primary_mac, sc.cve
                    FROM hosts h
                    JOIN host_software hs ON hs.host_id = h.id
                    JOIN software_cve sc ON sc.software_id = hs.software_id
                    WHERE h.platform = 'windows' AND h.primary_mac <> ''
                    UNION ALL
                    SELECT h.id, h.primary_mac, osv.cve
                    FROM hosts h
                    JOIN host_operating_system hos ON hos.host_id = h.id
                    JOIN operating_system_vulnerabilities osv
                      ON osv.operating_system_id = hos.os_id
                    WHERE h.platform = 'windows' AND h.primary_mac <> ''
                    UNION ALL
                    SELECT h.id, h.primary_mac, osvv.cve
                    FROM hosts h
                    JOIN host_operating_system hos ON hos.host_id = h.id
                    JOIN operating_systems os ON os.id = hos.os_id
                    JOIN operating_system_version_vulnerabilities osvv
                      ON osvv.os_version_id = os.os_version_id
                    WHERE h.platform = 'windows' AND h.primary_mac <> ''
                    """
                )
                hosts = {}
                for row in cursor.fetchall():
                    host = hosts.setdefault(
                        row["host_id"],
                        {
                            "host_id": row["host_id"],
                            "policy_id": f"cve:{self.cve_regex}",
                            "passes": True,
                            "mac": row["mac"].lower(),
                        },
                    )
                    if row["cve"] and self.matcher.search(row["cve"]):
                        host["passes"] = False
                return [hosts[host_id] for host_id in sorted(hosts)]
        finally:
            connection.close()


class PacketFenceClient:
    def __init__(
        self,
        transport,
        username,
        password,
        closed_event_lookback_seconds=3600,
        now=lambda: datetime.now(timezone.utc),
        server_timezone=None,
    ):
        self.transport = transport
        self.username = username
        self.password = password
        self.closed_event_lookback_seconds = closed_event_lookback_seconds
        self.now = now
        self.server_timezone = server_timezone

    def recover(self, mac, security_event_id):
        status, body = self.transport(
            "/api/v1/login",
            "POST",
            {"username": self.username, "password": self.password},
        )
        if status != 200 or not body.get("token"):
            raise RuntimeError(f"PacketFence login failed with HTTP {status}")
        token = body["token"]
        event_id, is_open = self._find_matching_event(mac, security_event_id, token)
        node_id = urllib.parse.quote(mac, safe=":")
        if is_open:
            self._put(
                f"/api/v1/node/{node_id}/close_security_event",
                {"security_event_id": str(event_id)},
                token,
            )
        self._put(f"/api/v1/node/{node_id}/reevaluate_access", None, token)

    def _find_matching_event(self, mac, security_event_id, token):
        status, body = self.transport(
            "/api/v1/security_events/search",
            "POST",
            {
                "fields": [
                    "id",
                    "status",
                    "mac",
                    "security_event_id",
                    "release_date",
                ],
                "limit": 100,
                "cursor": 0,
                "query": {
                    "op": "and",
                    "values": [
                        {"field": "mac", "op": "equals", "value": mac},
                        {
                            "field": "security_event_id",
                            "op": "equals",
                            "value": str(security_event_id),
                        },
                    ],
                },
                "sort": ["id DESC"],
            },
            token,
        )
        if status != 200 or body.get("status", 200) not in (200, "200"):
            raise RuntimeError(f"PacketFence security-event search failed with HTTP {status}")
        closed_event_id = None
        for event in body.get("items", []):
            if (
                str(event.get("mac", "")).lower() == mac.lower()
                and str(event.get("security_event_id")) == str(security_event_id)
            ):
                if event.get("status") == "open":
                    return event["id"], True
                if (
                    event.get("status") == "closed"
                    and closed_event_id is None
                    and self._is_recently_closed(event)
                ):
                    closed_event_id = event["id"]
        if closed_event_id is not None:
            return closed_event_id, False
        raise RuntimeError(
            f"No PacketFence event {security_event_id} found for MAC {mac}"
        )

    def _is_recently_closed(self, event):
        value = event.get("release_date")
        if not value or value == "0000-00-00 00:00:00":
            return False
        try:
            released_at = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return False
        if self.server_timezone is not None:
            released_at = released_at.replace(tzinfo=self.server_timezone)
        else:
            released_at = released_at.replace(tzinfo=timezone.utc)
        age = (self.now() - released_at).total_seconds()
        return 0 <= age <= self.closed_event_lookback_seconds

    def _put(self, path, payload, token):
        status, body = self.transport(path, "PUT", payload, token)
        if status != 200 or body.get("status", 200) not in (200, "200"):
            raise RuntimeError(f"PacketFence request failed: {path}, HTTP {status}")


class JsonStateStore:
    def __init__(self, path: Path):
        self.path = Path(path)

    def load(self):
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def save(self, state):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
        temporary.replace(self.path)


class RecoveryEngine:
    def __init__(self, store, packetfence, security_event_id):
        self.store = store
        self.packetfence = packetfence
        self.security_event_id = security_event_id

    def handle(self, rows):
        state = self.store.load()
        for row in rows:
            key = f"{row['host_id']}:{row['policy_id']}"
            previous = state.get(key)
            current = bool(row["passes"])
            if previous is False and current is True:
                self.packetfence.recover(row["mac"], self.security_event_id)
            state[key] = current
        self.store.save(state)
