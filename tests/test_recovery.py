import ssl
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from app import env_flag, mysql_ssl_options, read_env_or_file
from recovery import (
    FleetRepository,
    FleetVulnerabilityRepository,
    HttpJsonTransport,
    JsonStateStore,
    PacketFenceClient,
    RecoveryEngine,
)


class FakePacketFence:
    def __init__(self, failures=0):
        self.calls = []
        self.failures = failures

    def recover(self, mac, security_event_id):
        self.calls.append((mac, security_event_id))
        if self.failures:
            self.failures -= 1
            raise RuntimeError("PacketFence unavailable")


class AppConfigurationTests(unittest.TestCase):
    def test_reads_secret_from_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mysql-password"
            path.write_text("database-secret\n", encoding="utf-8")

            value = read_env_or_file(
                "MYSQL_PASSWORD", {"MYSQL_PASSWORD_FILE": str(path)}
            )

            self.assertEqual(value, "database-secret")

    def test_rejects_ambiguous_direct_and_file_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mysql-password"
            path.write_text("file-secret", encoding="utf-8")

            with self.assertRaises(ValueError):
                read_env_or_file(
                    "MYSQL_PASSWORD",
                    {
                        "MYSQL_PASSWORD": "environment-secret",
                        "MYSQL_PASSWORD_FILE": str(path),
                    },
                )

    def test_environment_flag_defaults_to_false(self):
        self.assertFalse(env_flag("PF_ALLOW_LEGACY_CA", {}))

    def test_environment_flag_accepts_true(self):
        self.assertTrue(env_flag("PF_ALLOW_LEGACY_CA", {"PF_ALLOW_LEGACY_CA": "true"}))

    def test_mysql_tls_uses_ca_and_hostname_verification(self):
        self.assertEqual(
            mysql_ssl_options({"MYSQL_SSL_CA": "/run/secrets/mysql-ca"}),
            {"ca": "/run/secrets/mysql-ca", "check_hostname": True},
        )

    def test_mysql_tls_is_absent_without_a_ca(self):
        self.assertIsNone(mysql_ssl_options({}))


class RecoveryEngineTests(unittest.TestCase):
    def test_fail_to_pass_recovers_packetfence_event(self):
        with tempfile.TemporaryDirectory() as directory:
            store = JsonStateStore(Path(directory) / "state.json")
            packetfence = FakePacketFence()
            engine = RecoveryEngine(store, packetfence, security_event_id="3500001")
            failing = {"host_id": 1, "policy_id": 2, "passes": False, "mac": "00:11:22:33:44:55"}
            passing = {**failing, "passes": True}

            engine.handle([failing])
            engine.handle([passing])

            self.assertEqual(packetfence.calls, [("00:11:22:33:44:55", "3500001")])

    def test_failed_recovery_is_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            store = JsonStateStore(Path(directory) / "state.json")
            packetfence = FakePacketFence(failures=1)
            engine = RecoveryEngine(store, packetfence, security_event_id="3500001")
            failing = {"host_id": 1, "policy_id": 2, "passes": False, "mac": "00:11:22:33:44:55"}
            passing = {**failing, "passes": True}
            engine.handle([failing])

            with self.assertRaises(RuntimeError):
                engine.handle([passing])
            engine.handle([passing])

            self.assertEqual(len(packetfence.calls), 2)


class HttpJsonTransportTests(unittest.TestCase):
    def test_rejects_non_https_base_url(self):
        with self.assertRaisesRegex(ValueError, "PF_BASE_URL must use HTTPS"):
            HttpJsonTransport("http://packetfence:9999", None)

    def test_keeps_strict_certificate_verification_by_default(self):
        transport = HttpJsonTransport("https://packetfence:9999", None)

        self.assertEqual(transport.context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(transport.context.check_hostname)
        self.assertTrue(transport.context.verify_flags & ssl.VERIFY_X509_STRICT)

    def test_legacy_ca_compatibility_is_explicit(self):
        transport = HttpJsonTransport(
            "https://packetfence:9999", None, allow_legacy_ca=True
        )

        self.assertFalse(transport.context.verify_flags & ssl.VERIFY_X509_STRICT)

    def test_sends_json_and_authorization_header(self):
        captured = {}

        class Response:
            status = 200

            def read(self):
                return b'{"status":200}'

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

        def opener(request, **kwargs):
            captured["request"] = request
            return Response()

        transport = HttpJsonTransport("https://packetfence:9999", None, opener=opener)
        status, body = transport("/close", "PUT", {"id": "3500001"}, "token-123")

        request = captured["request"]
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": 200})
        self.assertEqual(request.method, "PUT")
        self.assertEqual(request.headers["Authorization"], "token-123")
        self.assertEqual(request.data, b'{"id": "3500001"}')


class FleetRepositoryTests(unittest.TestCase):
    def test_rows_are_normalized_for_recovery_engine(self):
        class Cursor:
            def execute(self, query, parameters):
                self.query = query
                self.parameters = parameters

            def fetchall(self):
                return [{"host_id": 1, "policy_id": 2, "passes": 1, "mac": "AA:BB:CC:DD:EE:FF"}]

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

        class Connection:
            def cursor(self):
                return Cursor()

            def close(self):
                pass

        repository = FleetRepository(lambda: Connection(), policy_id=2)

        self.assertEqual(repository.rows(), [{
            "host_id": 1,
            "policy_id": 2,
            "passes": True,
            "mac": "aa:bb:cc:dd:ee:ff",
        }])


class FleetVulnerabilityRepositoryTests(unittest.TestCase):
    def test_rows_mark_only_hosts_with_matching_cves_as_failing(self):
        class Cursor:
            def execute(self, query):
                self.query = query

            def fetchall(self):
                return [
                    {"host_id": 1, "mac": "AA:BB:CC:DD:EE:FF", "cve": "CVE-2025-0411"},
                    {"host_id": 1, "mac": "AA:BB:CC:DD:EE:FF", "cve": "CVE-2024-9999"},
                    {"host_id": 2, "mac": "11:22:33:44:55:66", "cve": None},
                ]

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return None

        class Connection:
            def cursor(self):
                return Cursor()

            def close(self):
                pass

        repository = FleetVulnerabilityRepository(
            lambda: Connection(), cve_regex=r"^CVE-2025-0411$"
        )

        self.assertEqual(repository.rows(), [
            {
                "host_id": 1,
                "policy_id": "cve:^CVE-2025-0411$",
                "passes": False,
                "mac": "aa:bb:cc:dd:ee:ff",
            },
            {
                "host_id": 2,
                "policy_id": "cve:^CVE-2025-0411$",
                "passes": True,
                "mac": "11:22:33:44:55:66",
            },
        ])


class PacketFenceClientTests(unittest.TestCase):
    def test_recover_closes_matching_event_record_then_reevaluates_access(self):
        calls = []

        def transport(path, method="GET", payload=None, token=None):
            calls.append((path, method, payload, token))
            if path == "/api/v1/login":
                return 200, {"token": "token-123"}
            if path == "/api/v1/security_events/search":
                return 200, {"status": 200, "items": [
                    {
                        "id": 7,
                        "mac": "00:11:22:33:44:55",
                        "security_event_id": 3500001,
                        "status": "open",
                    }
                ]}
            return 200, {"status": 200}

        client = PacketFenceClient(transport, "recovery-user", "secret")
        client.recover("00:11:22:33:44:55", "3500001")

        self.assertEqual(calls[1][0:2], (
            "/api/v1/security_events/search",
            "POST",
        ))
        self.assertEqual(calls[1][2]["query"], {
            "op": "and",
            "values": [
                {"field": "mac", "op": "equals", "value": "00:11:22:33:44:55"},
                {"field": "security_event_id", "op": "equals", "value": "3500001"},
            ],
        })
        self.assertEqual(calls[2], (
            "/api/v1/node/00:11:22:33:44:55/close_security_event",
            "PUT",
            {"security_event_id": "7"},
            "token-123",
        ))
        self.assertEqual(calls[3], (
            "/api/v1/node/00:11:22:33:44:55/reevaluate_access",
            "PUT",
            None,
            "token-123",
        ))
    def test_retries_reevaluation_when_matching_event_is_already_closed(self):
        calls = []

        def transport(path, method="GET", payload=None, token=None):
            calls.append((path, method, payload, token))
            if path == "/api/v1/login":
                return 200, {"token": "token-123"}
            if path == "/api/v1/security_events/search":
                return 200, {"status": 200, "items": [
                    {
                        "id": 7,
                        "mac": "00:11:22:33:44:55",
                        "security_event_id": 3500001,
                        "status": "closed",
                        "release_date": "2026-09-14 12:00:00",
                    }
                ]}
            return 200, {"status": 200}

        client = PacketFenceClient(
            transport,
            "recovery-user",
            "secret",
            now=lambda: datetime(2026, 9, 14, 12, 30, tzinfo=timezone.utc),
        )
        client.recover("00:11:22:33:44:55", "3500001")

        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[2], (
            "/api/v1/node/00:11:22:33:44:55/reevaluate_access",
            "PUT",
            None,
            "token-123",
        ))

    def test_interprets_naive_release_date_in_packetfence_timezone(self):
        calls = []

        def transport(path, method="GET", payload=None, token=None):
            calls.append((path, method, payload, token))
            if path == "/api/v1/login":
                return 200, {"token": "token-123"}
            if path == "/api/v1/security_events/search":
                return 200, {"status": 200, "items": [
                    {
                        "id": 7,
                        "mac": "00:11:22:33:44:55",
                        "security_event_id": 3500001,
                        "status": "closed",
                        "release_date": "2026-09-14 08:00:00",
                    }
                ]}
            return 200, {"status": 200}

        client = PacketFenceClient(
            transport,
            "recovery-user",
            "secret",
            server_timezone=ZoneInfo("America/New_York"),
            now=lambda: datetime(2026, 9, 14, 12, 30, tzinfo=timezone.utc),
        )
        client.recover("00:11:22:33:44:55", "3500001")

        self.assertEqual(len(calls), 3)
        self.assertEqual(
            calls[2][0],
            "/api/v1/node/00:11:22:33:44:55/reevaluate_access",
        )

    def test_ignores_stale_closed_event(self):
        def transport(path, method="GET", payload=None, token=None):
            if path == "/api/v1/login":
                return 200, {"token": "token-123"}
            if path == "/api/v1/security_events/search":
                return 200, {"status": 200, "items": [
                    {
                        "id": 7,
                        "mac": "00:11:22:33:44:55",
                        "security_event_id": 3500001,
                        "status": "closed",
                        "release_date": "2026-09-14 10:00:00",
                    }
                ]}
            return 200, {"status": 200}

        client = PacketFenceClient(
            transport,
            "recovery-user",
            "secret",
            now=lambda: datetime(2026, 9, 14, 12, 30, tzinfo=timezone.utc),
        )

        with self.assertRaises(RuntimeError):
            client.recover("00:11:22:33:44:55", "3500001")


if __name__ == "__main__":
    unittest.main()
