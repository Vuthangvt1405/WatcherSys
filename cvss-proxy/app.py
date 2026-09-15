import logging
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from fastapi import FastAPI, HTTPException, Request
from requests.auth import HTTPBasicAuth

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("fleet-cvss-proxy")

DEFAULT_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_CACHE_TTL_SECONDS = 24 * 60 * 60
DEFAULT_PACKETFENCE_CREDENTIAL_FILE = "/run/secrets/pf-recovery-env"
USER_AGENT = "fleet-packetfence-cvss-proxy/1.0"


def required_env(name: str) -> str:
    if name not in os.environ or os.environ[name] == "":
        raise RuntimeError(f"Missing required environment variable: {name}")
    return os.environ[name]


def optional_env(name: str, default: str) -> str:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def env_bool(name: str, default: bool = False) -> bool:
    if name not in os.environ or os.environ[name] == "":
        return default

    normalized = os.environ[name].strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Invalid boolean value for {name}: {os.environ[name]}")


@dataclass
class Settings:
    nvd_api_url: str
    cache_ttl_seconds: int
    packetfence_url: str
    packetfence_user: str
    packetfence_password: str
    packetfence_ca_file: str
    packetfence_verify_tls: bool
    packetfence_credential_file: str

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            # Optional settings use defaults.
            nvd_api_url=optional_env("NVD_API_URL", DEFAULT_NVD_API_URL),
            cache_ttl_seconds=int(optional_env("CACHE_TTL_SECONDS", str(DEFAULT_CACHE_TTL_SECONDS))),
            packetfence_verify_tls=env_bool("PACKETFENCE_VERIFY_TLS", default=False),
            packetfence_ca_file=optional_env("PACKETFENCE_CA_FILE", ""),
            packetfence_credential_file=optional_env("PF_CREDENTIAL_FILE", DEFAULT_PACKETFENCE_CREDENTIAL_FILE),
            packetfence_user=optional_env("PACKETFENCE_USER", ""),
            packetfence_password=optional_env("PACKETFENCE_PASSWORD", ""),
            # Required settings must be explicit in the environment.
            packetfence_url=required_env("PACKETFENCE_URL"),
        )


settings = Settings.from_env()
# CVE -> {"score": float | None, "expires": float}
cache: dict[str, dict[str, Any]] = {}


def read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}

    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def load_packetfence_credentials() -> None:
    """Load PacketFence credentials from env or the shared recovery secret file."""
    values = read_env_file(Path(settings.packetfence_credential_file))
    settings.packetfence_user = (
        settings.packetfence_user
        or values.get("PACKETFENCE_USER")
        or values.get("PF_RECOVERY_USER")
        or ""
    )
    settings.packetfence_password = (
        settings.packetfence_password
        or values.get("PACKETFENCE_PASSWORD")
        or values.get("PF_RECOVERY_PASSWORD")
        or ""
    )


def packetfence_verify_value() -> bool | str:
    if not settings.packetfence_verify_tls:
        return False
    return settings.packetfence_ca_file or True


def select_metric(metrics: dict[str, Any], name: str) -> float | None:
    entries = metrics.get(name, [])
    if not entries:
        return None

    for source in ("nvd@nist.gov", None):
        for entry in entries:
            if source is not None and entry.get("source") != source:
                continue
            score = entry.get("cvssData", {}).get("baseScore")
            if score is not None:
                return float(score)
    return None


def extract_cvss_score(nvd_response: dict[str, Any]) -> float | None:
    vulnerabilities = nvd_response.get("vulnerabilities", [])
    if not vulnerabilities:
        return None

    metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})
    score = select_metric(metrics, "cvssMetricV31")
    if score is not None:
        return score
    return select_metric(metrics, "cvssMetricV30")


def get_nvd_cvss(cve_id: str) -> float | None:
    now = time.time()
    cached = cache.get(cve_id)
    if cached and cached["expires"] > now:
        return cached["score"]

    response = requests.get(
        settings.nvd_api_url,
        params={"cveId": cve_id},
        headers={"User-Agent": USER_AGENT},
        timeout=20,
    )
    response.raise_for_status()

    score = extract_cvss_score(response.json())
    cache[cve_id] = {"score": score, "expires": now + settings.cache_ttl_seconds}
    return score


def enrich_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], str, float]:
    vulnerability = payload.get("vulnerability")
    if not isinstance(vulnerability, dict):
        raise HTTPException(status_code=400, detail="Missing vulnerability object")

    cve_id = vulnerability.get("cve")
    if not cve_id:
        raise HTTPException(status_code=400, detail="Missing vulnerability.cve")

    try:
        score = get_nvd_cvss(cve_id)
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"NVD lookup failed: {exc}") from exc

    if score is None:
        raise HTTPException(status_code=422, detail=f"No CVSS v3.x score found for {cve_id}")

    vulnerability["cvss_score"] = score
    return payload, cve_id, score


def forward_to_packetfence(payload: dict[str, Any]) -> int:
    if not settings.packetfence_user or not settings.packetfence_password:
        raise HTTPException(status_code=500, detail="PacketFence credentials are not configured")

    try:
        response = requests.post(
            settings.packetfence_url,
            json=payload,
            auth=HTTPBasicAuth(settings.packetfence_user, settings.packetfence_password),
            verify=packetfence_verify_value(),
            timeout=20,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"PacketFence request failed: {exc}") from exc

    if not 200 <= response.status_code < 300:
        detail = f"PacketFence returned {response.status_code}: {response.text}"
        raise HTTPException(status_code=502, detail=detail)

    return response.status_code


@asynccontextmanager
async def lifespan(_: FastAPI):
    load_packetfence_credentials()
    logger.info(
        "Fleet CVSS proxy started; PacketFence URL=%s user=%s verify=%s",
        settings.packetfence_url,
        settings.packetfence_user or "<unset>",
        packetfence_verify_value(),
    )
    yield


app = FastAPI(title="Fleet CVSS Proxy", lifespan=lifespan)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/lookup/{cve_id}")
def lookup(cve_id: str):
    try:
        score = get_nvd_cvss(cve_id)
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"NVD lookup failed: {exc}") from exc

    if score is None:
        raise HTTPException(status_code=422, detail=f"No CVSS v3.x score found for {cve_id}")
    return {"cve": cve_id, "cvss_score": score}


@app.post("/fleet-cve")
async def fleet_cve(request: Request):
    payload, cve_id, score = enrich_payload(await request.json())
    packetfence_status = forward_to_packetfence(payload)

    logger.info("Forwarded %s CVSS=%s to PacketFence status=%s", cve_id, score, packetfence_status)
    return {
        "status": "forwarded",
        "cve": cve_id,
        "cvss_score": score,
        "packetfence_status": packetfence_status,
    }


@app.post("/debug/enrich-only")
async def debug_enrich_only(request: Request):
    payload, cve_id, score = enrich_payload(await request.json())
    return {"status": "enriched", "cve": cve_id, "cvss_score": score, "payload": payload}
