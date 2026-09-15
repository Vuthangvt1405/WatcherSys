import logging
import os
import time
from pathlib import Path

import requests
from fastapi import FastAPI, HTTPException, Request
from requests.auth import HTTPBasicAuth

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("fleet-cvss-proxy")

app = FastAPI(title="Fleet CVSS Proxy")

NVD_API_URL = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
CACHE_TTL = int(os.getenv("CACHE_TTL_SECONDS", str(24 * 60 * 60)))

PACKETFENCE_URL = os.getenv(
    "PACKETFENCE_URL",
    "https://172.16.1.3:9999/api/v1/fleetdm-events/cve",
)
PACKETFENCE_USER = os.getenv("PACKETFENCE_USER", "")
PACKETFENCE_PASSWORD = os.getenv("PACKETFENCE_PASSWORD", "")
PACKETFENCE_CA_FILE = os.getenv("PACKETFENCE_CA_FILE", "")
PACKETFENCE_VERIFY_TLS = os.getenv("PACKETFENCE_VERIFY_TLS", "false").lower() == "true"

# CVE -> {score, expires}
cache = {}


def load_packetfence_secret():
    """Allow reuse of the lab's .pf-recovery.env Docker secret."""
    global PACKETFENCE_USER, PACKETFENCE_PASSWORD

    secret_path = os.getenv("PF_CREDENTIAL_FILE", "/run/secrets/pf-recovery-env")
    path = Path(secret_path)
    if not path.exists():
        return

    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value

    PACKETFENCE_USER = PACKETFENCE_USER or values.get("PACKETFENCE_USER") or values.get("PF_RECOVERY_USER", "")
    PACKETFENCE_PASSWORD = PACKETFENCE_PASSWORD or values.get("PACKETFENCE_PASSWORD") or values.get("PF_RECOVERY_PASSWORD", "")


def packetfence_verify_value():
    if not PACKETFENCE_VERIFY_TLS:
        return False
    if PACKETFENCE_CA_FILE:
        return PACKETFENCE_CA_FILE
    return True


def select_metric(metrics, name):
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


def get_nvd_cvss(cve_id):
    now = time.time()
    cached = cache.get(cve_id)
    if cached and cached["expires"] > now:
        return cached["score"]

    headers = {"User-Agent": "fleet-packetfence-cvss-proxy/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=headers,
        timeout=20,
    )
    response.raise_for_status()

    vulnerabilities = response.json().get("vulnerabilities", [])
    if not vulnerabilities:
        return None

    metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})
    score = select_metric(metrics, "cvssMetricV31")
    if score is None:
        score = select_metric(metrics, "cvssMetricV30")

    cache[cve_id] = {"score": score, "expires": now + CACHE_TTL}
    return score


def enriched_payload(payload):
    vulnerability = payload.get("vulnerability")
    if not isinstance(vulnerability, dict):
        raise HTTPException(status_code=400, detail="Missing vulnerability object")

    cve_id = vulnerability.get("cve")
    if not cve_id:
        raise HTTPException(status_code=400, detail="Missing vulnerability.cve")

    try:
        score = get_nvd_cvss(cve_id)
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"NVD lookup failed: {exc}")

    if score is None:
        raise HTTPException(status_code=422, detail=f"No CVSS v3.x score found for {cve_id}")

    payload["vulnerability"]["cvss_score"] = score
    return payload, cve_id, score


@app.on_event("startup")
def startup():
    load_packetfence_secret()
    logger.info("Fleet CVSS proxy started; PacketFence URL=%s user=%s verify=%s", PACKETFENCE_URL, PACKETFENCE_USER or "<unset>", packetfence_verify_value())


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/lookup/{cve_id}")
def lookup(cve_id: str):
    try:
        score = get_nvd_cvss(cve_id)
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"NVD lookup failed: {exc}")
    if score is None:
        raise HTTPException(status_code=422, detail=f"No CVSS v3.x score found for {cve_id}")
    return {"cve": cve_id, "cvss_score": score}


@app.post("/fleet-cve")
async def fleet_cve(request: Request):
    payload = await request.json()
    payload, cve_id, score = enriched_payload(payload)

    if not PACKETFENCE_USER or not PACKETFENCE_PASSWORD:
        raise HTTPException(status_code=500, detail="PacketFence credentials are not configured")

    try:
        pf_response = requests.post(
            PACKETFENCE_URL,
            json=payload,
            auth=HTTPBasicAuth(PACKETFENCE_USER, PACKETFENCE_PASSWORD),
            verify=packetfence_verify_value(),
            timeout=20,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"PacketFence request failed: {exc}")

    if not 200 <= pf_response.status_code < 300:
        raise HTTPException(status_code=502, detail=f"PacketFence returned {pf_response.status_code}: {pf_response.text}")

    logger.info("Forwarded %s CVSS=%s to PacketFence status=%s", cve_id, score, pf_response.status_code)
    return {"status": "forwarded", "cve": cve_id, "cvss_score": score, "packetfence_status": pf_response.status_code}


@app.post("/debug/enrich-only")
async def debug_enrich_only(request: Request):
    payload = await request.json()
    payload, cve_id, score = enriched_payload(payload)
    return {"status": "enriched", "cve": cve_id, "cvss_score": score, "payload": payload}
