import os

from fastapi import Header, HTTPException

# format: "admin-key:admin,analyst-key:analyst,agent-key:agent"
API_KEYS = os.getenv("API_KEYS", "admin-key:admin,analyst-key:analyst,agent-key:agent")
KEY_ROLE_MAP = dict(item.split(":", 1) for item in API_KEYS.split(",") if ":" in item)


def _mtls_required_for_agents() -> bool:
    return os.getenv("AGENT_MTLS_REQUIRED", "false").lower() in {"1", "true", "yes", "on"}


def _trusted_fingerprints() -> set[str]:
    raw = os.getenv("AGENT_MTLS_TRUSTED_FINGERPRINTS", "")
    return {fingerprint.strip().lower() for fingerprint in raw.split(",") if fingerprint.strip()}


def require_role(*roles: str):
    def dependency(
        x_api_key: str = Header(default=""),
        x_client_cert_presented: str = Header(default="", alias="X-Client-Cert-Presented"),
        x_client_cert_fingerprint: str = Header(default="", alias="X-Client-Cert-Fingerprint"),
    ) -> str:
        role = KEY_ROLE_MAP.get(x_api_key)
        if not role:
            raise HTTPException(status_code=401, detail="invalid api key")

        if role == "agent" and _mtls_required_for_agents():
            if x_client_cert_presented.lower() != "true" or not x_client_cert_fingerprint:
                raise HTTPException(status_code=401, detail="mTLS client certificate required")

            trusted = _trusted_fingerprints()
            if trusted and x_client_cert_fingerprint.lower() not in trusted:
                raise HTTPException(status_code=401, detail="untrusted mTLS certificate fingerprint")

        if roles and role not in roles:
            raise HTTPException(status_code=403, detail="insufficient role")
        return role

    return dependency
