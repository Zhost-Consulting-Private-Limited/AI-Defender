import os
from fastapi import Header, HTTPException

# format: "admin-key:admin,analyst-key:analyst,agent-key:agent"
API_KEYS = os.getenv("API_KEYS", "admin-key:admin,analyst-key:analyst,agent-key:agent")
KEY_ROLE_MAP = dict(item.split(":", 1) for item in API_KEYS.split(",") if ":" in item)


def require_role(*roles: str):
    def dependency(x_api_key: str = Header(default="")) -> str:
        role = KEY_ROLE_MAP.get(x_api_key)
        if not role:
            raise HTTPException(status_code=401, detail="invalid api key")
        if roles and role not in roles:
            raise HTTPException(status_code=403, detail="insufficient role")
        return role

    return dependency
