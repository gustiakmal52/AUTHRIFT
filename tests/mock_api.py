"""
Intentionally vulnerable mock API for AUTHRIFT testing.

Endpoints:
- /api/secure/orders/{id}            — verifies token matches order owner
- /api/vulnerable/orders/{id}        — only verifies authentication, not ownership (BOLA)
- /api/profile                       — returns identity profile for authenticated actor (proper isolation)
- /api/leaky/profile                 — returns Alice's profile to everyone (session data leak)
- /api/orders (POST)                 — ordinary write endpoint available to ordinary users
- /api/admin/users (POST)            — verifies user is admin (Secure BFLA)
- /api/vulnerable/admin/users (POST) — only verifies authentication, not role (Vulnerable BFLA)
- /api/health                        — global static public endpoint

Supports both Bearer authorization header and session cookie.
"""
from fastapi import FastAPI, Header, Cookie, HTTPException
from typing import Optional

app = FastAPI(title="AUTHRIFT Test Target")

ORDERS = {
    "1001": {
        "id": "1001",
        "owner_id": "user_a",
        "customer_email": "alice@example.com",
        "address": "123 Main St",
        "total": 299.99,
        "items": ["Widget A", "Widget B"],
    },
    "2001": {
        "id": "2001",
        "owner_id": "user_b",
        "customer_email": "bob@example.com",
        "address": "456 Oak Ave",
        "total": 149.50,
        "items": ["Gadget C"],
    },
}

TOKENS = {
    "TOKEN_A": "user_a",
    "TOKEN_B": "user_b",
    "ADMIN_TOKEN": "admin",
    "cookie_session_a": "user_a",
    "cookie_session_b": "user_b",
}


def _authenticate(
    authorization: Optional[str] = None,
    session: Optional[str] = None,
) -> str:
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
    elif session:
        token = session.strip()

    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")

    user = TOKENS.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


@app.get("/api/secure/orders/{order_id}")
def get_secure_order(
    order_id: str,
    authorization: Optional[str] = Header(None),
    session: Optional[str] = Cookie(None),
):
    user = _authenticate(authorization, session)
    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if order["owner_id"] != user and user != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    return order


@app.get("/api/vulnerable/orders/{order_id}")
def get_vulnerable_order(
    order_id: str,
    authorization: Optional[str] = Header(None),
    session: Optional[str] = Cookie(None),
):
    _authenticate(authorization, session)
    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return order


@app.get("/api/profile")
def get_profile(
    authorization: Optional[str] = Header(None),
    session: Optional[str] = Cookie(None),
):
    user = _authenticate(authorization, session)
    profiles = {
        "user_a": {"username": "alice", "email": "alice@example.com", "role": "user"},
        "user_b": {"username": "bob", "email": "bob@example.com", "role": "user"},
        "admin": {"username": "admin", "email": "admin@example.com", "role": "admin"},
    }
    return profiles.get(user, {"username": user, "role": "user"})


@app.get("/api/leaky/profile")
def get_leaky_profile(
    authorization: Optional[str] = Header(None),
    session: Optional[str] = Cookie(None),
):
    _authenticate(authorization, session)
    return {"username": "alice", "email": "alice@example.com", "role": "user"}


@app.post("/api/orders")
def create_order(
    authorization: Optional[str] = Header(None),
    session: Optional[str] = Cookie(None),
):
    user = _authenticate(authorization, session)
    return {"status": "created", "order_id": "new_order_555", "created_by": user}


@app.post("/api/admin/users")
def secure_admin_create_user(
    authorization: Optional[str] = Header(None),
    session: Optional[str] = Cookie(None),
):
    user = _authenticate(authorization, session)
    if user != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return {"status": "created", "user_id": "new_user_999", "created_by": "admin"}


@app.post("/api/vulnerable/admin/users")
def vulnerable_admin_create_user(
    authorization: Optional[str] = Header(None),
    session: Optional[str] = Cookie(None),
):
    user = _authenticate(authorization, session)
    return {"status": "created", "user_id": "new_user_999", "created_by": user}


@app.get("/api/health")
def get_health():
    return {"status": "ok", "version": "1.0.0"}
