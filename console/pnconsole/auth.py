"""User accounts via Supabase Auth (GoTrue), plus an in-memory stand-in for tests.

The console never stores passwords: sign-up and login are forwarded to
Supabase, which returns short-lived access tokens and refresh tokens.
"""
from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass

import httpx


class AuthError(Exception):
    def __init__(self, message: str, status: int = 401):
        super().__init__(message)
        self.status = status


@dataclass
class User:
    id: str
    email: str


class SupabaseAuth:
    def __init__(self, url: str, anon_key: str, client: httpx.Client | None = None):
        self.base = url.rstrip("/") + "/auth/v1"
        self.http = client or httpx.Client(timeout=10, headers={"apikey": anon_key})
        self._cache: dict[str, tuple[float, User]] = {}

    def _post(self, path: str, body: dict, params: dict | None = None) -> dict:
        r = self.http.post(self.base + path, json=body, params=params)
        data = r.json() if r.content else {}
        if r.status_code >= 400:
            msg = data.get("msg") or data.get("error_description") or data.get("message") or "request failed"
            raise AuthError(str(msg), 400 if r.status_code < 500 else 502)
        return data

    @staticmethod
    def _session(d: dict) -> dict:
        return {"access_token": d.get("access_token"), "refresh_token": d.get("refresh_token"),
                "expires_in": d.get("expires_in"), "email": (d.get("user") or {}).get("email")}

    def signup(self, email: str, password: str) -> dict:
        d = self._post("/signup", {"email": email, "password": password})
        if not d.get("access_token"):
            return {"confirm_email": True, "email": email}
        return self._session(d)

    def login(self, email: str, password: str) -> dict:
        try:
            return self._session(self._post("/token", {"email": email, "password": password},
                                            {"grant_type": "password"}))
        except AuthError as e:
            raise AuthError("invalid email or password" if e.status == 400 else str(e), e.status) from None

    def refresh(self, refresh_token: str) -> dict:
        return self._session(self._post("/token", {"refresh_token": refresh_token},
                                        {"grant_type": "refresh_token"}))

    def user(self, access_token: str) -> User:
        key = hashlib.sha256(access_token.encode()).hexdigest()
        hit = self._cache.get(key)
        if hit and hit[0] > time.time():
            return hit[1]
        r = self.http.get(self.base + "/user", headers={"Authorization": f"Bearer {access_token}"})
        if r.status_code != 200:
            raise AuthError("session expired — run 'login' again")
        d = r.json()
        u = User(d["id"], d.get("email", ""))
        self._cache[key] = (time.time() + 60, u)
        if len(self._cache) > 5000:
            self._cache.clear()
        return u


class FirebaseAuth:
    """Firebase Authentication (email/password) via the Identity Toolkit REST API.

    Uses the project's Web API key, which is public by design; what protects
    accounts is Firebase Auth itself. ID tokens are verified with
    accounts:lookup and cached for 60 s.
    """

    ID = "https://identitytoolkit.googleapis.com/v1"
    SECURE = "https://securetoken.googleapis.com/v1/token"
    MESSAGES = {
        "EMAIL_EXISTS": "an account with that email already exists — run 'login'",
        "INVALID_LOGIN_CREDENTIALS": "invalid email or password",
        "EMAIL_NOT_FOUND": "invalid email or password",
        "INVALID_PASSWORD": "invalid email or password",
        "USER_DISABLED": "this account is disabled",
        "TOO_MANY_ATTEMPTS_TRY_LATER": "too many attempts — wait a few minutes and try again",
        "INVALID_EMAIL": "enter a valid email address",
        "OPERATION_NOT_ALLOWED": "email/password sign-in is not enabled for this console",
        "TOKEN_EXPIRED": "session expired — run 'login' again",
        "INVALID_REFRESH_TOKEN": "session expired — run 'login' again",
        "INVALID_ID_TOKEN": "session expired — run 'login' again",
    }

    def __init__(self, api_key: str, client: httpx.Client | None = None):
        self.key = api_key
        self.http = client or httpx.Client(timeout=10)
        self._cache: dict[str, tuple[float, User]] = {}

    def _call(self, url: str, **kw) -> dict:
        r = self.http.post(url, params={"key": self.key}, **kw)
        data = r.json() if r.content else {}
        if r.status_code >= 400:
            code = str((data.get("error") or {}).get("message", "request failed"))
            base = code.split(" ")[0].split(":")[0]
            if base == "WEAK_PASSWORD":
                raise AuthError("password must be at least 8 characters", 400)
            raise AuthError(self.MESSAGES.get(base, code.lower().replace("_", " ")),
                            401 if "TOKEN" in base else 400 if r.status_code < 500 else 502)
        return data

    @staticmethod
    def _session(d: dict, email: str | None = None) -> dict:
        return {"access_token": d.get("idToken") or d.get("id_token"),
                "refresh_token": d.get("refreshToken") or d.get("refresh_token"),
                "expires_in": int(d.get("expiresIn") or d.get("expires_in") or 3600),
                "email": d.get("email") or email}

    def signup(self, email: str, password: str) -> dict:
        if len(password) < 8:
            raise AuthError("password must be at least 8 characters", 400)
        return self._session(self._call(f"{self.ID}/accounts:signUp",
                                        json={"email": email, "password": password, "returnSecureToken": True}))

    def login(self, email: str, password: str) -> dict:
        return self._session(self._call(f"{self.ID}/accounts:signInWithPassword",
                                        json={"email": email, "password": password, "returnSecureToken": True}))

    def refresh(self, refresh_token: str) -> dict:
        return self._session(self._call(self.SECURE, data={"grant_type": "refresh_token",
                                                           "refresh_token": refresh_token}))

    def user(self, access_token: str) -> User:
        key = hashlib.sha256(access_token.encode()).hexdigest()
        hit = self._cache.get(key)
        if hit and hit[0] > time.time():
            return hit[1]
        try:
            d = self._call(f"{self.ID}/accounts:lookup", json={"idToken": access_token})
        except AuthError:
            raise AuthError("session expired — run 'login' again") from None
        users = d.get("users") or []
        if not users or users[0].get("disabled"):
            raise AuthError("session expired — run 'login' again")
        u = User(users[0]["localId"], users[0].get("email", ""))
        self._cache[key] = (time.time() + 60, u)
        if len(self._cache) > 5000:
            self._cache.clear()
        return u


class MemoryAuth:
    """Test/local stand-in. Passwords are hashed; tokens are random."""

    def __init__(self) -> None:
        self.users: dict[str, tuple[str, str, bytes]] = {}  # email -> (id, salt, hash)
        self.tokens: dict[str, User] = {}

    @staticmethod
    def _hash(pw: str, salt: str) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000)

    def _issue(self, email: str) -> dict:
        uid = self.users[email][0]
        tok = secrets.token_urlsafe(24)
        self.tokens[tok] = User(uid, email)
        return {"access_token": tok, "refresh_token": "r-" + tok, "expires_in": 3600, "email": email}

    def signup(self, email: str, password: str) -> dict:
        email = email.lower()
        if email in self.users:
            raise AuthError("User already registered", 400)
        if len(password) < 8:
            raise AuthError("Password should be at least 8 characters", 400)
        salt = secrets.token_hex(8)
        self.users[email] = (str(uuid.uuid4()), salt, self._hash(password, salt))
        return self._issue(email)

    def login(self, email: str, password: str) -> dict:
        email = email.lower()
        u = self.users.get(email)
        if not u or not secrets.compare_digest(u[2], self._hash(password, u[1])):
            raise AuthError("invalid email or password", 400)
        return self._issue(email)

    def refresh(self, refresh_token: str) -> dict:
        u = self.tokens.get(refresh_token.removeprefix("r-"))
        if not u:
            raise AuthError("session expired — run 'login' again")
        return self._issue(u.email)

    def user(self, access_token: str) -> User:
        u = self.tokens.get(access_token)
        if not u:
            raise AuthError("session expired — run 'login' again")
        return u
