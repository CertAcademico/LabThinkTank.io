import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from db import get_conn

SECRET_KEY    = os.getenv("JWT_SECRET", "cti-lab-dev-secret-CHANGE-IN-PRODUCTION")
ALGORITHM     = "HS256"
ALLOWED_DOMAIN = "universidadean.edu.co"
TOKEN_HOURS   = 24 * 7  # 1 semana

pwd_ctx  = CryptContext(schemes=["bcrypt"], deprecated="auto")
EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')


def _validate(email: str, password: str, name: str = "") -> None:
    if name is not None and not name.strip():
        raise ValueError("El nombre es requerido")
    if not EMAIL_RE.match(email):
        raise ValueError("Formato de email inválido")
    domain = email.split("@")[1].lower()
    if domain != ALLOWED_DOMAIN:
        raise ValueError(f"Solo se permiten cuentas @{ALLOWED_DOMAIN}")
    if len(password) < 8:
        raise ValueError("La contraseña debe tener al menos 8 caracteres")


def register(name: str, email: str, password: str,
             password_expires_at: Optional[str] = None) -> dict:
    email = email.strip().lower()
    name  = name.strip()
    _validate(email, password, name)

    with get_conn() as conn:
        if conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            raise ValueError("Este email ya está registrado")
        conn.execute(
            "INSERT INTO users (name, email, password_hash, password_expires_at) VALUES (?, ?, ?, ?)",
            (name, email, pwd_ctx.hash(password), password_expires_at),
        )
    return {"email": email, "name": name}


def login(email: str, password: str) -> str:
    email = email.strip().lower()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT name, password_hash, role, password_expires_at FROM users WHERE email = ?",
            (email,)
        ).fetchone()

    if not row or not pwd_ctx.verify(password, row["password_hash"]):
        raise ValueError("Email o contraseña incorrectos")

    # Check temporary password expiry
    expires_at = row["password_expires_at"]
    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp_dt:
                raise ValueError(
                    "Tu contraseña temporal ha vencido. "
                    "Contacta al administrador para renovar el acceso."
                )
        except ValueError as e:
            if "vencido" in str(e):
                raise

    payload = {
        "sub":  email,
        "name": row["name"],
        "role": row["role"],
        "exp":  datetime.utcnow() + timedelta(hours=TOKEN_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> Optional[dict]:
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {
            "email": data["sub"],
            "name":  data.get("name", ""),
            "role":  data.get("role", "student"),
        }
    except JWTError:
        return None
