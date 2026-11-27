import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from db import get_conn

SECRET_KEY    = os.getenv("JWT_SECRET", "")
if len(SECRET_KEY) < 32:
    raise RuntimeError("JWT_SECRET debe estar definido en .env y tener al menos 32 caracteres")
ALGORITHM     = "HS256"
ALLOWED_DOMAIN = "universidadean.edu.co"
TOKEN_HOURS   = 24 * 7  # estudiantes: 1 semana
ADMIN_TOKEN_HOURS = 12  # admin: sesión corta
STREAM_TICKET_SECONDS = 60

# Bloqueo por intentos fallidos (en memoria, por email): 5 fallos en 15 min → 15 min bloqueado.
MAX_FAILS     = 5
FAIL_WINDOW   = timedelta(minutes=15)
_fails: dict[str, list[datetime]] = {}

pwd_ctx  = CryptContext(schemes=["bcrypt"], deprecated="auto")
EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')


def open_signup_until() -> Optional[datetime]:
    """Fin de la ventana en que se acepta cualquier dominio (OPEN_SIGNUP_UNTIL, ISO 8601)."""
    raw = os.getenv("OPEN_SIGNUP_UNTIL", "").strip()
    if not raw:
        return None
    try:
        until = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone(timedelta(hours=-5)))  # hora Colombia
    return until


def open_domains_active() -> bool:
    until = open_signup_until()
    return bool(until and datetime.now(timezone.utc) < until)


def domain_allowed(email: str) -> bool:
    domain = email.rsplit("@", 1)[-1].lower()
    return domain == ALLOWED_DOMAIN or open_domains_active()


def _validate(email: str, password: str, name: str = "") -> None:
    if name is not None and not name.strip():
        raise ValueError("El nombre es requerido")
    if not EMAIL_RE.match(email):
        raise ValueError("Formato de email inválido")
    if not domain_allowed(email):
        raise ValueError(f"Solo se permiten cuentas @{ALLOWED_DOMAIN}")
    check_password_strength(password, email)


def check_password_strength(password: str, email: str = "") -> None:
    """Política mínima: 10+ caracteres, letras y números, y que no contenga el usuario del correo."""
    if len(password) < 10:
        raise ValueError("La contraseña debe tener al menos 10 caracteres")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ValueError("La contraseña debe combinar letras y números")
    local = email.split("@", 1)[0].lower()
    if len(local) >= 4 and local in password.lower():
        raise ValueError("La contraseña no puede contener tu usuario de correo")


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


def _recent_fails(email: str) -> list[datetime]:
    now = datetime.now(timezone.utc)
    fails = [t for t in _fails.get(email, []) if now - t < FAIL_WINDOW]
    _fails[email] = fails
    return fails


def login(email: str, password: str) -> str:
    email = email.strip().lower()
    if len(_recent_fails(email)) >= MAX_FAILS:
        raise ValueError("Demasiados intentos fallidos. Espera 15 minutos e inténtalo de nuevo.")
    with get_conn() as conn:
        row = conn.execute(
            "SELECT name, password_hash, role, password_expires_at FROM users WHERE email = ?",
            (email,)
        ).fetchone()

    if not row or not pwd_ctx.verify(password, row["password_hash"]):
        _fails.setdefault(email, []).append(datetime.now(timezone.utc))
        raise ValueError("Email o contraseña incorrectos")
    _fails.pop(email, None)

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

    hours = ADMIN_TOKEN_HOURS if row["role"] == "admin" else TOKEN_HOURS
    now = datetime.now(timezone.utc)
    payload = {
        "sub":  email,
        "name": row["name"],
        "role": row["role"],
        "iat":  int(now.timestamp()),
        "exp":  now + timedelta(hours=hours),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> Optional[dict]:
    """Valida el JWT de sesión contra la base: el rol sale de la BD (no del token) y
    se rechazan tokens emitidos antes de un cambio de contraseña o de un cierre de sesiones."""
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
    if data.get("scope"):          # tickets de streaming no sirven como sesión
        return None
    with get_conn() as conn:
        row = conn.execute("SELECT name, role, tokens_valid_after FROM users WHERE email = ?",
                           (data.get("sub", ""),)).fetchone()
    if not row:
        return None
    if row["tokens_valid_after"] and int(data.get("iat", 0)) < int(row["tokens_valid_after"]):
        return None
    return {"email": data["sub"], "name": row["name"] or data.get("name", ""), "role": row["role"] or "student"}


def create_stream_ticket(email: str) -> str:
    """Ticket de 60 s solo para abrir el stream SSE (EventSource no admite cabeceras y
    el valor viaja en la URL, donde queda en los logs). No sirve como sesión."""
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": email, "scope": "stream", "iat": int(now.timestamp()),
                       "exp": now + timedelta(seconds=STREAM_TICKET_SECONDS)}, SECRET_KEY, algorithm=ALGORITHM)


def verify_stream_ticket(ticket: str) -> bool:
    try:
        data = jwt.decode(ticket, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return False
    return data.get("scope") == "stream"


def change_password(email: str, current: str, new: str) -> None:
    email = email.strip().lower()
    with get_conn() as conn:
        row = conn.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,)).fetchone()
        if not row or not pwd_ctx.verify(current, row["password_hash"]):
            raise ValueError("La contraseña actual no es correcta")
        if current == new:
            raise ValueError("La nueva contraseña debe ser distinta de la actual")
        check_password_strength(new, email)
        conn.execute(
            "UPDATE users SET password_hash = ?, password_expires_at = NULL, tokens_valid_after = ? WHERE id = ?",
            (pwd_ctx.hash(new), int(datetime.now(timezone.utc).timestamp()), row["id"]),
        )


def ensure_admin() -> None:
    """Crea o restaura la cuenta admin definida en ADMIN_EMAIL / ADMIN_PASSWORD.

    - Si no existe, la crea con rol admin.
    - Si existe, garantiza que tenga rol admin (no toca la clave, para que
      un cambio hecho desde la plataforma no se pierda al reiniciar).
    - Con ADMIN_RESET_PASSWORD=true se fuerza la clave de .env en cada arranque.
    """
    email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("ADMIN_PASSWORD", "")
    if not email:
        return
    if not password:
        # Sin clave en .env: solo garantiza el rol de una cuenta ya existente.
        with get_conn() as conn:
            conn.execute("UPDATE users SET role = 'admin' WHERE email = ?", (email,))
        return
    name = os.getenv("ADMIN_NAME", "Admin Lab").strip() or "Admin Lab"
    reset = os.getenv("ADMIN_RESET_PASSWORD", "").strip().lower() in ("1", "true", "yes")

    with get_conn() as conn:
        row = conn.execute("SELECT id, role FROM users WHERE email = ?", (email,)).fetchone()
        if not row:
            conn.execute(
                "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
                (name, email, pwd_ctx.hash(password)),
            )
            print(f"[auth] cuenta admin creada: {email}")
            return
        if row["role"] != "admin":
            conn.execute("UPDATE users SET role = 'admin' WHERE id = ?", (row["id"],))
            print(f"[auth] rol admin restaurado: {email}")
        if reset:
            conn.execute(
                "UPDATE users SET password_hash = ?, password_expires_at = NULL, tokens_valid_after = ? WHERE id = ?",
                (pwd_ctx.hash(password), int(datetime.now(timezone.utc).timestamp()), row["id"]),
            )
            print(f"[auth] clave admin restablecida desde .env: {email}")
