"""Reglas de negocio y almacenamiento en SQLite."""
import hmac
import re
import secrets
import sqlite3
from datetime import date, datetime, time
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from seguridad import derivar, etiqueta_cuenta, json_bytes, verificar_password

PISTAS = {1: "Pádel 1", 2: "Tenis 1", 3: "Fútbol sala"}
HORAS = tuple(range(9, 22))
# SQLite impone un nonce único por reserva y una única reserva por franja.
ESQUEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    nombre TEXT PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    sal BLOB NOT NULL,
    verificador BLOB NOT NULL,
    etiqueta BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS reservas (
    id TEXT PRIMARY KEY,
    pista INTEGER NOT NULL,
    fecha TEXT NOT NULL,
    hora INTEGER NOT NULL,
    nonce BLOB NOT NULL UNIQUE,
    titular_cifrado BLOB NOT NULL,
    UNIQUE (pista, fecha, hora)
);
"""
CAMPOS = ("id", "pista", "fecha", "hora")


def validar_frase(frase):
    if not 12 <= len(frase) <= 128 or frase.isspace():
        raise ValueError("Usa una frase de entre 12 y 128 caracteres.")


def abrir_base(ruta):
    # row_factory permite acceder a cada campo por el nombre de su columna.
    db = sqlite3.connect(ruta, isolation_level="IMMEDIATE")
    db.row_factory = sqlite3.Row
    db.executescript(ESQUEMA)
    return db


def registrar(db, clave_mac, nombre, password):
    if not re.fullmatch(r"[a-z0-9_]{3,32}", nombre):
        raise ValueError("Usa de 3 a 32 letras minúsculas ASCII, dígitos o guiones bajos.")
    validar_frase(password)
    # El ID identifica la cuenta incluso si se reutiliza su nombre más adelante.
    # La base guarda un verificador y un HMAC, además de la sal y el ID.
    sal = secrets.token_bytes(16)
    cuenta_id = uuid4().hex
    verificador = derivar(password, sal)
    etiqueta = etiqueta_cuenta(clave_mac, nombre, cuenta_id, sal, verificador)
    try:
        with db:
            # SQLite recibe los valores aparte de la consulta, en lugar de interpolarlos.
            db.execute("INSERT INTO usuarios VALUES (?, ?, ?, ?, ?)",
                       (nombre, cuenta_id, sal, verificador, etiqueta))
    except sqlite3.IntegrityError as error:
        raise ValueError("Ese nombre de usuario ya existe.") from error


def autenticar(db, clave_mac, nombre, password):
    if len(password) > 128:
        return None
    cuenta = db.execute("SELECT id, sal, verificador, etiqueta FROM usuarios WHERE nombre = ?",
                        (nombre,)).fetchone()
    if cuenta is None:
        # Una búsqueda sin resultado también hace el cálculo costoso de contraseña.
        verificar_password(password, bytes(16), bytes(32))
        return None
    # Primero autentica los datos de la cuenta y después comprueba la contraseña.
    cuenta_id, sal, verificador, etiqueta = cuenta
    if not hmac.compare_digest(etiqueta_cuenta(clave_mac, nombre, cuenta_id, sal, verificador),
                              etiqueta):
        raise InvalidTag("Cuenta alterada.")
    return cuenta_id if verificar_password(password, sal, verificador) else None


def aad(reserva):
    # AES-GCM autentica estos campos visibles al comprobar el titular cifrado.
    return b"G&C Secure / reserva / v1\x00" + json_bytes(
        {campo: reserva[campo] for campo in CAMPOS})


def leer_reservas(db, clave):
    # decrypt comprueba la etiqueta antes de devolver el ID del titular.
    cifrador = AESGCM(clave)
    filas = db.execute("SELECT * FROM reservas ORDER BY fecha, hora, pista")
    return [
        ({campo: fila[campo] for campo in CAMPOS},
         cifrador.decrypt(fila["nonce"], fila["titular_cifrado"], aad(fila)).decode("utf-8"))
        for fila in filas
    ]


def disponibles(db, clave, pista, fecha, ahora=None):
    # Ahora puede fijarse en una prueba; por defecto se usa la hora del equipo.
    ahora = ahora or datetime.now()
    dia = date.fromisoformat(fecha)
    if pista not in PISTAS or dia.isoformat() != fecha or dia < ahora.date():
        raise ValueError("Elige una pista válida y una fecha no pasada (AAAA-MM-DD).")
    ocupadas = {r["hora"] for r, _ in leer_reservas(db, clave)
                if r["pista"] == pista and r["fecha"] == fecha}
    return [hora for hora in HORAS if hora not in ocupadas
            and datetime.combine(dia, time(hora)) > ahora]


def reservar(db, clave, cuenta_id, pista, fecha, hora):
    # El bloqueo cubre la consulta de disponibilidad, el nonce y la escritura.
    with db:
        db.execute("BEGIN IMMEDIATE")
        if hora not in disponibles(db, clave, pista, fecha):
            raise ValueError("Esa franja no está disponible.")
        reserva = {"id": uuid4().hex, "pista": pista, "fecha": fecha, "hora": hora}
        # Comprueba el nonce antes de cifrar con la clave de reservas.
        nonce = secrets.token_bytes(12)
        while db.execute("SELECT 1 FROM reservas WHERE nonce = ?", (nonce,)).fetchone():
            nonce = secrets.token_bytes(12)
        titular = AESGCM(clave).encrypt(nonce, cuenta_id.encode("utf-8"), aad(reserva))
        db.execute("INSERT INTO reservas VALUES (?, ?, ?, ?, ?, ?)",
                   (reserva["id"], pista, fecha, hora, nonce, titular))
    return reserva


def mis_reservas(db, clave, cuenta_id):
    # El menú solo recibe las reservas del ID que inició sesión.
    return [reserva for reserva, titular in leer_reservas(db, clave) if titular == cuenta_id]
