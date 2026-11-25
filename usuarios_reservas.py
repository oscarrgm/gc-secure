"""Cuentas de usuario, reservas y almacenamiento en SQLite."""
import hmac
import re
import secrets
import sqlite3
from datetime import date, datetime, time
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from seguridad import derivar, etiqueta_cuenta, json_bytes, validar_password, verificar_password

PISTAS = {1: "Pádel 1", 2: "Tenis 1", 3: "Fútbol sala"}
HORAS = tuple(range(9, 22))
# BLOB permite a SQLite guardar bytes directamente, sin convertirlos a Base64.
ESQUEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    -- El nombre es único y sirve para buscar la cuenta al iniciar sesión.
    nombre TEXT PRIMARY KEY,
    -- Cada cuenta nueva recibe su propio ID, aunque reutilice un nombre.
    id TEXT NOT NULL UNIQUE,
    -- La sal es aleatoria por cuenta. Se guarda para recalcular el verificador.
    sal BLOB NOT NULL,
    -- PBKDF2 calcula este valor a partir de la contraseña y la sal.
    -- Al iniciar sesión se compara el resultado; la contraseña no se guarda.
    verificador BLOB NOT NULL,
    -- HMAC de nombre, ID, sal y verificador para detectar cambios en la cuenta.
    etiqueta BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS reservas (
    -- Identifica una reserva concreta, no al usuario ni a la pista.
    id TEXT PRIMARY KEY,
    -- Estos tres campos identifican la franja y quedan visibles.
    pista INTEGER NOT NULL,
    fecha TEXT NOT NULL,
    hora INTEGER NOT NULL,
    -- AES-GCM necesita este valor para recuperar el titular. Se guarda en claro y UNIQUE evita que dos reservas guardadas tengan el mismo nonce.
    nonce BLOB NOT NULL UNIQUE,
    -- ID de la cuenta que reservó, cifrado con AES-GCM. Incluye su etiqueta.
    titular_cifrado BLOB NOT NULL,
    -- Impide dos reservas en la misma pista, fecha y hora.
    UNIQUE (pista, fecha, hora)
);
"""
CAMPOS = ("id", "pista", "fecha", "hora")

#Recibe la ruta de la base de datos y devuelve un objeto de conexión a SQLite.
#La base de datos se abre en modo "IMMEDIATE" para que las transacciones bloqueen la base de datos desde el principio y no haya sorpresas al escribir.
def abrir_base(ruta):
    #Abre el archivo de SQLite o lo crea si aún no existe. (db es la conexión que usaremos para enviarle consultas)
    db = sqlite3.connect(ruta, isolation_level="IMMEDIATE")
    #Devuelve las filas como sqlite3.Row para acceder a sus columnas por nombre.
    db.row_factory = sqlite3.Row
    #Ejecuta las dos instrucciones SQL (crea las tablas si no existen). executescript ejecuta varias instrucciones SQL separadas por punto y coma.
    db.executescript(ESQUEMA)
    #devuelve la conexión a la base de datos abierta
    return db

#Registra un nuevo usuario en la base de datos.
def registrar(db, clave_mac, nombre, password):
    #fullmatch exige que el nombre entero cumpla el patrón de 3 a 32 caracteres [a-z0-9_]
    #no permitimos mayúsculas, espacios ni caracteres especiales
    if not re.fullmatch(r"[a-z0-9_]{3,32}", nombre):
        raise ValueError("Usa de 3 a 32 letras minúsculas ASCII, dígitos o guiones bajos.")
    #Comprueba la contraseña
    validar_password(password)

    #La base guarda un verificador y un HMAC, además de la sal y el ID.
    sal = secrets.token_bytes(16)  #Sal aleatoria para el verificador de esta cuenta.
    cuenta_id = uuid4().hex #Genera un ID aleatorio y lo representa como texto hexadecimal.
    verificador = derivar(password, sal) #Deriva una clave de 32 bytes a partir de la contraseña y la sal
    etiqueta = etiqueta_cuenta(clave_mac, nombre, cuenta_id, sal, verificador) #Para comprobar que el nombre, ID, sal y verificador no se han modificado.

    #Se añade al usuario a la base de datos. La transacción se confirma al salir del bloque with.
    try:
        with db:
            #Cada ? recibe un valor de la tupla de abajo, en el mismo orden.
            db.execute("INSERT INTO usuarios VALUES (?, ?, ?, ?, ?)",
                       (nombre, cuenta_id, sal, verificador, etiqueta))
    #Si el nombre ya existe, SQLite rechaza el INSERT porque es clave primaria.
    except sqlite3.IntegrityError as error:
        raise ValueError("Ese nombre de usuario ya existe.") from error


#Comprueba que el nombre y la contraseña coinciden con una cuenta de la base de datos.
def autenticar(db, clave_mac, nombre, password):
    #La longitud de registro es de 12 a 128 caracteres. Descarta el resto sin consultar SQLite.
    if not 12 <= len(password) <= 128:
        return None

    #Busca por nombre (clave primaria). fetchone devuelve la fila (como objeto sqlite3.Row) o None.
    cuenta = db.execute("SELECT id, sal, verificador, etiqueta FROM usuarios WHERE nombre = ?",
                        (nombre,)).fetchone()

    if cuenta is None:
        #Repite el cálculo costoso con una sal y un verificador ficticios (ceros).
        #Así cuesta más distinguir por el tiempo si la cuenta existe.
        #Se ignora el resultado y el acceso se rechaza siempre.
        verificar_password(password, bytes(16), bytes(32)) #Bytes(x) devuelve x ceros. La sal es de 16 bytes y el verificador de 32.
        return None


    #Guardo los valores de la fila en variables.
    cuenta_id, sal, verificador, etiqueta = cuenta
    #Primero autentica los datos de la cuenta (para comprobar la integridad)
    if not hmac.compare_digest(etiqueta_cuenta(clave_mac, nombre, cuenta_id, sal, verificador),
                              etiqueta):
        raise InvalidTag("Cuenta alterada.")
    #Después comprueba la contraseña.
    if verificar_password(password, sal, verificador):
        return cuenta_id
    return None


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
