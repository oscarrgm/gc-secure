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

# Catálogo común: el menú muestra las pistas y disponibles() valida el número.
PISTAS = {1: "Pádel", 2: "Tenis", 3: "Fútbol sala"}
#Las franjas horarias son de 9 a 21, inclusive. La hora final no se reserva.
HORAS = tuple(range(9, 22))
# BLOB permite a SQLite guardar bytes directamente, sin convertirlos a Base64.
ESQUEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    -- El nombre es único y sirve para buscar la cuenta al iniciar sesión.
    nombre TEXT PRIMARY KEY,
    -- Cada cuenta nueva recibe su propio ID, aunque reutilice un nombre.
    id TEXT NOT NULL UNIQUE,
    -- El salt es aleatorio por cuenta. Se guarda para recalcular el verificador.
    salt BLOB NOT NULL,
    -- PBKDF2 calcula este valor a partir de la contraseña y el salt.
    -- Al iniciar sesión se compara el resultado; la contraseña no se guarda.
    verificador BLOB NOT NULL,
    -- HMAC de nombre, ID, salt y verificador para detectar cambios en la cuenta.
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
# Campos visibles de cada reserva. También se autentican como datos asociados.
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

    #La base guarda un verificador y un HMAC, además del salt y el ID.
    salt = secrets.token_bytes(16)  #Salt aleatorio para el verificador de esta cuenta.
    cuenta_id = uuid4().hex #Genera un ID aleatorio y lo representa como texto hexadecimal.
    verificador = derivar(password, salt) #Deriva una clave de 32 bytes a partir de la contraseña y el salt
    etiqueta = etiqueta_cuenta(clave_mac, nombre, cuenta_id, salt, verificador) #Para comprobar que el nombre, ID, salt y verificador no se han modificado.

    #Se añade al usuario a la base de datos. La transacción se confirma al salir del bloque with.
    try:
        with db:
            #Cada ? recibe un valor de la tupla de abajo, en el mismo orden.
            db.execute("INSERT INTO usuarios VALUES (?, ?, ?, ?, ?)",
                       (nombre, cuenta_id, salt, verificador, etiqueta))
    #Si el nombre ya existe, SQLite rechaza el INSERT porque es clave primaria.
    except sqlite3.IntegrityError as error:
        raise ValueError("Ese nombre de usuario ya existe.") from error


#Comprueba que el nombre y la contraseña coinciden con una cuenta de la base de datos.
def autenticar(db, clave_mac, nombre, password):
    #La longitud de registro es de 12 a 128 caracteres. Descarta el resto sin consultar SQLite.
    if not 12 <= len(password) <= 128:
        return None

    #Busca por nombre (clave primaria). fetchone devuelve la fila (como objeto sqlite3.Row) o None.
    cuenta = db.execute("SELECT id, salt, verificador, etiqueta FROM usuarios WHERE nombre = ?",
                        (nombre,)).fetchone()

    if cuenta is None:
        #Repite el cálculo costoso con un salt y un verificador ficticios (ceros).
        #Así cuesta más distinguir por el tiempo si la cuenta existe.
        #Se ignora el resultado y el acceso se rechaza siempre.
        verificar_password(password, bytes(16), bytes(32)) #Bytes(x) devuelve x ceros. El salt es de 16 bytes y el verificador de 32.
        return None


    #Guardo los valores de la fila en variables.
    cuenta_id, salt, verificador, etiqueta = cuenta
    #Primero autentica los datos de la cuenta (para comprobar la integridad)
    if not hmac.compare_digest(etiqueta_cuenta(clave_mac, nombre, cuenta_id, salt, verificador),
                              etiqueta):
        raise InvalidTag("Cuenta alterada.")
    #Después comprueba la contraseña.
    if verificar_password(password, salt, verificador):
        return cuenta_id
    return None

#Prepara los datos asociados de la reserva. AES-GCM usa estos bytes para detectar cambios en los campos visibles sin necesidad de cifrarlos.
def aad(reserva):
    #Copia solo los campos visibles de CAMPOS: id, pista, fecha y hora.
    campos_visibles = {}
    for campo in CAMPOS:
        campos_visibles[campo] = reserva[campo]
    #El prefijo identifica estos datos como parte de una reserva de G&C Secure.
    contexto = b"G&C Secure / reserva / v1\x00"
    #Al cifrar y descifrar usamos la misma conversión a bytes. Si cambia un campo, AES-GCM detecta el cambio al comprobar la etiqueta.
    datos_visibles = json_bytes(campos_visibles)
    return contexto + datos_visibles


#Lee todas las reservas de la base de datos y devuelve una lista de parejas (reserva, titular)
#Se usa para mostrar las reservas de un usuario y para comprobar la disponibilidad de una franja.
def leer_reservas(db, clave):
    #Prepara AES-GCM con la clave simétrica de las reservas.
    cifrador = AESGCM(clave)
    #El SELECT recorre todas las filas.
    filas = db.execute("SELECT * FROM reservas ORDER BY fecha, hora, pista")

    reservas_leidas = []
    # De cada fila copiamos los campos "id", "pista", "fecha" y "hora".
    #Se descifra el titular y se devuelve junto con los datos visibles de la reserva.
    for fila in filas:
        reserva = {}
        for campo in CAMPOS:
            reserva[campo] = fila[campo]

        #decrypt comprueba la etiqueta antes de devolver los bytes del ID.
        #trata de descifrar el ID del titular de la reserva, que estaba cifrado con AES-GCM y autenticado con los datos visibles de la reserva.
        titular_bytes = cifrador.decrypt(fila["nonce"], fila["titular_cifrado"], aad(fila))
        titular = titular_bytes.decode("utf-8")
        #Cada elemento es una pareja: datos visibles de la reserva e ID de su titular.
        reservas_leidas.append((reserva, titular))

    return reservas_leidas


#Devuelve las horas disponibles para una pista y fecha dadas, comparando con las reservas existentes.
def disponibles(db, clave, pista, fecha):
    #fijamos la fecha actual para que no se puedan reservar franjas pasadas.
    ahora = datetime.now()
    #paso la fecha de texto a un objeto date para poder compararla con la fecha actual
    #ademas, verifica que la fecha introducida por el usuario es válida (que no ha puesto mes o dia inexistentes)
    # fromisoformat admite formatos ISO. La comparación posterior exige AAAA-MM-DD.
    dia = date.fromisoformat(fecha)

    #Comprobamos que la pista que nos ha dado el usuario es válida
    #y que la fecha no es pasada. Si no, lanzamos un ValueError.
    #isoformat vuelve a escribir la fecha como AAAA-MM-DD para compararlo con la entrada, exigiendo ese formato.
    if pista not in PISTAS or dia.isoformat() != fecha or dia < ahora.date():
        raise ValueError("Elige una pista válida y una fecha no pasada (AAAA-MM-DD).")

    #Guarda las horas de las reservas que coincidan con la pista y el día elegidos.
    ocupadas = []
    #leer_reservas devuelve una lista de parejas (reserva, titular). Solo nos interesa la reserva ([0]).
    for elemento in leer_reservas(db, clave):
        #Cada elemento es una pareja: [0] son los datos de la reserva y [1] es el ID del titular.
        reserva = elemento[0]
        if reserva["pista"] == pista and reserva["fecha"] == fecha:
            ocupadas.append(reserva["hora"])

    #Devuelve las horas libres, que son las de HORAS que no están ocupadas y que no han pasado todavía.
    horas_libres = []
    for hora in HORAS:
        #Si la hora no está ocupada, comprueba que la franja aún no ha empezado.
        if hora not in ocupadas:
            #Une el día y la hora para comprobar que la franja aún no ha empezado.
            inicio_franja = datetime.combine(dia, time(hora))
            if inicio_franja > ahora:
                horas_libres.append(hora)
    return horas_libres

#Guarda una reserva en la base de datos, cifrando el ID del titular con AES-GCM.
def reservar(db, clave, cuenta_id, pista, fecha, hora):
    # with db confirma la transacción si todo va bien o la revierte si hay un error.
    with db:
        #Pide el turno de escritura antes de consultar, y lo mantiene hasta guardar la reserva, incluida la comprobación del nonce.
        db.execute("BEGIN IMMEDIATE")
        #La franja pudo ocuparse desde que se mostró el menú. Si dos usuarios eligen la misma hora, quien consigue primero el turno puede guardarla.
        #Si la guarda, el siguiente verá que ya está ocupada al comprobarla aquí
        if hora not in disponibles(db, clave, pista, fecha):
            raise ValueError("Esa franja no está disponible.")

        #Crea un diccionario con los datos visibles de la reserva. El ID es aleatorio y se guarda en la base de datos.
        reserva = {"id": uuid4().hex, "pista": pista, "fecha": fecha, "hora": hora}
        #Genera un nonce y comprueba que no se repita en la base de datos, ya que AES-GCM necesita un nonce único para cada cifrado con la misma clave
        nonce = secrets.token_bytes(12)
        while db.execute("SELECT 1 FROM reservas WHERE nonce = ?", (nonce,)).fetchone():
            nonce = secrets.token_bytes(12)

        #Cifra el ID del titular con AES-GCM, usando el nonce y los datos visibles de la reserva como datos asociados
        titular = AESGCM(clave).encrypt(nonce, cuenta_id.encode("utf-8"), aad(reserva))
        #Se inserta la reserva en la base de datos. La transacción se confirma al salir del bloque with
        db.execute("INSERT INTO reservas VALUES (?, ?, ?, ?, ?, ?)",
                   (reserva["id"], pista, fecha, hora, nonce, titular))
    return reserva


# Devuelve solo las reservas de la cuenta que ha iniciado sesión.
def mis_reservas(db, clave, cuenta_id):
    reservas_propias = []
    for elemento in leer_reservas(db, clave):
        #Cada elemento contiene los datos de la reserva y el ID de su titular.
        reserva = elemento[0]
        titular = elemento[1]
        if titular == cuenta_id:
            reservas_propias.append(reserva)
    return reservas_propias
