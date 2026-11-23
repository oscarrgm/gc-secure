"""Contraseñas, claves del sistema, cifrado y firma."""
import base64
import hashlib
import hmac
import json
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITERACIONES = 600_000
# Estos prefijos identifican el propósito de los datos que autentica cada operación.
CONTEXTO_CLAVES = b"G&C Secure / claves / v1"
CONTEXTO_FIRMA = b"G&C Secure / justificante / v1\x00"
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def codificar(datos):
    # Base64 convierte bytes en texto para JSON. Se puede revertir sin una clave.
    return base64.b64encode(datos).decode("ascii")


def decodificar(texto):
    return base64.b64decode(texto, validate=True)


def json_bytes(datos):
    # El orden fijo y los separadores dan la misma representación a los mismos datos.
    return json.dumps(datos, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def derivar(secreto, sal):
    # PBKDF2 repite el cálculo para encarecer cada intento de adivinar la frase.
    return hashlib.pbkdf2_hmac("sha256", secreto.encode("utf-8"),
                               sal, ITERACIONES, dklen=32)


def verificar_password(password, sal, verificador):
    # Recalcula el verificador con la sal guardada y compara en tiempo constante.
    return hmac.compare_digest(derivar(password, sal), verificador)


def etiqueta_cuenta(clave, nombre, cuenta_id, sal, verificador):
    # El HMAC vincula los cuatro campos a la clave del sistema.
    contenido = json_bytes([nombre, cuenta_id, codificar(sal), codificar(verificador)])
    return hmac.digest(clave, b"G&C Secure / cuenta / v1\x00" + contenido, "sha256")


def crear_claves(ruta, frase):
    # El sistema genera claves independientes para cifrar, firmar y autenticar cuentas.
    clave_aes = AESGCM.generate_key(bit_length=128)
    privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = privada.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    contenido = json_bytes({"aes": codificar(clave_aes), "rsa": codificar(pem),
                            "mac": codificar(secrets.token_bytes(32))})
    # Protege las tres claves juntas con AES-GCM y una clave derivada de la frase.
    sal, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    protegido = AESGCM(derivar(frase, sal)).encrypt(nonce, contenido, CONTEXTO_CLAVES)
    with ruta.open("xb") as archivo:
        archivo.write(sal + nonce + protegido)


def cargar_claves(ruta, frase):
    datos = ruta.read_bytes()
    if len(datos) < 44:
        raise ValueError("Fichero de claves incompleto.")
    # El archivo empieza por la sal y el nonce, de tamaño fijo. El resto va cifrado.
    sal, nonce, protegido = datos[:16], datos[16:28], datos[28:]
    contenido = AESGCM(derivar(frase, sal)).decrypt(nonce, protegido, CONTEXTO_CLAVES)
    claves = json.loads(contenido)
    if "mac" not in claves:
        raise ValueError("Datos de la versión previa. Usa otro directorio con --datos e inicialízalo.")
    privada = serialization.load_pem_private_key(decodificar(claves["rsa"]), None)
    return decodificar(claves["aes"]), privada, decodificar(claves["mac"])


def clave_publica_pem(privada):
    # PEM es el formato de texto que guardamos en el archivo centro.pem.
    return privada.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)


def firmar_justificante(privada, reserva):
    # Se firman los bytes exactos de la reserva y se empaquetan con la firma.
    mensaje = json_bytes(reserva)
    firma = privada.sign(CONTEXTO_FIRMA + mensaje, PSS, hashes.SHA256())
    return json_bytes({"mensaje": codificar(mensaje), "firma": codificar(firma)})


def verificar_justificante(publica_pem, documento):
    publica = serialization.load_pem_public_key(publica_pem)
    if not isinstance(publica, rsa.RSAPublicKey) or publica.key_size < 2048:
        raise ValueError("Se necesita una clave pública RSA de al menos 2048 bits.")
    sobre = json.loads(documento)
    if not isinstance(sobre, dict) or sobre.keys() != {"mensaje", "firma"}:
        raise ValueError("Formato de justificante incorrecto.")
    if not all(isinstance(valor, str) for valor in sobre.values()):
        raise ValueError("Codificación de justificante incorrecta.")
    mensaje = decodificar(sobre["mensaje"])
    firma = decodificar(sobre["firma"])
    # Una firma inválida interrumpe la operación con InvalidSignature.
    publica.verify(firma, CONTEXTO_FIRMA + mensaje, PSS, hashes.SHA256())
    reserva = json.loads(mensaje)
    if not isinstance(reserva, dict) or reserva.keys() != {"id", "pista", "fecha", "hora"}:
        raise ValueError("Formato de reserva incorrecto.")
    return reserva
