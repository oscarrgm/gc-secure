"""Contraseñas, claves del sistema, cifrado y firma."""
import base64
import hashlib
import hmac
import json
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Numero de iteraciones de PBKDF2 para derivar la clave de cifrado a partir de la contraseña del operador.
#Cuanto mayor, más lento será el desbloqueo y más seguro frente a ataques de fuerza bruta.
ITERACIONES = 600_000

#Etiqueta fija para el paquete de claves del sistema. Se incluye en el cálculo de la etiqueta AES-GCM para que no se pueda usar el mismo paquete para otro propósito.
CONTEXTO_CLAVES = b"G&C Secure / claves / v1"

#Etiqueta fija para los justificantes de G&C Secure v1. Con un solo tipo de documento no es necesaria, pero si la misma clave firmara también cancelaciones,
#cada tipo usaría una etiqueta distinta al firmar y al verificar.
#\x00 es un byte de valor cero que separa la etiqueta del mensaje.
CONTEXTO_FIRMA = b"G&C Secure / justificante / v1\x00"

#Prefijo del HMAC de la cuenta, tanto al registrarla como al autenticarla.
CONTEXTO_REGISTRO = b"G&C Secure / cuenta / v1\x00"

#PSS prepara el bloque que firma RSA. Usa el resumen del mensaje y un salt aleatorio de 32 bytes para calcular un segundo resumen, H.
#MGF1 usa SHA-256 y H para generar una secuencia de bytes (la máscara). PSS la combina mediante XOR con la parte del bloque que contiene el salt.
#Al verificar, se vuelve a generar la misma máscara y se aplica XOR de nuevo para recuperar el salt original.
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


#Representa los bytes originales como texto Base64 para guardarlos en JSON. b64encode devuelve bytes ASCII y decode("ascii") los convierte en un str.
def codificar(datos):
    return base64.b64encode(datos).decode("ascii")

#Convierte el texto Base64 de vuelta a los bytes originales. validate=True rechaza texto Base64 inválido.
def decodificar(texto):
    return base64.b64decode(texto, validate=True)


#convierto un diccionario a JSON y lo codifico en UTF-8 para que AES-GCM pueda cifrarlo
def json_bytes(datos):
    #dumps() toma el diccionario y nos da texto JSON
    return json.dumps(datos, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


#Comprueba la longitud (entre 12 y 128) y exige una mayúscula, una minúscula y un dígito.
def validar_password(password):
    if not 12 <= len(password) <= 128:
        raise ValueError("Usa una contraseña de entre 12 y 128 caracteres.")
    #any comprueba si al menos un carácter cumple cada requisito.
    tiene_mayuscula = any(c.isalpha() and c.isupper() for c in password) #isalpha comprueba si c es una letra e isupper si es mayúscula.
    tiene_minuscula = any(c.isalpha() and c.islower() for c in password) #islower comprueba si la letra es minúscula.
    tiene_digito = any(c.isdecimal() for c in password) #isdecimal comprueba si c es un dígito decimal.
    if not tiene_mayuscula or not tiene_minuscula or not tiene_digito:
        raise ValueError("Incluye al menos una mayúscula, una minúscula y un dígito.")


#Deriva una clave de 32 bytes a partir de la contraseña y el salt
def derivar(secreto, salt):
    #PBKDF2 repite el cálculo para encarecer cada intento de adivinar el secreto. "sha256" es la función resumen que usa HMAC y secreto.encode convierte
    #la contraseña en bytes para que HMAC pueda usarla como clave. El salt permite obtener resultados distintos con la misma contraseña.
    #ITERACIONES fija cuántas rondas se hacen (encareciendo ataques de fuerza bruta)
    #La contraseña es la clave de HMAC en todas las rondas.
    #La primera usa el salt y un contador y las siguientes, el resultado anterior.
    #dklen=32 pide 32 bytes de salida.
    return hashlib.pbkdf2_hmac("sha256", secreto.encode("utf-8"),
                               salt, ITERACIONES, dklen=32)


#Comprueba que la contraseña coincide con el verificador guardado en la base de datos.
def verificar_password(password, salt, verificador):
    return hmac.compare_digest(derivar(password, salt), verificador)


#El HMAC vincula los cuatro campos a la clave del sistema.
def etiqueta_cuenta(clave, nombre, cuenta_id, salt, verificador):
    #Reúne los cuatro campos como bytes. El salt y el verificador van en Base64 dentro del JSON.
    contenido = json_bytes([nombre, cuenta_id, codificar(salt), codificar(verificador)])
    #Calcula una etiqueta HMAC con la clave secreta del centro y los datos de la cuenta.
    return hmac.digest(clave, CONTEXTO_REGISTRO + contenido, "sha256")


#Solo se llama al inicializar
#Recibe la password y la ruta donde guardará la clave
def crear_claves(ruta, password_operador):
    #El sistema genera claves independientes para cifrar, firmar y autenticar cuentas.
    clave_aes = AESGCM.generate_key(bit_length=128)
    #RSA: e = 65537 es el exponente público usado para verificar firmas. key_size pide un módulo n de 2048 bits.
    privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    #private_bytes convierte la clave en bytes.
    pem = privada.private_bytes(serialization.Encoding.PEM, #Como representa el paquete (como texto)
                                 serialization.PrivateFormat.PKCS8, #Como organizar esos bytes. PKCS8 da a la librería un formato conocido para escribir y recuperar esa información
                                 serialization.NoEncryption()) #No cifra la clave privada dentro del paquete, porque el archivo completo se cifra con AES-GCM más abajo

    #codificar convierte los bytes a Base64 para guardarlos en JSON.
    contenido = json_bytes({"aes": codificar(clave_aes), "rsa": codificar(pem),
                            "mac": codificar(secrets.token_bytes(32))})  # Clave HMAC de las cuentas.

    #Protege las tres claves juntas con AES-GCM y una clave derivada de la contraseña.
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    #Encriptamos el contenido con AES-GCM usando la clave derivada de la contraseña del operador, el nonce y el contexto CONTEXTO_CLAVES.
    protegido = AESGCM(derivar(password_operador, salt)).encrypt(nonce, contenido, CONTEXTO_CLAVES) #se incluye el contexto para que AES-GCM autentique también el propósito de los datos cifrados
    #"x" crea un archivo nuevo y falla si ya existe y "b" permite escribir bytes.
    with ruta.open("xb") as archivo:
        archivo.write(salt + nonce + protegido)

#Carga las claves del sistema desde el archivo cifrado con la contraseña del operador
def cargar_claves(ruta, password_operador):
    #Lee el archivo en el mismo orden en que se escribió: salt, nonce y paquete cifrado con su etiqueta. El mínimo es 16 + 12 + 16 = 44 bytes:
    #16 de salt, 12 de nonce y 16 de etiqueta AES-GCM, incluso sin contenido.
    datos = ruta.read_bytes()
    if len(datos) < 44:
        raise ValueError("Fichero de claves incompleto.")
    #Separa el salt y el nonce. El resto es el texto cifrado con su etiqueta al final.
    salt, nonce, protegido = datos[:16], datos[16:28], datos[28:]
    #Repite la derivación con la contraseña y el salt guardado. AES-GCM comprueba la etiqueta con el mismo nonce y contexto antes de devolver el JSON.
    contenido = AESGCM(derivar(password_operador, salt)).decrypt(nonce, protegido, CONTEXTO_CLAVES)

    #Lee el JSON que se preparó al crear las claves y lo convierte en un diccionario
    claves = json.loads(contenido)

    #El paquete debe ser un diccionario con los tres campos: aes, rsa y mac.
    if not isinstance(claves, dict) or claves.keys() != {"aes", "rsa", "mac"}:
        raise ValueError("Formato de archivo de claves incorrecto.")

    #decodificar quita el Base64 exterior
    #carga el PEM como una clave RSA utilizable (objeto de cryptography). None indica que el PEM no lleva contraseña propia (porque no lo habiamos cifrado).
    privada = serialization.load_pem_private_key(decodificar(claves["rsa"]), None)
    #Devuelve AES y HMAC como bytes y la privada RSA como objeto de cryptography.
    return decodificar(claves["aes"]), privada, decodificar(claves["mac"])


#Función para obtener la clave pública en formato PEM a partir de la clave privada.
def clave_publica_pem(privada):
    #PEM es el formato de texto que guardamos en el archivo centro.pem.
    return privada.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)


#Se firma el justificante con la clave privada del centro. Se devuelve un JSON con el mensaje y la firma en Base64.
def firmar_justificante(privada, reserva):
    #Se firman los bytes exactos de la reserva y se empaquetan con la firma.
    mensaje = json_bytes(reserva)
    #PSS prepara el bloque que firma RSA (usa un salt). CONTEXTO_FIRMA indica el tipo de documento y se concatena con el mensaje para que la firma dependa de ambos.
    #hashes.SHA256() calcula el resumen de los datos que se firman.
    firma = privada.sign(CONTEXTO_FIRMA + mensaje, PSS, hashes.SHA256())
    return json_bytes({"mensaje": codificar(mensaje), "firma": codificar(firma)})


#Funcion llamada desde main.py para verificar el justificante recibido del centro, usando la clave pública del centro.
def verificar_justificante(publica_pem, documento):

    #serialization.load_pem_public_key recibe los bytes del PEM y devuelve una clave pública utilizable.
    publica = serialization.load_pem_public_key(publica_pem)
    #Comprueba si la clave es del tipo RSAPublicKey. Y si es RSA exigimos al menos 2048 bits (key_size indica su tamaño en bits).
    if not isinstance(publica, rsa.RSAPublicKey) or publica.key_size < 2048:
        raise ValueError("Se necesita una clave pública RSA de al menos 2048 bits.")

    #Lee el JSON y lo convierte en un diccionario.
    sobre = json.loads(documento)
    #El diccionario debe tener exactamente dos claves: mensaje y firma.
    if not isinstance(sobre, dict) or sobre.keys() != {"mensaje", "firma"}:
        raise ValueError("Formato de justificante incorrecto.")
    #Comprueba que ambos valores sean str.
    if not all(isinstance(valor, str) for valor in sobre.values()):
        raise ValueError("Codificación de justificante incorrecta.")

    #En el JSON, el mensaje y la firma están escritos como texto Base64.
    #se usa para poder guardar la firma en el JSON, ya que no puede guardar bytes directamente (generada por RSA).
    #Los decodificamos para recuperar los bytes originales antes de verificar la firma.
    mensaje = decodificar(sobre["mensaje"])
    firma = decodificar(sobre["firma"])

    #Comprueba la firma con la clave pública y los mismos datos que firmó el centro. Si cambia el mensaje, la comprobación fallará.
    #Usamos el mismo contexto que al firmar, que indica el tipo de documento.
    #El método .verify() de cryptography recibe:
    #1.firma: los bytes de la firma recuperados del justificante. (con la publica y la firma recupero el bloque PSS)
    #2.CONTEXTO_FIRMA + mensaje: los datos exactos que firmó el centro.
    #3.PSS (como interpreto el bloque): la misma configuración de máscara y salt que se usó al firmar.
    #4.SHA256(): la función que calcula el resumen de los datos del punto 2.
    #Si la firma no coincide, verify lanza InvalidSignature y la función se detiene.
    publica.verify(firma, CONTEXTO_FIRMA + mensaje, PSS, hashes.SHA256())

    #Si la firma es válida, lee el mensaje y comprueba que sea un diccionario con exactamente los campos id, pista, fecha y hora antes de devolverlo.
    reserva = json.loads(mensaje)
    if not isinstance(reserva, dict) or reserva.keys() != {"id", "pista", "fecha", "hora"}:
        raise ValueError("Formato de reserva incorrecto.")
    return reserva
