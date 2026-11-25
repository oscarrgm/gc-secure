# G&C Secure

Aplicación local de consola para reservar pistas deportivas y comprobar justificantes de reserva. Usa Python 3.11 o posterior, SQLite y la versión fijada de `cryptography`.

## Instalar y ejecutar

Abre PowerShell en esta carpeta y ejecuta:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py inicializar
.\.venv\Scripts\python.exe main.py
```

Si usas otra versión de Python compatible, ajusta el argumento de `py`. El primer comando de la aplicación pide una contraseña de acceso del operador y genera el archivo de claves. El menú vuelve a pedir esa contraseña y permite crear cuentas. Para las nuevas contraseñas se piden entre 12 y 128 caracteres, al menos una mayúscula, una minúscula y un dígito. Usa una contraseña de operador distinta de las contraseñas de las cuentas. Las reservas se guardan en `datos/` junto con el archivo de claves cifrado. Para una demostración independiente puedes situar `--datos demo` antes del subcomando o usarlo al abrir el menú.

## Recorrido de demostración

1. Crea dos cuentas ficticias. Intenta entrar con una contraseña incorrecta y, después, con la correcta.
2. Reserva una pista para mañana a las 18:00. Cierra sesión, entra con la segunda cuenta y comprueba que la franja ya no aparece y que esa reserva no figura en «Mis reservas».
3. Vuelve a la cuenta titular y exporta el justificante como `justificante.json`. Cierra la aplicación.
4. Exporta por separado la clave pública del centro y verifica el justificante:

```powershell
.\.venv\Scripts\python.exe main.py exportar-publica centro.pem
.\.venv\Scripts\python.exe main.py verificar justificante.json centro.pem
.\.venv\Scripts\python.exe -m unittest -v
```

Las pruebas modifican copias temporales del texto cifrado, la etiqueta, los datos asociados y la firma. También comprueban la clave y la contraseña incorrectas, la colisión de nonce, la doble reserva y el flujo de consola tras reiniciar. Salir con código 1 indica que el comando no completó la operación.

## Decisiones del programa

- `main.py` contiene el menú y los comandos. `usuarios_reservas.py` controla las cuentas, las franjas y SQLite. `seguridad.py` concentra las operaciones criptográficas.
- El registro almacena un verificador PBKDF2-HMAC-SHA-256 de 32 bytes, con 600 000 iteraciones y una sal aleatoria de 16 bytes por cuenta. Al entrar se vuelve a derivar y se compara en tiempo constante.
- Cada cuenta tiene un ID aleatorio. Un HMAC-SHA-256 autentica el nombre, el ID, la sal y el verificador con una clave aleatoria independiente de 256 bits guardada en el archivo de claves cifrado. Si se altera la cuenta, el inicio de sesión se rechaza. Una nueva cuenta con el mismo nombre recibe un ID distinto y no hereda las reservas.
- AES-128-GCM cifra el identificador del titular y autentica también el ID, la pista, la fecha y la hora de la reserva como datos asociados. El nonce aleatorio de 12 bytes se comprueba antes de cifrar dentro de una transacción SQLite que impide escrituras simultáneas. Los registros se conservan y la base de datos también impone la unicidad del nonce y de la franja. El tag de 16 bytes va al final del texto cifrado, tal como lo devuelve la biblioteca.
- La contraseña del operador se usa con PBKDF2 y una sal propia para obtener una clave AES de 256 bits. Esta clave protege el archivo que contiene la clave AES de reservas y la clave privada RSA. El archivo de claves se crea una vez con un nonce aleatorio y no se reescribe. Las claves se generan localmente y los mensajes de la consola no las muestran.
- El centro firma el contenido exacto del justificante con RSA-PSS de 2048 bits, SHA-256, MGF1 con SHA-256 y una sal PSS de 32 bytes. El verificador recibe la clave pública por separado, sin necesidad de acceder a la base de datos. El documento permite verificar la emisión de la reserva. Verificarlo varias veces es una consulta y no crea reservas ni concede acceso a la pista.

El programa está pensado para un equipo bajo control del operador. Mantén la carpeta de datos bajo una cuenta del sistema con permisos de acceso restringidos y conserva juntos el archivo de claves y la base de datos cuando hagas copias. AES-GCM detecta la alteración de un registro de reserva que sigue presente, pero no impide el borrado ni detecta que se restaure una copia antigua completa. La disponibilidad de las pistas queda visible en la base de datos. Para comprobar quién firmó el justificante, el verificador necesita obtener la clave pública del centro por un canal de confianza.

Se utilizó OpenAI Codex para diseñar e implementar el programa, las pruebas y estas instrucciones.

Si conservas datos creados con el prototipo anterior a la revisión, déjalos en su carpeta y usa un directorio nuevo con `--datos demo` tanto al inicializar como al arrancar. La versión revisada usa identificadores de cuenta y una clave HMAC adicional.
