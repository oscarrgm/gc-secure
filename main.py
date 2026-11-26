"""Interfaz de consola de G&C Secure."""
import csv
import getpass
import os
import sqlite3
import subprocess
import sys
from contextlib import closing, suppress
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag

from usuarios_reservas import (PISTAS, abrir_base, autenticar, disponibles,
                               mis_reservas, registrar, reservar)
from seguridad import (cargar_claves, clave_publica_pem, crear_claves,
                        firmar_justificante, validar_password, verificar_justificante)

#Si no se indica --datos, se usa la carpeta datos junto a main.py.
DATOS = Path(__file__).resolve().parent / "datos"

#Mensaje de uso que se muestra al pedir ayuda o al dar argumentos incorrectos.
USO = """G&C Secure | Reservas deportivas

Uso:
  main.py [--datos CARPETA]
  main.py [--datos CARPETA] inicializar
  main.py [--datos CARPETA] exportar-publica DESTINO
  main.py [--datos CARPETA] verificar JUSTIFICANTE CLAVE_PUBLICA

Si omites --datos, se usa la carpeta datos junto a main.py.
Al inicializar, se crea una carpeta nueva con permisos restringidos.
Al exportar la clave pública, se añade .pem al destino si falta.
"""

#Lee los argumentos de la línea de comandos y devuelve la carpeta de datos, el comando y las rutas de archivo como objetos Path.
def leer_argumentos(argumentos):
    # La carpeta de datos por defecto es "datos" junto a main.py., en caso de que no se indique otra.
    carpeta = DATOS
    # --datos elige dónde buscar o guardar claves.bin y reservas.sqlite3. Inicializar prepara esa carpeta y al arrancar se reutiliza la misma.

    if argumentos[:1] == ["--datos"]: #si aparece --datos en la primera posición, se procesa y se elimina de la lista de argumentos
        if len(argumentos) < 2 or argumentos[1].startswith("-"): #verifica que haya un argumento después de --datos y que no sea otro comando
            raise ValueError("Falta la carpeta después de --datos.")
        carpeta = Path(argumentos[1]) #cambio la carpeta de datos a la especificada por el usuario
        argumentos = argumentos[2:] #recorta la lista de argumentos para eliminar --datos y la carpeta especificada

    if not argumentos:
        # Sin comando se abre el menú normal.
        return carpeta, None, []

    #La primera palabra debe ser un comando válido. Un archivo suelto se rechaza (porque se trata como un comando invalido), y las palabras que siguen al comando son sus rutas.
    comando = argumentos[0]
    archivos = argumentos[1:]
    # El diccionario relaciona cada comando con el número de rutas que pide:
    # inicializar: 0, porque el programa decide los nombres internos.
    # exportar-publica: 1, el destino del PEM con la clave pública.
    # verificar: 2, primero el justificante JSON y luego la clave pública PEM.
    cantidades = {"inicializar": 0, "exportar-publica": 1, "verificar": 2}
    if comando not in cantidades:
        raise ValueError(f"Comando desconocido: {comando}.")
    if len(archivos) != cantidades[comando] or any(a.startswith("-") for a in archivos): #si no hay el número correcto de archivos o si alguno empieza con "-", se lanza un error
        raise ValueError(f"Argumentos incorrectos para {comando}.")
    # Devuelve la carpeta (es un path), el comando y las rutas de archivo como objetos Path.
    return carpeta, comando, [Path(archivo) for archivo in archivos]


#Funcion que prepara la carpeta de datos con permisos restringidos
def preparar_carpeta_datos(carpeta):
    #Solo cambiamos los permisos de una carpeta nueva. En sistemas POSIX, 0o700 da acceso al propietario y la carpeta se protege al crearla.
    carpeta = carpeta.absolute()
    carpeta.mkdir(parents=True, mode=0o700)
    if sys.platform != "win32":
        return

    sistema = Path(os.environ["SystemRoot"]) / "System32"
    try:
        # El SID identifica a la cuenta aunque Windows esté en otro idioma.
        identidad = subprocess.run(
            [sistema / "whoami.exe", "/user", "/fo", "csv", "/nh"],
            check=True, capture_output=True,
        ).stdout
        _, sid = next(csv.reader([identidad.decode("ascii", errors="replace").strip()]))
        # Damos acceso al operador, al sistema y a los administradores.
        # Los archivos nuevos heredan estos permisos en lugar de los del directorio padre.
        icacls = sistema / "icacls.exe"
        subprocess.run(
            [icacls, carpeta, "/grant:r", f"*{sid}:(OI)(CI)F",
             "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"],
            check=True, capture_output=True,
        )
        subprocess.run(
            [icacls, carpeta, "/inheritance:r"], check=True, capture_output=True,
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        # Si falla la configuración, aún no se han escrito las claves.
        with suppress(OSError):
            carpeta.rmdir()
        raise OSError("No se pudieron restringir los permisos de la carpeta de datos.") from error


#Escribe el contenido en la ruta indicada, pero falla si el archivo ya existe. Se usa para exportar la clave pública y los justificantes firmados.
def guardar_nuevo(ruta, contenido):
    #"xb" escribe bytes y falla si el archivo ya existe.
    with ruta.open("xb") as archivo:
        archivo.write(contenido)


#Funcion que imprime los datos de una reserva en formato legible. Se usa para mostrar reservas y justificantes.
def mostrar(reserva):
    print(f'{reserva["id"]} | {PISTAS[reserva["pista"]]} | '
          f'{reserva["fecha"]} | {reserva["hora"]:02d}:00')

#Da las opciones de las pistas, y pide cual quiere y su fecha
def elegir_pista_y_fecha():
    #Cada item es una pareja como (2, "Tenis")
    #item[0] es el número de la pista e item[1] es su nombre.
    for item in PISTAS.items():
        print(f"{item[0]}. {item[1]}")
    #Pide al usuario y devuelve el número de pista como entero y la fecha como texto.
    return int(input("Número de pista: ")), input("Fecha (AAAA-MM-DD): ").strip()

#Menú que se muestra tras iniciar sesión.
#Permite ver disponibilidad, reservar, consultar reservas y exportar justificantes.
def menu_usuario(db, clave, privada, cuenta_id):
    while True:
        #Muestra las opciones
        print("\n1. Ver disponibilidad y reservar\n2. Mis reservas\n"
              "3. Exportar justificante\n0. Cerrar sesión")
        #Pide el input del usuario y elimina los espacios de los extremos
        opcion = input("> ").strip()

        try:
            #Opción para cerrar sesión y volver al menú principal
            if opcion == "0":
                return

            #Opción para ver disponibilidad y reservar
            if opcion == "1":
                pista, fecha = elegir_pista_y_fecha()
                #Busca las horas disponibles para la pista y fecha indicadas, usando la función disponibles de usuarios_reservas.py
                horas = disponibles(db, clave, pista, fecha)
                #Imprime las horas disponibles en formato HH:00, o un mensaje si no hay ninguna.
                if not horas:
                    print("No hay franjas disponibles.")
                    #Vuelve a mostrar el menú de usuario
                    continue

                #Imprime todas las horas disponibles en una sola línea, separadas por comas.
                print("Disponibles:", ", ".join(f"{hora:02d}:00" for hora in horas))
                #Pregunta la hora de inicio de la reserva, o permite volver al menú si se pulsa Enter sin escribir nada.
                entrada = input("Hora de inicio (HH) o Enter para volver: ").strip()
                #Si introduce una hora, se llama a reservar para guardar la reserva en la base de datos.
                if entrada:
                    #Se mete la reserva en la base de datos y se devuelve un diccionario con los datos visibles de la reserva.
                    reserva = reservar(db, clave, cuenta_id, pista, fecha, int(entrada))
                    print("Reserva guardada y cifrada con AES-128-GCM.")
                    mostrar(reserva)

            #Opción para consultar y exportar justificantes de reservas propias
            elif opcion in {"2", "3"}:
                #Consultar y exportar parten de la misma lista de reservas propias.
                reservas = mis_reservas(db, clave, cuenta_id)
                if not reservas:
                    print("No tienes reservas.")
                    continue
                print("Etiquetas AES-GCM verificadas.")

                #La lista del menú se numera desde 1 para que puedas elegir una reserva.
                numero = 1
                #Se imprimen todas las reservas
                for reserva in reservas:
                    print(f"{numero}. ", end="")
                    mostrar(reserva)
                    numero += 1

                #Si la opcion es exportar justificante, es el mismo proceso, y luego pide el número de reserva y la ruta donde guardar el justificante firmado.
                if opcion == "3":
                    numero = int(input("Número de reserva: "))
                    #Se comprueba que el número de reserva sea válido
                    if not 1 <= numero <= len(reservas):
                        raise ValueError("Número de reserva inválido.")

                    #La lista visible empieza en 1; los índices de Python empiezan en 0.
                    reserva = reservas[numero - 1]
                    #Se pregunta la ruta donde guardar el justificante firmado
                    ruta = Path(input("Ruta para guardar el justificante: ").strip())
                    #Se llama a firmar_justificante para firmar la reserva con la clave privada RSA y se guarda en la ruta indicada. Si el archivo ya existe, guardar_nuevo lanza un error.
                    guardar_nuevo(ruta, firmar_justificante(privada, reserva))
                    #Si todo va bien, se muestra un mensaje indicando que el justificante se ha firmado y guardado correctamente.
                    print(f"Justificante firmado (RSA-PSS-2048/SHA-256): {ruta}")
            else:
                print("Opción no válida.")
        #Errores
        except InvalidTag:
            print("Datos rechazados: falló la comprobación AES-GCM.", file=sys.stderr)
        except FileExistsError:
            print("El archivo de destino ya existe.")
        except (ValueError, OSError, sqlite3.Error) as error:
            print(f"No se pudo completar la operación. {error}", file=sys.stderr)


#Menú tras abrir el sistema con la contraseña del operador
def menu(db, clave, privada, clave_mac):
    #Menú de entrada. Al cerrar sesión se vuelve aquí.
    while True:
        print("\nG&C Secure | Reservas deportivas\n"
              "1. Registrarse\n2. Iniciar sesión\n0. Salir")
        #strip quita los espacios de los extremos, Por ejemplo: " 2 " se lee como "2".
        opcion = input("> ").strip()

        #Opcion de salir
        if opcion == "0":
            return

        #Cualquier otro numero que no sea ni 1 ni 2 es invalido
        if opcion not in {"1", "2"}:
            print("Opción no válida.")
            #Vuelve al inicio del bucle para mostrar el menú con las opciones disponibles.
            continue

        #Si eliges registrarse o iniciar sesión, pide el nombre de usuario y la contraseña.
        nombre = input("Usuario: ").strip()
        #getpass lee la contraseña sin mostrarla en la terminal.
        password = getpass.getpass("Contraseña: ")

        try:
            #Si la opción es registrarse, pide repetir la contraseña y llama a registrar.
            if opcion == "1":
                if password != getpass.getpass("Repite la contraseña: "):
                    raise ValueError("Las contraseñas no coinciden.")

            #Dentro de registrar, se valida el nombre y la contraseña, se genera el salt, el ID de la cuenta, el verificador y la etiqueta, y se inserta en la base de datos
                registrar(db, clave_mac, nombre, password)
                print("Cuenta creada.")

            #Opción para iniciar sesión.
            elif opcion == "2":
                cuenta_id = autenticar(db, clave_mac, nombre, password)
                #Si autenticar no devuelve un ID, las credenciales son incorrectas.
                if cuenta_id is None:
                    print("Credenciales incorrectas.")
                #Si autenticar devuelve un ID, se abre el menú de usuario
                else:
                    menu_usuario(db, clave, privada, cuenta_id)

        #Errores
        except InvalidTag:
            print("Cuenta rechazada: falló la comprobación HMAC.", file=sys.stderr)
        except (ValueError, TypeError, sqlite3.Error) as error:
            print(f"No se pudo completar la operación. {error}", file=sys.stderr)


def main():
    # sys.argv[0] es el nombre del programa; solo leemos lo que viene después.
    argumentos = sys.argv[1:]
    # Si se pide ayuda, se muestra el mensaje de uso definido y termina el programa.
    if "-h" in argumentos or "--help" in argumentos:
        print(USO)
        return 0

    try:
        #La función leer_argumentos devuelve la carpeta de datos, el comando y los archivos necesarios.
        carpeta, comando, archivos = leer_argumentos(argumentos)
    except ValueError as error:
        #Muestra el motivo del error y el mensaje de uso en la salida de errores.
        print(f"{error}\n{USO}", file=sys.stderr)
        # 2 indica argumentos incorrectos. Una ejecución correcta devuelve 0.
        return 2

    ruta_claves = carpeta / "claves.bin" #fichero donde se guardan las claves cifradas
    ruta_db = carpeta / "reservas.sqlite3" #fichero donde se guarda la base de datos de reservas

    try:

        if comando == "verificar":
            #Basta unicamente con el justificante y la clave pública, aunque no exista la carpeta de datos.
            justificante, publica = archivos #si habia archivos, se asignan a justificante y publica (clave pública)
            #como publica y justificante son objetos Path, se puede usar read_bytes() para leer su contenido en bytes.
            #llamamos a la función verificar_justificante (en seguridad.py) con el contenido de los archivos y guardamos el resultado en reserva.
            reserva = verificar_justificante(publica.read_bytes(), justificante.read_bytes())
            mostrar(reserva)
            print("Firma válida (RSA-PSS/SHA-256).")
            return 0

        if comando == "inicializar":
            #Una instalación nueva usa una carpeta nueva para proteger sus archivos desde el principio.
            if carpeta.exists():
                raise ValueError("La carpeta de datos ya existe. Elige una nueva con --datos.")

            #Lee la contraseña del operador sin mostrarla en la terminal.
            password_operador = getpass.getpass("Contraseña de acceso del operador: ")
            #Reutiliza los mismos requisitos que al crear una cuenta de usuario.
            validar_password(password_operador)
            #Pide escribirla otra vez para detectar errores al teclear
            if password_operador != getpass.getpass("Repite la contraseña: "):
                raise ValueError("Las contraseñas no coinciden.")

            # Aplicamos los permisos antes de guardar el paquete cifrado.
            preparar_carpeta_datos(carpeta)

            #Creamos las claves y las guardamos en el archivo de claves cifrado con la contraseña del operador.
            crear_claves(ruta_claves, password_operador)
            print("Claves generadas. Guarda la contraseña de acceso en un lugar seguro.")
            return 0

        #Para abrir el menú o exportar la clave pública, claves.bin debe existir y ser un archivo (no solo si existe (por eso no usamos exists())).
        #Lo comprobamos antes de pedir la contraseña del operador.
        if not ruta_claves.is_file():
            raise ValueError("No se encuentran las claves. Usa el comando inicializar.")
        #El menú y la exportación desbloquean primero el archivo de claves.
        password_operador = getpass.getpass("Contraseña de acceso del operador: ")
        #recupera la clave AES, la clave privada RSA y la clave MAC a partir del archivo de claves cifrado con la contraseña del operador.
        clave, privada, clave_mac = cargar_claves(ruta_claves, password_operador)

        if comando == "exportar-publica":
            #Utilizamos la función clave_publica_pem para obtener la clave pública en formato PEM a partir de la clave privada.
            #Luego usamos guardar_nuevo para escribir la clave pública en el archivo destino (debe ser nuevo, ya que así no reemplazamos por accidente la clave pública de otro centro).
            destino = archivos[0]
            #destino.name devuelve el nombre del archivo (sin la ruta). Si no termina en .pem, se añade.
            if destino.name and not destino.name.lower().endswith(".pem"):
                destino = destino.with_name(destino.name + ".pem")
            guardar_nuevo(destino, clave_publica_pem(privada))
            print(f"Clave pública exportada en {destino}.")

        #Si no hay comando, abrimos el menú normal. La base de datos se abre dentro de un bloque with para cerrarla automáticamente al salir del menú.
        else:
            #abrimos la base de datos de reservas con abrir_base y la usamos dentro de un with closing para cerrarla automáticamente al salir del menú
            #guardamos en db la conexión a la base de datos abierta
            with closing(abrir_base(ruta_db)) as db:
                #abrimos el menu principal (el que se ve antes de iniciar sesión o registrarse) con la base de datos, la clave AES, la clave privada RSA y la clave MAC
                menu(db, clave, privada, clave_mac)
        # Si la operación termina correctamente, devolvemos 0 a la terminal.
        return 0

    #Cada except maneja un tipo de error. cryptography lanza InvalidSignature si la firma no es válida e InvalidTag si falla la autenticación de AES-GCM.
    except InvalidSignature:
        print("Justificante rechazado: firma inválida.", file=sys.stderr)
    except InvalidTag:
        print("Clave no desbloqueada: contraseña incorrecta o fichero alterado.", file=sys.stderr)
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError) as error:
        print(f"Operación rechazada. {error}", file=sys.stderr)
    except (KeyboardInterrupt, EOFError):
        print("\nOperación interrumpida.", file=sys.stderr)
    #Tras mostrar el error, devolvemos 1 para indicar que la operación falló.
    return 1


#Al lanzar main.py directamente, ejecuta main y devuelve su código a la terminal:
#0 si termina bien, 1 si falla o se interrumpe, 2 si los argumentos son incorrectos.
if __name__ == "__main__":
    sys.exit(main())
