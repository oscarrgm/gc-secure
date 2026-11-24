"""Interfaz de consola de G&C Secure."""
import getpass
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag

from reservas import (PISTAS, abrir_base, autenticar, disponibles, mis_reservas,
                      registrar, reservar)
from seguridad import (cargar_claves, clave_publica_pem, crear_claves,
                        firmar_justificante, validar_password, verificar_justificante)

# Si no se indica --datos, se usa la carpeta datos junto a main.py.
DATOS = Path(__file__).resolve().parent / "datos"
USO = """G&C Secure | Reservas deportivas

Uso:
  main.py [--datos CARPETA]
  main.py [--datos CARPETA] inicializar
  main.py [--datos CARPETA] exportar-publica DESTINO
  main.py [--datos CARPETA] verificar JUSTIFICANTE CLAVE_PUBLICA

Si omites --datos, se usa la carpeta datos junto a main.py.
"""


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


def guardar_nuevo(ruta, contenido):
    # "xb" escribe bytes y falla si el archivo ya existe.
    with ruta.open("xb") as archivo:
        archivo.write(contenido)


def mostrar(reserva):
    # El catálogo da el nombre de la pista; :02d muestra la hora con dos cifras.
    print(f'{reserva["id"]} | {PISTAS[reserva["pista"]]} | '
          f'{reserva["fecha"]} | {reserva["hora"]:02d}:00')


def elegir_pista_y_fecha():
    for numero, pista in PISTAS.items():
        print(f"{numero}. {pista}")
    return int(input("Número de pista: ")), input("Fecha (AAAA-MM-DD): ").strip()


def menu_usuario(db, clave, privada, cuenta_id):
    # El ID de la sesión identifica al titular de las reservas.
    while True:
        print("\n1. Ver disponibilidad y reservar\n2. Mis reservas\n"
              "3. Exportar justificante\n0. Cerrar sesión")
        opcion = input("> ").strip()
        try:
            if opcion == "0":
                return
            if opcion == "1":
                pista, fecha = elegir_pista_y_fecha()
                horas = disponibles(db, clave, pista, fecha)
                if not horas:
                    print("No hay franjas disponibles.")
                    continue
                print("Disponibles:", ", ".join(f"{hora:02d}:00" for hora in horas))
                entrada = input("Hora de inicio (HH) o Enter para volver: ").strip()
                if entrada:
                    reserva = reservar(db, clave, cuenta_id, pista, fecha, int(entrada))
                    print("Reserva guardada y cifrada con AES-128-GCM.")
                    mostrar(reserva)
            elif opcion in {"2", "3"}:
                # Consultar y exportar parten de la misma lista de reservas propias.
                reservas = mis_reservas(db, clave, cuenta_id)
                if not reservas:
                    print("No tienes reservas.")
                    continue
                print("Etiquetas AES-GCM verificadas.")
                for numero, reserva in enumerate(reservas, 1):
                    print(f"{numero}. ", end="")
                    mostrar(reserva)
                if opcion == "3":
                    numero = int(input("Número de reserva: "))
                    if not 1 <= numero <= len(reservas):
                        raise ValueError("Número de reserva inválido.")
                    # La lista visible empieza en 1; los índices de Python empiezan en 0.
                    reserva = reservas[numero - 1]
                    ruta = Path(input("Ruta para guardar el justificante: ").strip())
                    guardar_nuevo(ruta, firmar_justificante(privada, reserva))
                    print(f"Justificante firmado (RSA-PSS-2048/SHA-256): {ruta}")
            else:
                print("Opción no válida.")
        except InvalidTag:
            print("Datos rechazados: falló la comprobación AES-GCM.", file=sys.stderr)
        except FileExistsError:
            print("El archivo de destino ya existe.")
        except (ValueError, OSError, sqlite3.Error) as error:
            print(f"No se pudo completar la operación. {error}", file=sys.stderr)


def menu(db, clave, privada, clave_mac):
    # Menú de entrada. Al cerrar sesión se vuelve aquí.
    while True:
        print("\nG&C Secure | Reservas deportivas\n"
              "1. Registrarse\n2. Iniciar sesión\n0. Salir")
        opcion = input("> ").strip()
        if opcion == "0":
            return
        if opcion not in {"1", "2"}:
            print("Opción no válida.")
            continue
        nombre = input("Usuario: ").strip()
        # getpass lee la contraseña sin mostrarla en la terminal.
        password = getpass.getpass("Contraseña: ")
        try:
            if opcion == "1":
                if password != getpass.getpass("Repite la contraseña: "):
                    raise ValueError("Las contraseñas no coinciden.")
                registrar(db, clave_mac, nombre, password)
                print("Cuenta creada.")
            # := guarda el resultado de autenticar y comprueba si da acceso.
            elif cuenta_id := autenticar(db, clave_mac, nombre, password):
                del password
                menu_usuario(db, clave, privada, cuenta_id)
            else:
                print("Credenciales incorrectas.")
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
            #Cada directorio se prepara una vez para conservar las claves y sus datos.
            if ruta_claves.exists() or ruta_db.exists():
                raise ValueError("Ya existen datos o claves en este directorio.") #Falla si intenta inicializar en un directorio que ya tiene claves o base de datos.

            #Lee la contraseña del operador sin mostrarla en la terminal.
            password_operador = getpass.getpass("Contraseña de acceso del operador: ")
            #Reutiliza los mismos requisitos que al crear una cuenta de usuario.
            validar_password(password_operador)
            #Pide escribirla otra vez para detectar errores al teclear
            if password_operador != getpass.getpass("Repite la contraseña: "):
                raise ValueError("Las contraseñas no coinciden.")

            #Creamos la carpeta donde guardaremos las claves y la base de datos
            #parents=True crea también los directorios padres si no existen, exist_ok=True evita error si ya existe.
            carpeta.mkdir(parents=True, exist_ok=True)

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
            # El justificante JSON se exporta por separado desde el menú de usuario.
            guardar_nuevo(archivos[0], clave_publica_pem(privada))
            print("Clave pública exportada.")
        else:
            # closing cierra la conexión de SQLite al salir del menú.
            with closing(abrir_base(ruta_db)) as db:
                menu(db, clave, privada, clave_mac)
        return 0
    except InvalidSignature:
        print("Justificante rechazado: firma inválida.", file=sys.stderr)
    except InvalidTag:
        print("Clave no desbloqueada: contraseña incorrecta o fichero alterado.", file=sys.stderr)
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError) as error:
        print(f"Operación rechazada. {error}", file=sys.stderr)
    except (KeyboardInterrupt, EOFError):
        print("\nOperación interrumpida.", file=sys.stderr)
    return 1


# Al lanzar main.py directamente, ejecuta main y devuelve su código a la terminal.
if __name__ == "__main__":
    sys.exit(main())
