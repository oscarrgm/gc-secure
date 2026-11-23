"""Interfaz de consola de G&C Secure."""
import argparse
import getpass
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag

from reservas import (PISTAS, abrir_base, autenticar, disponibles, mis_reservas,
                      registrar, reservar, validar_frase)
from seguridad import (cargar_claves, clave_publica_pem, crear_claves,
                        firmar_justificante, verificar_justificante)

DATOS = Path(__file__).resolve().parent / "datos"


def guardar_nuevo(ruta, contenido):
    with ruta.open("xb") as archivo:
        archivo.write(contenido)


def mostrar(reserva):
    print(f'{reserva["id"]} | {PISTAS[reserva["pista"]]} | '
          f'{reserva["fecha"]} | {reserva["hora"]:02d}:00')


def elegir_pista_y_fecha():
    for numero, pista in PISTAS.items():
        print(f"{numero}. {pista}")
    return int(input("Número de pista: ")), input("Fecha (AAAA-MM-DD): ").strip()


def menu_usuario(db, clave, privada, cuenta_id):
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
        password = getpass.getpass("Contraseña: ")
        try:
            if opcion == "1":
                if password != getpass.getpass("Repite la contraseña: "):
                    raise ValueError("Las contraseñas no coinciden.")
                registrar(db, clave_mac, nombre, password)
                print("Cuenta creada.")
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
    parser = argparse.ArgumentParser(description="G&C Secure | Reservas deportivas")
    parser.add_argument("--datos", type=Path, default=DATOS, help="Directorio de datos")
    comandos = parser.add_subparsers(dest="comando")
    comandos.add_parser("inicializar", help="Genera las claves del sistema")
    exportar = comandos.add_parser("exportar-publica", help="Exporta la clave del centro")
    exportar.add_argument("destino", type=Path)
    verificar = comandos.add_parser("verificar", help="Verifica un justificante")
    verificar.add_argument("justificante", type=Path)
    verificar.add_argument("publica", type=Path, help="Clave pública obtenida del centro")
    args = parser.parse_args()
    ruta_claves = args.datos / "claves.bin"
    ruta_db = args.datos / "reservas.sqlite3"
    try:
        if args.comando == "verificar":
            reserva = verificar_justificante(args.publica.read_bytes(),
                                               args.justificante.read_bytes())
            mostrar(reserva)
            print("Firma válida (RSA-PSS/SHA-256).")
            return 0
        if args.comando == "inicializar":
            if ruta_claves.exists() or ruta_db.exists():
                raise ValueError("Ya existen datos o claves en este directorio.")
            frase = getpass.getpass("Frase de acceso del operador: ")
            validar_frase(frase)
            if frase != getpass.getpass("Repite la frase: "):
                raise ValueError("Las frases no coinciden.")
            args.datos.mkdir(parents=True, exist_ok=True)
            crear_claves(ruta_claves, frase)
            print("Claves generadas. Guarda la frase de acceso en un lugar seguro.")
            return 0
        if not ruta_claves.is_file():
            raise ValueError("No se encuentran las claves. Usa el comando inicializar.")
        clave, privada, clave_mac = cargar_claves(
            ruta_claves, getpass.getpass("Frase del operador: "))
        if args.comando == "exportar-publica":
            guardar_nuevo(args.destino, clave_publica_pem(privada))
            print("Clave pública exportada.")
        else:
            with closing(abrir_base(ruta_db)) as db:
                menu(db, clave, privada, clave_mac)
        return 0
    except InvalidSignature:
        print("Justificante rechazado: firma inválida.", file=sys.stderr)
    except InvalidTag:
        print("Clave no desbloqueada: frase incorrecta o fichero alterado.", file=sys.stderr)
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError) as error:
        print(f"Operación rechazada. {error}", file=sys.stderr)
    except (KeyboardInterrupt, EOFError):
        print("\nOperación interrumpida.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
