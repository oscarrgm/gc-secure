import io
import json
import secrets
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature, InvalidTag

import main
from usuarios_reservas import abrir_base, autenticar, disponibles, mis_reservas, registrar, reservar
from seguridad import (cargar_claves, clave_publica_pem, codificar, crear_claves,
                        decodificar, firmar_justificante, verificar_justificante)


# Cada prueba recibe su propia base temporal y se limpia al acabar.
class PracticaTest(unittest.TestCase):
    def setUp(self):
        temporal = tempfile.TemporaryDirectory()
        self.addCleanup(temporal.cleanup)
        self.ruta = Path(temporal.name)
        self.db = abrir_base(self.ruta / "reservas.sqlite3")
        self.addCleanup(self.db.close)
        self.fecha = (date.today() + timedelta(days=1)).isoformat()
        self.password = "Ejemplo ficticio 42"
        self.clave = bytes(range(16))
        self.clave_mac = secrets.token_bytes(32)

    def test_registro_y_autenticacion(self):
        for debil in ("Corta1", " " * 12, "Sin numero alguno", "sin mayusculas 42",
                      "SIN MINUSCULAS 42"):
            with self.subTest(password=debil), self.assertRaises(ValueError):
                registrar(self.db, self.clave_mac, "ana", debil)
        for nombre in ("ana", "luis"):
            registrar(self.db, self.clave_mac, nombre, self.password)
        cuentas = self.db.execute("SELECT salt, verificador FROM usuarios").fetchall()
        self.assertNotEqual(cuentas[0]["salt"], cuentas[1]["salt"])
        self.assertNotEqual(cuentas[0]["verificador"], cuentas[1]["verificador"])
        self.assertTrue(autenticar(self.db, self.clave_mac, "ana", self.password))
        self.assertFalse(autenticar(self.db, self.clave_mac, "ana", "incorrecta"))
        self.assertFalse(autenticar(self.db, self.clave_mac, "nadie", self.password))
        with self.assertRaises(ValueError):
            registrar(self.db, self.clave_mac, "ana", self.password)

    def test_manipulacion_y_recreacion_de_cuenta(self):
        registrar(self.db, self.clave_mac, "ana", self.password)
        titular = autenticar(self.db, self.clave_mac, "ana", self.password)
        reservar(self.db, self.clave, titular, 2, self.fecha, 18)
        with self.db:
            self.db.execute("UPDATE usuarios SET verificador = zeroblob(32)")
        with self.assertRaises(InvalidTag):
            autenticar(self.db, self.clave_mac, "ana", self.password)
        with self.db:
            self.db.execute("DELETE FROM usuarios")
        registrar(self.db, self.clave_mac, "ana", self.password)
        titular_nuevo = autenticar(self.db, self.clave_mac, "ana", self.password)
        self.assertNotEqual(titular, titular_nuevo)
        self.assertEqual(mis_reservas(self.db, self.clave, titular_nuevo), [])

    def test_disponibilidad_y_titular(self):
        datos = reservar(self.db, self.clave, "ana", 2, self.fecha, 18)
        self.assertNotIn(18, disponibles(self.db, self.clave, 2, self.fecha))
        self.assertEqual(mis_reservas(self.db, self.clave, "ana"), [datos])
        self.assertEqual(mis_reservas(self.db, self.clave, "luis"), [])
        with self.assertRaises(ValueError):
            reservar(self.db, self.clave, "luis", 2, self.fecha, 18)
        with self.assertRaises(InvalidTag):
            mis_reservas(self.db, bytes(16), "ana")

    def test_cifrado_y_metadatos_alterados(self):
        # Cambia por separado el texto cifrado, la etiqueta y un campo visible.
        reservar(self.db, self.clave, "ana", 2, self.fecha, 18)
        legitimo = self.db.execute("SELECT titular_cifrado FROM reservas").fetchone()[0]
        for indice in (0, -1):
            alterado = bytearray(legitimo)
            alterado[indice] ^= 1
            with self.db:
                self.db.execute("UPDATE reservas SET titular_cifrado = ?", (alterado,))
            with self.assertRaises(InvalidTag):
                mis_reservas(self.db, self.clave, "ana")
        with self.db:
            self.db.execute("UPDATE reservas SET titular_cifrado = ?, hora = 19", (legitimo,))
        with self.assertRaises(InvalidTag):
            disponibles(self.db, self.clave, 2, self.fecha)

    def test_colision_de_nonce(self):
        # Fuerza que el generador entregue dos veces el mismo nonce.
        primero, segundo = b"a" * 12, b"b" * 12
        with patch("usuarios_reservas.secrets.token_bytes", side_effect=[primero, primero, segundo]):
            reservar(self.db, self.clave, "ana", 2, self.fecha, 18)
            reservar(self.db, self.clave, "ana", 2, self.fecha, 19)
        self.assertEqual(len(mis_reservas(self.db, self.clave, "ana")), 2)
        self.assertEqual({r[0] for r in self.db.execute("SELECT nonce FROM reservas")},
                         {primero, segundo})

    def test_claves_y_firma(self):
        archivo = self.ruta / "claves.bin"
        crear_claves(archivo, self.password)
        clave, privada, _ = cargar_claves(archivo, self.password)
        with self.assertRaises(InvalidTag):
            cargar_claves(archivo, "incorrecta")
        original = archivo.read_bytes()
        archivo.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaises(InvalidTag):
            cargar_claves(archivo, self.password)
        self.assertNotIn(b"PRIVATE KEY", original)
        datos = reservar(self.db, clave, "ana", 2, self.fecha, 18)
        documento = firmar_justificante(privada, datos)
        publica = clave_publica_pem(privada)
        for _ in range(2):
            self.assertEqual(verificar_justificante(publica, documento), datos)
        self.assertEqual(len(mis_reservas(self.db, clave, "ana")), 1)
        for campo in ("mensaje", "firma"):
            sobre = json.loads(documento)
            modificado = bytearray(decodificar(sobre[campo]))
            modificado[0] ^= 1
            sobre[campo] = codificar(modificado)
            with self.assertRaises(InvalidSignature):
                verificar_justificante(publica, json.dumps(sobre))

    def test_flujo_de_consola_con_reinicio(self):
        # Simula entradas de terminal y vuelve a abrir el mismo directorio.
        datos = self.ruta / "datos_cli"
        doc = self.ruta / "justificante.json"
        pub = self.ruta / "centro.pem"

        def ejecutar(argumentos, entradas=(), secretos=()):
            salida = io.StringIO()
            with (patch("sys.argv", ["main.py", "--datos", str(datos), *argumentos]),
                  patch("builtins.input", side_effect=entradas),
                  patch("main.getpass.getpass", side_effect=secretos),
                  redirect_stdout(salida), redirect_stderr(salida)):
                codigo = main.main()
            return codigo, salida.getvalue()

        self.assertEqual(ejecutar(["inicializar"], secretos=[self.password] * 2)[0], 0)
        codigo, salida = ejecutar([], ["1", "ana", "2", "ana", "1", "2",
                                        self.fecha, "18", "0", "0"], [self.password] * 4)
        self.assertEqual(codigo, 0)
        self.assertIn("Reserva guardada", salida)
        codigo, salida = ejecutar([], ["2", "ana", "3", "1", str(doc), "0", "0"],
                                   [self.password] * 2)
        self.assertEqual(codigo, 0)
        self.assertIn("Justificante firmado", salida)
        self.assertEqual(ejecutar(["exportar-publica", str(pub)],
                                  secretos=[self.password])[0], 0)
        codigo, salida = ejecutar(["verificar", str(doc), str(pub)])
        self.assertEqual(codigo, 0)
        self.assertIn("Firma válida", salida)
        sobre = json.loads(doc.read_bytes())
        sobre["firma"] = codificar(bytes(256))
        doc.write_text(json.dumps(sobre), encoding="utf-8")
        codigo, salida = ejecutar(["verificar", str(doc), str(pub)])
        self.assertEqual(codigo, 1)
        self.assertIn("firma inválida", salida)


if __name__ == "__main__":
    unittest.main()
