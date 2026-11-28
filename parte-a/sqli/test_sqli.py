"""
Validación automática de la corrección de SQL Injection en /search.

Uso (desde la raíz del repositorio, con el entorno virtual activo):
    python parte-a/sqli/test_sqli.py

Usa el cliente de pruebas de Flask: no hace falta tener la app corriendo.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app import app  # noqa: E402

ATAQUES = [
    "'",
    "zzz' OR 1=1--",
    "zzz' UNION SELECT id, username, role, password_hash FROM users--",
    "zzz' UNION SELECT id, delivery_address, user_id, total FROM orders--",
    "zzz' UNION SELECT 1, name, 2, type FROM sqlite_master WHERE type='table'--",
]


class PruebasSQLi(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def buscar(self, q):
        return self.client.get("/search", query_string={"q": q}).get_data(as_text=True)

    def test_busqueda_normal_sigue_funcionando(self):
        html = self.buscar("SUV")
        self.assertIn("SUV Familiar GT", html)

    def test_busqueda_vacia_muestra_todo_el_catalogo(self):
        self.assertEqual(self.buscar("").count("<tr><td>"), 8)

    def test_ataques_no_devuelven_datos(self):
        for ataque in ATAQUES:
            with self.subTest(ataque=ataque):
                html = self.buscar(ataque)
                self.assertIn("Sin resultados", html)
                self.assertNotIn("Error en la consulta", html)
                self.assertNotIn("scrypt:", html)
                self.assertNotIn("dirección ficticia", html)

    def test_comodines_like_se_tratan_como_texto(self):
        self.assertIn("Sin resultados", self.buscar("%"))
        self.assertIn("Sin resultados", self.buscar("_"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
