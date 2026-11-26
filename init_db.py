"""Crea la base de datos de laboratorio con datos ficticios."""
import os
import sqlite3

from werkzeug.security import generate_password_hash

# Cuentas ficticias solo para el laboratorio local
USUARIOS = [
    ("alice", "alice123", "user"),
    ("bob", "bob123", "user"),
    ("admin", "admin123", "admin"),
]

VEHICULOS = [
    ("Sedán Compacto LX", 2022, 289000, "Sedán económico, ideal para la ciudad."),
    ("SUV Familiar GT", 2023, 459000, "SUV de 7 plazas con amplio espacio de carga."),
    ("Pickup Trabajo 4x4", 2021, 520000, "Pickup de doble cabina con tracción 4x4."),
    ("Hatchback Urbano", 2020, 215000, "Hatchback ágil y de bajo consumo."),
    ("Sedán Ejecutivo", 2023, 610000, "Sedán de lujo con interior de piel."),
    ("Crossover Sport", 2022, 398000, "Crossover con motor turbo y rines deportivos."),
    ("Eléctrico City", 2024, 575000, "Auto eléctrico con 400 km de autonomía."),
    ("Van Pasajeros", 2021, 480000, "Van de 12 pasajeros para transporte."),
]

# (usuario, vehículo, total, dirección ficticia, estatus)
PEDIDOS = [
    ("alice", 1, 289000, "Calle Falsa 123, Monterrey (dirección ficticia)", "Entregado"),
    ("alice", 7, 575000, "Calle Falsa 123, Monterrey (dirección ficticia)", "En trámite"),
    ("bob", 3, 520000, "Avenida Inventada 456, San Pedro (dirección ficticia)", "Financiamiento aprobado"),
    ("bob", 5, 610000, "Avenida Inventada 456, San Pedro (dirección ficticia)", "En trámite"),
]

RESENAS = [
    (1, "alice", "Muy buen auto para la ciudad."),
    (2, "bob", "Espacioso, lo recomiendo para la familia."),
]


def create_db(path):
    if os.path.exists(path):
        os.remove(path)
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        );
        CREATE TABLE vehicles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            year INTEGER NOT NULL,
            price INTEGER NOT NULL,
            description TEXT NOT NULL
        );
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            vehicle_id INTEGER NOT NULL,
            total INTEGER NOT NULL,
            delivery_address TEXT NOT NULL,
            status TEXT NOT NULL
        );
        CREATE TABLE reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vehicle_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            comment TEXT NOT NULL
        );
        """
    )
    for username, password, role in USUARIOS:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )
    for v in VEHICULOS:
        db.execute("INSERT INTO vehicles (name, year, price, description) VALUES (?, ?, ?, ?)", v)
    ids = {u: i + 1 for i, (u, _, _) in enumerate(USUARIOS)}
    for user, vehicle, total, addr, status in PEDIDOS:
        db.execute(
            "INSERT INTO orders (user_id, vehicle_id, total, delivery_address, status) VALUES (?, ?, ?, ?, ?)",
            (ids[user], vehicle, total, addr, status),
        )
    for vehicle, user, comment in RESENAS:
        db.execute(
            "INSERT INTO reviews (vehicle_id, user_id, comment) VALUES (?, ?, ?)",
            (vehicle, ids[user], comment),
        )
    db.commit()
    db.close()


if __name__ == "__main__":
    ruta = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab.db")
    create_db(ruta)
    print("Base de datos de laboratorio creada:", ruta)
