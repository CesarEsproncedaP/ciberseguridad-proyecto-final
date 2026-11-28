"""
App de laboratorio en Flask para el proyecto final de Ciberseguridad.

ATENCIÓN: contiene vulnerabilidades INTENCIONALES (SQL Injection, XSS
almacenado e IDOR/BOLA) para practicar su identificación y corrección.
Ejecútala SOLO en localhost y con datos ficticios.
"""
import logging
import os
import sqlite3
from functools import wraps

from flask import (Flask, abort, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash

import init_db

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "lab.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "clave-solo-para-laboratorio")

# Registro de eventos (se usa en el análisis de registros)
logging.basicConfig(
    filename=os.path.join(BASE_DIR, "app.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("lab")

if not os.path.exists(DB_PATH):
    init_db.create_db(DB_PATH)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    vehicles = get_db().execute(
        "SELECT id, name, year, price FROM vehicles ORDER BY id"
    ).fetchall()
    return render_template("index.html", vehicles=vehicles)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            log.info("LOGIN_OK user=%s ip=%s", username, request.remote_addr)
            destino = request.args.get("next", "")
            if destino.startswith("/") and not destino.startswith("//"):
                return redirect(destino)
            return redirect(url_for("index"))
        log.warning("LOGIN_FAIL user=%s ip=%s", username, request.remote_addr)
        error = "Usuario o contraseña incorrectos"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    log.info("LOGOUT user=%s", session.get("username"))
    session.clear()
    return redirect(url_for("index"))


@app.route("/search")
def search():
    # Se limita la longitud: ningún nombre de vehículo legítimo pasa de 100 caracteres
    q = request.args.get("q", "")[:100]
    # CORREGIDO (SQL Injection): consulta parametrizada. La entrada viaja como dato
    # (marcador ?), nunca como parte del código SQL. También se escapan los comodines
    # de LIKE (% y _) para que se busquen como texto literal.
    patron = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    sql = "SELECT id, name, year, price FROM vehicles WHERE name LIKE ? ESCAPE '\\'"
    log.info("SEARCH q=%r ip=%s", q, request.remote_addr)
    rows, error = [], None
    try:
        rows = get_db().execute(sql, (patron,)).fetchall()
    except sqlite3.Error as exc:
        error = "Error en la consulta"
        log.error("SEARCH_ERROR q=%r error=%s", q, exc)
    return render_template("search.html", q=q, rows=rows, error=error)


@app.route("/vehicle/<int:vehicle_id>")
def vehicle(vehicle_id):
    db = get_db()
    v = db.execute("SELECT * FROM vehicles WHERE id = ?", (vehicle_id,)).fetchone()
    if v is None:
        abort(404)
    reviews = db.execute(
        "SELECT r.id, r.comment, u.username FROM reviews r "
        "JOIN users u ON u.id = r.user_id WHERE r.vehicle_id = ? ORDER BY r.id",
        (vehicle_id,),
    ).fetchall()
    return render_template("vehicle.html", v=v, reviews=reviews)


@app.route("/vehicle/<int:vehicle_id>/review", methods=["POST"])
@login_required
def add_review(vehicle_id):
    comment = request.form.get("comment", "")
    # VULNERABLE (XSS almacenado): el comentario se guarda y se muestra sin neutralizar
    db = get_db()
    db.execute(
        "INSERT INTO reviews (vehicle_id, user_id, comment) VALUES (?, ?, ?)",
        (vehicle_id, session["user_id"], comment),
    )
    db.commit()
    log.info("REVIEW_ADD user=%s vehicle=%s", session["username"], vehicle_id)
    return redirect(url_for("vehicle", vehicle_id=vehicle_id))


@app.route("/my-orders")
@login_required
def my_orders():
    rows = get_db().execute(
        "SELECT o.id, v.name, o.total, o.status FROM orders o "
        "JOIN vehicles v ON v.id = o.vehicle_id WHERE o.user_id = ? ORDER BY o.id",
        (session["user_id"],),
    ).fetchall()
    return render_template("orders.html", rows=rows)


@app.route("/orders/<int:order_id>")
@login_required
def order_detail(order_id):
    order = get_db().execute(
        "SELECT o.id, o.user_id, o.total, o.delivery_address, o.status, "
        "v.name AS vehicle, u.username AS owner FROM orders o "
        "JOIN vehicles v ON v.id = o.vehicle_id "
        "JOIN users u ON u.id = o.user_id WHERE o.id = ?",
        (order_id,),
    ).fetchone()
    if order is None:
        abort(404)
    # VULNERABLE (IDOR/BOLA): no se comprueba que el pedido pertenezca al usuario de la sesión
    log.info("ORDER_VIEW user=%s order=%s", session["username"], order_id)
    return render_template("order.html", order=order)


@app.errorhandler(403)
def forbidden(e):
    log.warning("ACCESS_DENIED user=%s path=%s", session.get("username"), request.path)
    return render_template("error.html", code=403, msg="Acceso denegado"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, msg="No encontrado"), 404


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=5000, debug=False)
