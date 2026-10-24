

import os
from functools import wraps

import psycopg2
import psycopg2.sql as sql
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "cambiar en produccion")

# --- Configuración de conexión al Postgres del contenedor ---------
PGHOST = os.environ.get("PGHOST", "10.0.3.35")   # IP del servidor
PGPORT = os.environ.get("PGPORT", "5432")
PGDATABASE = os.environ.get("PGDATABASE", "postgres")


def get_connection(user=None, password=None):
    """Abre una conexión nueva. Si no se pasan credenciales, usa las de sesión."""
    user = user or session.get("pg_user")
    password = password or session.get("pg_pass")
    return psycopg2.connect(
        host=PGHOST, port=PGPORT, dbname=PGDATABASE,
        user=user, password=password, connect_timeout=5,
    )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "pg_user" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ------------------------------------------------------------------ #
# LOGIN / LOGOUT
# ------------------------------------------------------------------ #
@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("tables") if "pg_user" in session else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("usuario", "")
        password = request.form.get("password", "")
        try:
            conn = get_connection(user, password)
            conn.close()
        except psycopg2.OperationalError as e:
            flash(f"No se pudo autenticar contra PostgreSQL: {e}", "error")
            return render_template("login.html")

        session["pg_user"] = user
        session["pg_pass"] = password
        flash(f"Conectado como '{user}'", "success")
        return redirect(url_for("tables"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------ #
# LISTADO DE TABLAS ACCESIBLES
# ------------------------------------------------------------------ #
@app.route("/tables")
@login_required
def tables():
    try:
        conn = get_connection()
        cur = conn.cursor()
        # information_schema sólo muestra lo que el rol conectado puede ver
        cur.execute("""
            SELECT table_schema, table_name
            FROM information_schema.tables
            WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
            ORDER BY table_schema, table_name;
        """)
        rows = cur.fetchall()
        cur.close()
        conn.close()
    except psycopg2.Error as e:
        flash(f"Error consultando tablas: {e}", "error")
        rows = []

    return render_template("tables.html", rows=rows, user=session.get("pg_user"))


# ------------------------------------------------------------------ #
# REGISTROS DE UNA TABLA + DEMO SQL INJECTION
# ------------------------------------------------------------------ #
def tabla_es_accesible(cur, schema, table):
    """Valida que la tabla exista y sea visible para el usuario conectado."""
    cur.execute("""
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = %s AND table_name = %s
    """, (schema, table))
    return cur.fetchone() is not None


@app.route("/table/<schema>/<table>")
@login_required
def table_detail(schema, table):
    modo = request.args.get("modo", "seguro")   # "seguro" o "vulnerable"
    columna = request.args.get("columna", "")
    valor = request.args.get("valor", "")
    error = None
    columnas, filas = [], []

    try:
        conn = get_connection()
        cur = conn.cursor()

        if not tabla_es_accesible(cur, schema, table):
            flash("Esa tabla no existe o no tienes acceso a ella.", "error")
            return redirect(url_for("tables"))

        tabla_ident = sql.Identifier(schema, table)

        if columna and valor:
            if modo == "vulnerable":
                # --- INSEGURO A PROPÓSITO: concatenación directa -------
                # Ejemplo de payload para la demo:
                #   columna = nombre
                #   valor   = ' OR '1'='1
                query = (
                    f'SELECT * FROM "{schema}"."{table}" '
                    f"WHERE \"{columna}\" = '{valor}' LIMIT 200;"
                )
                cur.execute(query)
            else:
                # --- SEGURO: identificador validado + valor parametrizado
                if columna not in columnas_validas(cur, schema, table):
                    raise ValueError("Columna no válida")
                query = sql.SQL("SELECT * FROM {} WHERE {} = %s LIMIT 200").format(
                    tabla_ident, sql.Identifier(columna)
                )
                cur.execute(query, (valor,))
        else:
            cur.execute(sql.SQL("SELECT * FROM {} LIMIT 200").format(tabla_ident))

        columnas = [desc[0] for desc in cur.description]
        filas = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        error = str(e)

    return render_template(
        "table.html", schema=schema, table=table, columnas=columnas, filas=filas,
        modo=modo, columna=columna, valor=valor, error=error,
    )


def columnas_validas(cur, schema, table):
    cur.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_schema = %s AND table_name = %s
    """, (schema, table))
    return {r[0] for r in cur.fetchall()}


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
