# PG Explorer — app web de auditoría/consulta sobre PostgreSQL

App Flask mínima que cumple con el enunciado:
- Login = autenticación real contra PostgreSQL (el usuario/contraseña que metes
  son credenciales de un rol de Postgres).
- Lista las tablas a las que ese rol tiene acceso (vía `information_schema`,
  que ya filtra según privilegios).
- Permite ver los registros de una tabla, con un buscador.
- El buscador tiene **dos modos** para la parte de SQL Injection:
  - `vulnerable`: concatena el valor directamente en el SQL → inyectable.
  - `seguro`: usa consultas parametrizadas (`%s` + `psycopg2`) e identificadores
    validados contra `information_schema` → no inyectable.

## 1. Preparar el Postgres del contenedor LXC

Dentro del LXC, en `postgresql.conf`:
```
listen_addresses = '*'
```

En `pg_hba.conf`, añade una línea para permitir conexión desde donde
ejecutes la app Flask (ajusta la subred):
```
host    all             all             192.168.1.0/24          scram-sha-256
```

Reinicia Postgres: `sudo systemctl restart postgresql`.

Verifica el puerto 5432 abierto en el firewall del LXC (si usas `iptables`
o `ufw`) y, si LXC está detrás de un firewall del host, abre también ahí.

Crea un par de roles de prueba con privilegios distintos para que la demo
de "tablas accesibles según el usuario" se note:
```sql
CREATE ROLE lector LOGIN PASSWORD 'lector123';
GRANT CONNECT ON DATABASE tu_bd TO lector;
GRANT SELECT ON TABLE clientes TO lector;   -- sólo ve "clientes"
```

## 2. Configurar la app

Edita las variables de entorno (o los valores por defecto en `app.py`):
```
export PGHOST=192.168.1.100   # IP del contenedor LXC
export PGPORT=5432
export PGDATABASE=tu_bd
```

## 3. Instalar y arrancar

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Abre `http://localhost:5000`.

## 4. Demo de SQL Injection

1. Entra a una tabla, pon una columna de texto (p.ej. `nombre`) y en
   "Valor" escribe: `' OR '1'='1`
2. Con **modo = vulnerable**, la consulta se vuelve
   `... WHERE "nombre" = '' OR '1'='1' LIMIT 200;` y te devuelve TODAS las
   filas, saltándose el filtro (y daría pie a extraer datos arbitrarios).
3. Cambia a **modo = seguro** con el mismo valor: la cadena entera se trata
   como un literal de búsqueda, no como código SQL, así que no hay match
   y no se filtra nada indebido. Captura ambas pantallas para el informe.

### Qué explicar en la memoria de la práctica
- Causa: en modo vulnerable el valor del usuario se concatena directamente
  dentro de la sentencia SQL, así que caracteres como `'` rompen la cadena
  y permiten inyectar lógica SQL arbitraria.
- Solución aplicada: separar código de datos.
  - Los **valores** van siempre como parámetros (`%s` + tupla de valores en
    `cur.execute`), nunca con f-strings/concatenación.
  - Los **identificadores** (nombre de tabla/columna, que no se pueden
    parametrizar con `%s`) se validan contra una lista blanca obtenida de
    `information_schema` y se citan con `psycopg2.sql.Identifier`.
- Con esas dos medidas, el mismo payload que antes devolvía toda la tabla
  ahora no devuelve nada (se busca literalmente el texto `' OR '1'='1`).

## Notas de seguridad (para la memoria, no para producción)
- Las credenciales de Postgres se guardan en la sesión de Flask (server-side)
  sólo para reabrir conexión en cada petición; en un entorno real se usaría
  un pool de conexiones autenticado una vez y un sistema de sesión propio.
- `app.secret_key` debe cambiarse por una clave aleatoria real
  (`export FLASK_SECRET_KEY=...`) y la app debería ejecutarse con
  `debug=False` fuera de desarrollo.
