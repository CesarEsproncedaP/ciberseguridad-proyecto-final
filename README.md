# Proyecto final de Ciberseguridad: laboratorio Flask

Aplicación de laboratorio en Python y Flask (portal de clientes de una agencia de autos ficticia).
**Contiene vulnerabilidades intencionales** para practicar su identificación y corrección.
Úsala solo en `localhost` y con datos ficticios.

## Cómo ejecutarla (Windows, PowerShell)
```
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
Abre http://127.0.0.1:5000.

### Con Docker (alternativa)
```
docker compose up --build
```
Luego abre http://127.0.0.1:5000. El puerto solo se publica en localhost. La base de datos (`lab.db`) se crea sola la primera vez
y los eventos de seguridad se guardan en `app.log`.

Las cuentas de laboratorio son ficticias y están definidas en `init_db.py`.

## Estructura
- `app.py`: aplicación Flask.
- `init_db.py`: crea la base de datos con datos ficticios.
- `templates/`: plantillas HTML.
- `parte-a/`: correcciones y evidencias de SQL Injection, XSS e IDOR/BOLA.
- `parte-b/`: mejora de seguridad para la organización (DAuto).
