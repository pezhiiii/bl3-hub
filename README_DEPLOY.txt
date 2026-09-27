BL3 HUB V5.0 — Deploy Ready

Files:
- app.py
- requirements.txt
- Procfile

IMPORTANT ENVIRONMENT VARIABLES
1) BL3_SECRET_KEY
   Use a long random secret. Do not reuse your wallet seed/private key.
2) BL3_DB_PATH
   Point this to a persistent disk/volume path on your host.
   Example: /data/bl3.db
3) PORT
   Usually set automatically by the hosting platform.

IMPORTANT DATABASE NOTE
SQLite must live on persistent storage. If the host uses an ephemeral filesystem,
the database may reset after redeploy/restart.

LOCAL TEST
pip install -r requirements.txt
python app.py

PRODUCTION START
gunicorn app:app
