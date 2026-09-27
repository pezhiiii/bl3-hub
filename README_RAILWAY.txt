BL3 HUB V5.1 — Railway Ready

Railway settings:
- Start Command: gunicorn app:app
- Volume mount path: /data
- BL3_DB_PATH=/data/bl3.db
- BL3_SECRET_KEY=<generate a strong random value locally>

Generate a secret locally:
python -c "import secrets; print(secrets.token_hex(32))"

Do not share BL3_SECRET_KEY, wallet seed phrases, or private keys.

After deployment:
Settings -> Networking -> Generate Domain
