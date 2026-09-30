# Task 03 — Secure Login System with Attack Prevention

Flask authentication demo with defensive controls:
- Werkzeug PBKDF2 password hashing
- No plaintext password storage
- Login attempt tracking and 60-second account lockout after 5 failures
- Per-IP login request limiting
- HttpOnly/SameSite session cookies
- CSRF tokens
- Parameterized SQLite queries
- Password-strength validation
- Generic login errors
- Security response headers
- Logout/session cleanup

## Run
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000.

Set a production SECRET_KEY and use HTTPS before deployment.
