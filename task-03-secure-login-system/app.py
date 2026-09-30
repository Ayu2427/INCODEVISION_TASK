import os,secrets,sqlite3,time
from pathlib import Path
from flask import Flask,flash,redirect,render_template,request,session,url_for
from werkzeug.security import check_password_hash,generate_password_hash

BASE=Path(__file__).resolve().parent; DB=BASE/"data"/"users.db"
app=Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get("SECRET_KEY",secrets.token_hex(32)),SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE="Lax",SESSION_COOKIE_SECURE=False,MAX_CONTENT_LENGTH=16*1024)
MAX_FAILED=5; LOCK_SECONDS=60; IP_WINDOW=60; IP_MAX_ATTEMPTS=15; ip_attempts={}

def db():
    DB.parent.mkdir(exist_ok=True); c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def init_db():
    with db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0)")
def csrf_token():
    t=session.get("_csrf")
    if not t: t=secrets.token_urlsafe(32); session["_csrf"]=t
    return t
def valid_csrf(): return secrets.compare_digest(request.form.get("_csrf",""),session.get("_csrf",""))
def rate_limited(ip):
    now=time.time(); b=[t for t in ip_attempts.get(ip,[]) if now-t<IP_WINDOW]
    if len(b)>=IP_MAX_ATTEMPTS: ip_attempts[ip]=b; return True
    b.append(now); ip_attempts[ip]=b; return False
def password_ok(p):
    return len(p)>=12 and any(c.islower() for c in p) and any(c.isupper() for c in p) and any(c.isdigit() for c in p) and any(not c.isalnum() for c in p)

@app.context_processor
def inject_csrf(): return {"csrf_token":csrf_token()}
@app.after_request
def security_headers(r):
    r.headers["X-Content-Type-Options"]="nosniff"; r.headers["X-Frame-Options"]="DENY"; r.headers["Referrer-Policy"]="no-referrer"; r.headers["Cache-Control"]="no-store"; r.headers["Content-Security-Policy"]="default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'"; return r

@app.route("/")
def index(): return redirect(url_for("dashboard" if session.get("user") else "login"))

@app.route("/register",methods=["GET","POST"])
def register():
    if request.method=="POST":
        if not valid_csrf(): return "Invalid CSRF token",400
        u=request.form.get("username","").strip().lower(); p=request.form.get("password","")
        if not(3<=len(u)<=32) or not u.replace("_","").isalnum(): flash("Choose a valid username."); return render_template("register.html")
        if not password_ok(p): flash("Password must be 12+ characters and include upper, lower, number and symbol."); return render_template("register.html")
        try:
            with db() as c: c.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",(u,generate_password_hash(p)))
            flash("Registration successful. You can now log in."); return redirect(url_for("login"))
        except sqlite3.IntegrityError: flash("Registration could not be completed.")
    return render_template("register.html")

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        if not valid_csrf(): return "Invalid CSRF token",400
        if rate_limited(request.remote_addr or "unknown"): flash("Too many login requests. Try again later."); return render_template("login.html"),429
        u=request.form.get("username","").strip().lower(); p=request.form.get("password","")
        with db() as c:
            user=c.execute("SELECT * FROM users WHERE username=?",(u,)).fetchone(); now=time.time(); valid=False
            if user and user["locked_until"]<=now: valid=check_password_hash(user["password_hash"],p)
            if valid:
                c.execute("UPDATE users SET failed_attempts=0,locked_until=0 WHERE id=?",(user["id"],)); session.clear(); session["user"]=u; csrf_token(); return redirect(url_for("dashboard"))
            if user:
                failed=user["failed_attempts"]+1; lock=now+LOCK_SECONDS if failed>=MAX_FAILED else 0
                c.execute("UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?",(0 if lock else failed,lock,user["id"]))
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if not session.get("user"): return redirect(url_for("login"))
    return render_template("dashboard.html",username=session["user"])
@app.route("/logout",methods=["POST"])
def logout():
    if not valid_csrf(): return "Invalid CSRF token",400
    session.clear(); return redirect(url_for("login"))
if __name__=="__main__": init_db(); app.run(host="127.0.0.1",port=5000,debug=False)
