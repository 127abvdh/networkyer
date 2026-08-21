from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3, secrets, hashlib
from pathlib import Path

app = Flask(__name__, template_folder=".")
app.secret_key = secrets.token_hex(32)
DB = Path("networkyar.db")

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con=db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL, phone TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, ref_code TEXT UNIQUE NOT NULL,
      parent_id INTEGER, balance INTEGER DEFAULT 0,
      card_number TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS withdrawals(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER, amount INTEGER, card_number TEXT,
      status TEXT DEFAULT 'pending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS ad_events(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER, revenue INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    con.commit(); con.close()

init_db()

def hashpw(p): return hashlib.sha256(p.encode()).hexdigest()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        name=request.form["name"].strip()
        phone=request.form["phone"].strip()
        password=request.form["password"]
        ref=request.form.get("ref","").strip()
        parent=None
        con=db()
        if ref:
            row=con.execute("SELECT id FROM users WHERE ref_code=?",(ref,)).fetchone()
            parent=row["id"] if row else None
        code=secrets.token_urlsafe(6).replace("-","").replace("_","")[:8].upper()
        try:
            con.execute("INSERT INTO users(name,phone,password_hash,ref_code,parent_id) VALUES(?,?,?,?,?)",
                        (name,phone,hashpw(password),code,parent))
            con.commit()
            row=con.execute("SELECT id FROM users WHERE phone=?",(phone,)).fetchone()
            session["uid"]=row["id"]
        except sqlite3.IntegrityError:
            con.close()
            return render_template("register.html", error="این شماره قبلاً ثبت شده است.")
        con.close()
        return redirect("/dashboard")
    return render_template("register.html", ref=request.args.get("ref",""))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        con=db()
        row=con.execute("SELECT * FROM users WHERE phone=? AND password_hash=?",
                        (request.form["phone"],hashpw(request.form["password"]))).fetchone()
        con.close()
        if row:
            session["uid"]=row["id"]; return redirect("/dashboard")
        return render_template("login.html", error="اطلاعات ورود نادرست است.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear(); return redirect("/")

def current_user():
    uid=session.get("uid")
    if not uid: return None
    con=db(); row=con.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone(); con.close()
    return row

@app.route("/dashboard")
def dashboard():
    u=current_user()
    if not u: return redirect("/login")
    con=db()
    direct=con.execute("SELECT COUNT(*) n FROM users WHERE parent_id=?",(u["id"],)).fetchone()["n"]
    total=con.execute("""
      WITH RECURSIVE t(id) AS (
        SELECT id FROM users WHERE parent_id=?
        UNION ALL SELECT users.id FROM users JOIN t ON users.parent_id=t.id
      ) SELECT COUNT(*) n FROM t
    """,(u["id"],)).fetchone()["n"]
    withdrawals=con.execute("SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC",(u["id"],)).fetchall()
    con.close()
    return render_template("dashboard.html",u=u,direct=direct,total=total,withdrawals=withdrawals)

@app.route("/withdraw", methods=["POST"])
def withdraw():
    u=current_user()
    if not u: return redirect("/login")
    amount=int(request.form["amount"])
    card=request.form["card"].replace("-","").replace(" ","")
    if amount <= 0 or amount > u["balance"] or len(card)!=16 or not card.isdigit():
        return redirect("/dashboard")
    con=db()
    con.execute("INSERT INTO withdrawals(user_id,amount,card_number) VALUES(?,?,?)",(u["id"],amount,card))
    con.execute("UPDATE users SET balance=balance-?, card_number=? WHERE id=?",(amount,card,u["id"]))
    con.commit(); con.close()
    return redirect("/dashboard")

@app.route("/api/stats")
def stats():
    con=db()
    users=con.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
    con.close()
    return jsonify({"users":users})

if __name__=="__main__":
    init_db()
    app.run(debug=True)
