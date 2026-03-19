from flask import Flask, request, redirect, url_for, session, make_response, jsonify, send_file
from io import BytesIO
import os
import time

app = Flask(__name__)
app.secret_key = "123456"  # propositalmente fraca para o lab

# "Banco" fake com senha em texto puro, propositalmente inseguro
USERS = {
    "admin": {
        "password": "admin123",
        "role": "admin",
        "email": "admin@lab.local"
    },
    "filipe": {
        "password": "senha123",
        "role": "user",
        "email": "filipe@lab.local"
    }
}

PRODUCTS = [
    {"id": 1, "name": "Servidor", "price": 5000},
    {"id": 2, "name": "Firewall", "price": 3000},
    {"id": 3, "name": "Notebook", "price": 4200},
]

FAKE_ENV = """
APP_ENV=development
DEBUG=True
SECRET_KEY=123456
DB_HOST=127.0.0.1
DB_USER=admin
DB_PASSWORD=admin123
JWT_SECRET=jwt-lab-secret
"""

INDEX_HTML = """
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8">
  <title>Lab Flask Vulnerável</title>
  <!-- TODO: remover comentários internos -->
  <!-- debug=true -->
  <!-- secret temp token: lab-token-123 -->
</head>
<body>
  <h1>Lab Flask Vulnerável</h1>
  <p>Ambiente local de estudo.</p>

  <ul>
    <li><a href="/login">Login</a></li>
    <li><a href="/admin">Admin</a></li>
    <li><a href="/api/users">API Users</a></li>
    <li><a href="/openapi.json">OpenAPI</a></li>
    <li><a href="/debug">Debug</a></li>
    <li><a href="/upload">Upload</a></li>
    <li><a href="/.env">Arquivo .env</a></li>
  </ul>

  <script>
    // FIXME: remover antes de produção
    const apiKey = "front-lab-key";
  </script>
</body>
</html>
"""

LOGIN_HTML = """
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8">
  <title>Login</title>
</head>
<body>
  <h1>Login do Lab</h1>
  <form method="POST" action="/login">
    <label>Usuário</label><br>
    <input type="text" name="username"><br><br>

    <label>Senha</label><br>
    <input type="password" name="password"><br><br>

    <button type="submit">Entrar</button>
  </form>

  {message}
</body>
</html>
"""

UPLOAD_HTML = """
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8">
  <title>Upload</title>
</head>
<body>
  <h1>Upload do Lab</h1>
  <form method="POST" enctype="multipart/form-data" action="/upload">
    <input type="file" name="file">
    <button type="submit">Enviar</button>
  </form>
  {message}
</body>
</html>
"""

@app.route("/")
def index():
    response = make_response(INDEX_HTML)

    # Cookie propositalmente sem vários atributos fortes
    response.set_cookie("lab_session", "abc123")

    # Header revelando tecnologia
    response.headers["X-Powered-By"] = "Flask-Lab/1.0"

    return response

@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # propositalmente inseguro: loga credenciais no terminal
        print(f"[LAB] Tentativa de login -> usuario={username} senha={password}")

        user = USERS.get(username)
        if user and user["password"] == password:
            session["user"] = username
            session["role"] = user["role"]
            return redirect(url_for("admin"))
        else:
            message = "<p style='color:red'>Credenciais inválidas.</p>"

    return LOGIN_HTML.format(message=message)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/admin")
def admin():
    # propositalmente fraco: qualquer usuário logado entra
    if "user" not in session:
        return "<h1>Acesso negado</h1>", 403

    return f"""
    <h1>Painel Admin</h1>
    <p>Usuário logado: {session.get('user')}</p>
    <p>Role: {session.get('role')}</p>
    <p><a href="/backup.zip">Backup</a></p>
    <p><a href="/dashboard">Dashboard</a></p>
    <p><a href="/logout">Sair</a></p>
    """

@app.route("/dashboard")
def dashboard():
    return """
    <h1>Dashboard</h1>
    <p>Status: OK</p>
    <p>Version: dev-build-2026</p>
    """

@app.route("/api/users")
def api_users():
    # propositalmente devolve dados demais
    return jsonify([
        {
            "username": username,
            "email": data["email"],
            "role": data["role"],
            "password": data["password"]
        }
        for username, data in USERS.items()
    ])

@app.route("/api/products")
def api_products():
    return jsonify(PRODUCTS)

@app.route("/openapi.json")
def openapi():
    return jsonify({
        "openapi": "3.0.0",
        "info": {
            "title": "Lab API",
            "version": "1.0"
        },
        "paths": {
            "/api/users": {"get": {"summary": "Lista usuários"}},
            "/api/products": {"get": {"summary": "Lista produtos"}},
            "/login": {"post": {"summary": "Login"}},
            "/upload": {"post": {"summary": "Upload de arquivo"}}
        }
    })

@app.route("/debug")
def debug():
    # propositalmente verboso
    return jsonify({
        "debug": True,
        "environment": "development",
        "cwd": os.getcwd(),
        "pythonpath_hint": "lab flask",
        "session": dict(session),
        "server_time": time.time()
    })

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /admin\nDisallow: /debug\n", 200, {"Content-Type": "text/plain"}

@app.route("/.env")
def exposed_env():
    return FAKE_ENV, 200, {"Content-Type": "text/plain"}

@app.route("/backup.zip")
def backup_zip():
    fake_zip = BytesIO(b"PK\x03\x04FAKE-ZIP-CONTENT-LAB")
    return send_file(fake_zip, mimetype="application/zip", as_attachment=False, download_name="backup.zip")

@app.route("/upload", methods=["GET", "POST"])
def upload():
    message = ""

    if request.method == "POST":
        file = request.files.get("file")
        if file:
            # propositalmente inseguro: sem validação real
            content = file.read()
            filename = file.filename or "sem_nome"
            size = len(content)

            message = f"<p>Arquivo recebido: {filename} ({size} bytes)</p>"

    return UPLOAD_HTML.format(message=message)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5550, debug=True)