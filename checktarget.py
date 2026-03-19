import csv
import hashlib
import json
import os
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
import yaml
from bs4 import BeautifulSoup

COMMON_RISKS = {
    21: "FTP exposto pode aumentar o risco de exposição de credenciais.",
    23: "Telnet é inseguro por transmitir dados sem criptografia.",
    80: "HTTP sem TLS pode expor sessão e credenciais.",
    111: "RPC exposto amplia a superfície de ataque.",
    139: "NetBIOS exposto pode revelar informações internas.",
    445: "SMB exposto exige validação rigorosa.",
    3306: "MySQL exposto diretamente é arriscado.",
    3389: "RDP exposto requer forte restrição e proteção.",
    5000: "Porta comum de desenvolvimento. Valide exposição indevida.",
    5432: "PostgreSQL exposto deve ser bem restringido.",
    5900: "VNC exposto pode ser perigoso se mal configurado.",
    6379: "Redis exposto é um risco clássico quando sem controle.",
    8080: "Serviço web alternativo exposto. Verifique autenticação.",
    8443: "HTTPS alternativo exposto. Verifique configuração.",
    9090: "Painel ou serviço de teste pode estar exposto."
}

findings = []
detected_technologies = set()
discovered_endpoints = []
evidences = []

def load_config(path="config.yaml"):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

CONFIG = load_config()

TARGET_URL = CONFIG["target_url"]
TARGET_HOST = CONFIG["target_host"]
HTTP_TIMEOUT = CONFIG["timeouts"]["http"]
SOCKET_TIMEOUT = CONFIG["timeouts"]["socket"]

OUTPUT_CSV = CONFIG["outputs"]["csv"]
OUTPUT_HTML = CONFIG["outputs"]["html"]
OUTPUT_JSON = CONFIG["outputs"]["json"]
EVIDENCE_DIR = CONFIG["outputs"]["evidence_dir"]

PORTS = CONFIG["scan"]["ports"]
COMMON_PATHS = CONFIG["scan"]["common_paths"]
EXPOSED_FILE_EXTENSIONS = CONFIG["scan"]["exposed_file_extensions"]
CANDIDATE_BASE_NAMES = CONFIG["scan"]["candidate_base_names"]
SECURITY_HEADERS = CONFIG["scan"]["security_headers"]

LOGIN_FLOW_ENABLED = CONFIG.get("login_flow", {}).get("enabled", False)
LOGIN_PATHS = CONFIG.get("login_flow", {}).get("login_paths", [])
INVALID_USERNAME = CONFIG.get("login_flow", {}).get("invalid_username", "fake_user")
INVALID_PASSWORD = CONFIG.get("login_flow", {}).get("invalid_password", "fake_pass")

def add_finding(category, severity, target, detail, recommendation):
    findings.append({
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "category": category,
        "severity": severity,
        "target": target,
        "detail": detail,
        "recommendation": recommendation
    })

def add_evidence(url, method, status_code, content_type, body_text):
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    fingerprint = hashlib.sha256(f"{method}:{url}".encode()).hexdigest()[:16]
    filename = os.path.join(EVIDENCE_DIR, f"{fingerprint}.txt")
    snippet = body_text[:4000]
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"URL: {url}\n")
        f.write(f"METHOD: {method}\n")
        f.write(f"STATUS: {status_code}\n")
        f.write(f"CONTENT-TYPE: {content_type}\n")
        f.write("\n--- BODY SNIPPET ---\n")
        f.write(snippet)
    evidences.append({
        "url": url,
        "method": method,
        "status_code": status_code,
        "content_type": content_type,
        "file": filename
    })

def safe_decode(data: bytes) -> str:
    try:
        return data.decode(errors="ignore").strip().replace("\r", " ").replace("\n", " ")[:240]
    except Exception:
        return ""

def severity_weight(sev: str) -> int:
    return {"alta": 3, "media": 2, "baixa": 1}.get(sev, 0)

def validate_targets():
    parsed = urlparse(TARGET_URL)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("target_url inválida no YAML.")
    if not TARGET_HOST:
        raise ValueError("target_host inválido no YAML.")

def fetch_url(url, method="GET", data=None, allow_redirects=True):
    try:
        resp = requests.request(
            method,
            url,
            timeout=HTTP_TIMEOUT,
            data=data,
            allow_redirects=allow_redirects
        )
        body = resp.text if "text" in resp.headers.get("Content-Type", "").lower() or "json" in resp.headers.get("Content-Type", "").lower() else ""
        add_evidence(
            url=url,
            method=method,
            status_code=resp.status_code,
            content_type=resp.headers.get("Content-Type", ""),
            body_text=body
        )
        return resp
    except requests.RequestException:
        return None

def get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except OSError:
        return "desconhecido"

def try_banner(host: str, port: int) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SOCKET_TIMEOUT)
            s.connect((host, port))
            if port in (80, 8080, 8443, 5000, 9090):
                s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            elif port == 443:
                return "HTTPS/TLS aberto"
            else:
                try:
                    s.sendall(b"\r\n")
                except Exception:
                    pass
            data = s.recv(1024)
            if data:
                return safe_decode(data)
    except Exception:
        pass
    return ""

def scan_port(host: str, port: int):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SOCKET_TIMEOUT)
            if s.connect_ex((host, port)) == 0:
                service = get_service_name(port)
                banner = try_banner(host, port)
                risk = COMMON_RISKS.get(port, "Porta aberta requer validação do contexto.")
                for token, tech in [
                    ("nginx", "Nginx"),
                    ("apache", "Apache"),
                    ("gunicorn", "Gunicorn"),
                    ("uvicorn", "Uvicorn"),
                    ("iis", "IIS")
                ]:
                    if token in banner.lower():
                        detected_technologies.add(tech)

                add_finding(
                    category="porta_aberta",
                    severity="alta" if port in (23, 3306, 6379, 3389) else "media",
                    target=f"{host}:{port}",
                    detail=f"Serviço provável: {service}. Banner: {banner or 'não identificado'}. Risco: {risk}",
                    recommendation="Validar necessidade da exposição e restringir por firewall, ACL ou VPN."
                )
    except Exception:
        pass

def run_port_scan():
    with ThreadPoolExecutor(max_workers=50) as executor:
        list(executor.map(lambda p: scan_port(TARGET_HOST, p), PORTS))

def detect_frameworks(response):
    text = response.text.lower()
    headers = {k.lower(): v for k, v in response.headers.items()}
    cookies = [c.lower() for c in response.cookies.keys()]

    fingerprints = [
        ("Flask/Werkzeug", lambda: "werkzeug" in headers.get("server", "").lower() or "flask" in text),
        ("Django", lambda: "csrftoken" in cookies or "django" in text),
        ("Laravel", lambda: "laravel_session" in cookies or "laravel" in text),
        ("Express", lambda: "x-powered-by" in headers and "express" in headers["x-powered-by"].lower()),
        ("ASP.NET", lambda: "asp.net" in headers.get("x-powered-by", "").lower() or "__viewstate" in text),
        ("Spring", lambda: "jsessionid" in cookies or "whitelabel error page" in text),
        ("Rails", lambda: "_session_id" in cookies or "ruby on rails" in text),
        ("React", lambda: "react" in text),
        ("Vue", lambda: "vue" in text),
        ("Angular", lambda: "ng-version" in text),
        ("Bootstrap", lambda: "bootstrap" in text),
        ("Swagger/OpenAPI", lambda: "swagger" in text or "openapi" in text),
    ]

    for name, matcher in fingerprints:
        try:
            if matcher():
                detected_technologies.add(name)
        except Exception:
            pass

    server = response.headers.get("Server")
    if server:
        detected_technologies.add(f"Server: {server}")

def check_headers(response):
    for header in SECURITY_HEADERS:
        if header not in response.headers:
            add_finding(
                category="header_ausente",
                severity="media",
                target=TARGET_URL,
                detail=f"Header ausente: {header}",
                recommendation=f"Adicionar o header {header} conforme a política da aplicação."
            )

    if response.headers.get("Server"):
        add_finding(
            category="banner_exposto",
            severity="baixa",
            target=TARGET_URL,
            detail=f"Header Server expõe: {response.headers.get('Server')}",
            recommendation="Reduzir exposição de banner e versão quando possível."
        )

    if response.headers.get("X-Powered-By"):
        add_finding(
            category="banner_exposto",
            severity="baixa",
            target=TARGET_URL,
            detail=f"X-Powered-By expõe: {response.headers.get('X-Powered-By')}",
            recommendation="Evitar exposição desnecessária de tecnologia."
        )

def check_cookies(response):
    set_cookie_headers = response.headers.get("Set-Cookie")
    if not set_cookie_headers:
        return

    cookie_text = set_cookie_headers.lower()
    if "httponly" not in cookie_text:
        add_finding(
            category="cookie_inseguro",
            severity="alta",
            target=TARGET_URL,
            detail="Cookie sem flag HttpOnly.",
            recommendation="Definir HttpOnly para reduzir risco de acesso via script."
        )
    if TARGET_URL.startswith("https://") and "secure" not in cookie_text:
        add_finding(
            category="cookie_inseguro",
            severity="alta",
            target=TARGET_URL,
            detail="Cookie sem flag Secure em contexto HTTPS.",
            recommendation="Definir Secure para cookies transmitidos apenas via HTTPS."
        )
    if "samesite" not in cookie_text:
        add_finding(
            category="cookie_inseguro",
            severity="media",
            target=TARGET_URL,
            detail="Cookie sem atributo SameSite.",
            recommendation="Definir SameSite=Lax ou Strict conforme o fluxo."
        )

def check_cors(response):
    acao = response.headers.get("Access-Control-Allow-Origin")
    acac = response.headers.get("Access-Control-Allow-Credentials")
    if acao == "*":
        sev = "alta" if acac and acac.lower() == "true" else "media"
        add_finding(
            category="cors_permissivo",
            severity=sev,
            target=TARGET_URL,
            detail=f"CORS permissivo detectado. ACAO={acao}, ACAC={acac}",
            recommendation="Restringir origens permitidas e revisar uso de credenciais."
        )

def check_http_methods():
    resp = fetch_url(TARGET_URL, method="OPTIONS")
    if not resp:
        return
    allow = resp.headers.get("Allow", "")
    if allow:
        risky = [m for m in ("PUT", "DELETE", "PATCH", "TRACE", "CONNECT") if m in allow.upper()]
        if risky:
            add_finding(
                category="metodos_http",
                severity="media",
                target=TARGET_URL,
                detail=f"Métodos potencialmente sensíveis habilitados: {', '.join(risky)}. Allow={allow}",
                recommendation="Restringir métodos não necessários no servidor ou proxy."
            )

def analyze_forms(base_url, html):
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")

    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        full_action = urljoin(base_url, action or "")
        inputs = form.find_all("input")
        input_names = [i.get("name") for i in inputs if i.get("name")]
        input_types = [i.get("type", "text").lower() for i in inputs]

        if full_action not in discovered_endpoints:
            discovered_endpoints.append(full_action)

        if "password" in input_types and not base_url.startswith("https://"):
            add_finding(
                category="senha_sem_https",
                severity="alta",
                target=full_action,
                detail="Formulário com campo de senha em página sem HTTPS.",
                recommendation="Publicar a aplicação atrás de HTTPS e redirecionar HTTP para HTTPS."
            )

        has_csrf = any("csrf" in (name or "").lower() for name in input_names)
        if method == "POST" and not has_csrf:
            add_finding(
                category="csrf_ausente",
                severity="media",
                target=full_action,
                detail="Formulário POST sem indício de token CSRF.",
                recommendation="Implementar proteção CSRF em operações state-changing."
            )

def discover_comments_and_indicators(html):
    lowered = html.lower()
    markers = ["todo", "fixme", "apikey", "secret", "token", "password", "debug"]
    hits = [m for m in markers if m in lowered]
    if hits:
        add_finding(
            category="comentarios_ou_indicios",
            severity="baixa",
            target=TARGET_URL,
            detail=f"Indicadores textuais encontrados no HTML/JS: {', '.join(sorted(set(hits)))}",
            recommendation="Revisar código cliente e remover comentários ou referências sensíveis."
        )

def discover_common_paths():
    for path in COMMON_PATHS:
        url = urljoin(TARGET_URL, path)
        resp = fetch_url(url)
        if not resp:
            continue

        if resp.status_code == 200:
            discovered_endpoints.append(url)
            severity = "alta" if any(p in path for p in ["/.env", "/swagger.json", "/openapi.json", "/debug", "/console"]) else "media"
            add_finding(
                category="caminho_exposto",
                severity=severity,
                target=url,
                detail=f"Caminho acessível com status 200: {path}",
                recommendation="Validar se o recurso deve ser público, proteger ou remover se necessário."
            )
        elif resp.status_code in (401, 403):
            discovered_endpoints.append(url)

def discover_exposed_files():
    for base_name in CANDIDATE_BASE_NAMES:
        for ext in EXPOSED_FILE_EXTENSIONS:
            candidate = f"/{base_name}{ext}"
            url = urljoin(TARGET_URL, candidate)
            resp = fetch_url(url)
            if resp and resp.status_code == 200:
                sev = "alta" if ext in (".env", ".sql", ".zip", ".bak") else "media"
                add_finding(
                    category="arquivo_exposto",
                    severity=sev,
                    target=url,
                    detail=f"Arquivo potencialmente sensível acessível: {candidate}",
                    recommendation="Remover da área pública, proteger o recurso e revisar processo de deploy/backup."
                )

def fingerprint_main_page():
    response = fetch_url(TARGET_URL)
    if not response:
        add_finding(
            category="erro_acesso",
            severity="baixa",
            target=TARGET_URL,
            detail="Não foi possível acessar a aplicação.",
            recommendation="Verificar disponibilidade da aplicação no lab."
        )
        return

    detect_frameworks(response)
    check_headers(response)
    check_cookies(response)
    check_cors(response)
    check_http_methods()
    analyze_forms(TARGET_URL, response.text)
    discover_comments_and_indicators(response.text)

    soup = BeautifulSoup(response.text, "html.parser")
    for a in soup.find_all("a", href=True):
        full = urljoin(TARGET_URL, a.get("href"))
        if full.startswith(TARGET_URL) and full not in discovered_endpoints:
            discovered_endpoints.append(full)

def analyze_login_flow():
    if not LOGIN_FLOW_ENABLED:
        return

    for path in LOGIN_PATHS:
        login_url = urljoin(TARGET_URL, path)
        resp = fetch_url(login_url)
        if not resp or resp.status_code >= 400:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            continue

        form = forms[0]
        action = urljoin(login_url, form.get("action", "") or login_url)
        method = form.get("method", "POST").upper()
        inputs = form.find_all("input")

        payload = {}
        password_field = None
        username_field = None

        for inp in inputs:
            name = inp.get("name")
            if not name:
                continue
            input_type = inp.get("type", "text").lower()

            if input_type == "hidden":
                payload[name] = inp.get("value", "")
            elif input_type == "password":
                password_field = name
            elif input_type in ("text", "email"):
                username_field = name

        if username_field and password_field:
            payload[username_field] = INVALID_USERNAME
            payload[password_field] = INVALID_PASSWORD

            if method == "POST":
                submit_resp = fetch_url(action, method="POST", data=payload, allow_redirects=False)
            else:
                submit_resp = fetch_url(action, method="GET", data=payload, allow_redirects=False)

            if not submit_resp:
                continue

            detail_parts = [f"Login path: {login_url}", f"Status resposta inválida: {submit_resp.status_code}"]

            if submit_resp.status_code in (200, 302, 303):
                detail_parts.append("Fluxo respondeu de forma consistente a credenciais inválidas.")

            body = submit_resp.text.lower()
            errors_found = [s for s in ["inválid", "invalid", "erro", "incorrect", "failed"] if s in body]
            if errors_found:
                detail_parts.append("Mensagem de erro de autenticação detectada.")

            if not body and submit_resp.status_code in (302, 303):
                detail_parts.append("Redirecionamento detectado após tentativa inválida.")

            add_finding(
                category="login_flow",
                severity="baixa",
                target=login_url,
                detail=" | ".join(detail_parts),
                recommendation="Validar manualmente mensagens de erro, política de bloqueio e consistência do fluxo de autenticação."
            )

            if "rate limit" in body or submit_resp.status_code == 429:
                add_finding(
                    category="rate_limit",
                    severity="baixa",
                    target=login_url,
                    detail="Indício de proteção de taxa detectado no fluxo de login.",
                    recommendation="Manter e revisar parâmetros de limitação conforme o contexto."
                )

            return

def export_csv():
    fieldnames = ["timestamp", "category", "severity", "target", "detail", "recommendation"]
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)

def build_risk_summary():
    summary = {}
    for f in findings:
        summary.setdefault(f["category"], 0)
        summary[f["category"]] += severity_weight(f["severity"])
    return summary

def build_executive_summary():
    total = len(findings)
    altas = sum(1 for f in findings if f["severity"] == "alta")
    medias = sum(1 for f in findings if f["severity"] == "media")
    baixas = sum(1 for f in findings if f["severity"] == "baixa")
    if altas >= 3:
        postura = "elevado"
    elif altas >= 1 or medias >= 4:
        postura = "moderado"
    else:
        postura = "controlado"
    return {
        "total_achados": total,
        "altas": altas,
        "medias": medias,
        "baixas": baixas,
        "postura": postura
    }

def prioritized_recommendations():
    ordered = sorted(findings, key=lambda x: severity_weight(x["severity"]), reverse=True)
    seen = set()
    result = []
    for f in ordered:
        key = (f["severity"], f["recommendation"])
        if key not in seen:
            seen.add(key)
            result.append(key)
    return result[:10]

def export_json():
    payload = {
        "target_url": TARGET_URL,
        "target_host": TARGET_HOST,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "executive_summary": build_executive_summary(),
        "technologies": sorted(detected_technologies),
        "endpoints": sorted(set(discovered_endpoints)),
        "risk_summary": build_risk_summary(),
        "findings": findings,
        "evidences": evidences
    }
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

def export_html():
    summary = build_executive_summary()
    risk_summary = build_risk_summary()
    recs = prioritized_recommendations()

    findings_rows = ""
    for f in findings:
        findings_rows += f"""
        <tr>
            <td>{f['timestamp']}</td>
            <td>{f['category']}</td>
            <td>{f['severity']}</td>
            <td>{f['target']}</td>
            <td>{f['detail']}</td>
            <td>{f['recommendation']}</td>
        </tr>
        """

    endpoints_html = "".join(f"<li>{e}</li>" for e in sorted(set(discovered_endpoints))) or "<li>Nenhum</li>"
    tech_html = "".join(f"<li>{t}</li>" for t in sorted(detected_technologies)) or "<li>Não identificado</li>"
    risks_html = "".join(f"<li><strong>{k}</strong>: score {v}</li>" for k, v in sorted(risk_summary.items(), key=lambda x: x[1], reverse=True)) or "<li>Sem dados</li>"
    recs_html = "".join(f"<li><strong>{sev.upper()}</strong>: {rec}</li>" for sev, rec in recs) or "<li>Sem recomendações</li>"
    evid_html = "".join(f"<li>{e['method']} {e['url']} -> {e['file']}</li>" for e in evidences[:50]) or "<li>Sem evidências</li>"

    html = f"""
    <!doctype html>
    <html lang="pt-br">
    <head>
      <meta charset="utf-8">
      <title>Relatório do Perfilador</title>
      <style>
        body {{ font-family: Arial, sans-serif; margin: 24px; color: #222; }}
        h1, h2 {{ color: #0f3d66; }}
        .card {{ border: 1px solid #ddd; padding: 16px; border-radius: 10px; margin-bottom: 16px; }}
        table {{ border-collapse: collapse; width: 100%; font-size: 14px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
        th {{ background: #f2f2f2; text-align: left; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 999px; background: #eef5ff; margin-right: 8px; }}
      </style>
    </head>
    <body>
      <h1>Perfilador de Aplicação</h1>
      <div class="card">
        <h2>Resumo Executivo</h2>
        <p>
          <span class="badge">Total: {summary['total_achados']}</span>
          <span class="badge">Altas: {summary['altas']}</span>
          <span class="badge">Médias: {summary['medias']}</span>
          <span class="badge">Baixas: {summary['baixas']}</span>
          <span class="badge">Postura: {summary['postura']}</span>
        </p>
        <p>Alvo analisado: <strong>{TARGET_URL}</strong></p>
      </div>

      <div class="card"><h2>Tecnologias Detectadas</h2><ul>{tech_html}</ul></div>
      <div class="card"><h2>Endpoints Relevantes</h2><ul>{endpoints_html}</ul></div>
      <div class="card"><h2>Risco por Categoria</h2><ul>{risks_html}</ul></div>
      <div class="card"><h2>Recomendações Priorizadas</h2><ul>{recs_html}</ul></div>
      <div class="card"><h2>Evidências HTTP</h2><ul>{evid_html}</ul></div>

      <div class="card">
        <h2>Achados</h2>
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Categoria</th>
              <th>Severidade</th>
              <th>Alvo</th>
              <th>Detalhe</th>
              <th>Recomendação</th>
            </tr>
          </thead>
          <tbody>{findings_rows}</tbody>
        </table>
      </div>
    </body>
    </html>
    """
    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html)

def print_console_summary():
    summary = build_executive_summary()
    print("\n=== RESUMO EXECUTIVO ===")
    print(f"Alvo             : {TARGET_URL}")
    print(f"Host             : {TARGET_HOST}")
    print(f"Achados totais   : {summary['total_achados']}")
    print(f"Alta             : {summary['altas']}")
    print(f"Média            : {summary['medias']}")
    print(f"Baixa            : {summary['baixas']}")
    print(f"Postura estimada : {summary['postura']}")

    print("\n=== TECNOLOGIAS ===")
    for tech in sorted(detected_technologies) or ["Não identificado"]:
        print(f"- {tech}")

    print("\n=== ENDPOINTS ===")
    for ep in sorted(set(discovered_endpoints))[:20]:
        print(f"- {ep}")

    print("\n=== EVIDÊNCIAS ===")
    for e in evidences[:10]:
        print(f"- {e['method']} {e['url']} -> {e['file']}")

def compare_reports(old_json_path, new_json_path):
    with open(old_json_path, "r", encoding="utf-8") as f:
        old = json.load(f)
    with open(new_json_path, "r", encoding="utf-8") as f:
        new = json.load(f)

    def normalize(item):
        return (item["category"], item["severity"], item["target"], item["detail"])

    old_set = {normalize(i) for i in old.get("findings", [])}
    new_set = {normalize(i) for i in new.get("findings", [])}

    removed = old_set - new_set
    added = new_set - old_set

    print("\n=== COMPARADOR DE RELATÓRIOS ===")
    print(f"Achados removidos: {len(removed)}")
    for item in sorted(removed)[:20]:
        print(f"- REMOVIDO: {item}")

    print(f"\nNovos achados: {len(added)}")
    for item in sorted(added)[:20]:
        print(f"- NOVO: {item}")

def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "compare":
        if len(sys.argv) != 4:
            print("Uso: python pentest_lab_tool.py compare relatorio_antigo.json relatorio_novo.json")
            sys.exit(1)
        compare_reports(sys.argv[2], sys.argv[3])
        return

    validate_targets()

    print("=== PERFILADOR DE APLICAÇÃO PARA LAB ===")
    print(f"URL : {TARGET_URL}")
    print(f"Host: {TARGET_HOST}")

    run_port_scan()
    fingerprint_main_page()
    discover_common_paths()
    discover_exposed_files()
    analyze_login_flow()

    export_csv()
    export_json()
    export_html()
    print_console_summary()

    print(f"\n[✓] CSV : {OUTPUT_CSV}")
    print(f"[✓] JSON: {OUTPUT_JSON}")
    print(f"[✓] HTML: {OUTPUT_HTML}")
    print(f"[✓] Evidências em: {EVIDENCE_DIR}")
    print("[i] Use apenas em ambiente próprio ou com autorização formal.")

if __name__ == "__main__":
    main()