from flask import Flask, request, jsonify
import smtplib, imaplib, poplib, time, logging, os, sqlite3, socket, urllib.parse
from dotenv import load_dotenv
try:
    import socks
except Exception:
    socks = None

# --- Загружаем .env ---
load_dotenv()

# --- Настройка логов ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler("checks.log"), logging.StreamHandler()]
)

# --- Flask app ---
app = Flask(__name__)

# --- Провайдеры (расширенный список топовых сервисов) ---
PROVIDERS = {
    'gmail.com': {'imap_host': 'imap.gmail.com', 'imap_port': 993,
                  'pop3_host': 'pop.gmail.com', 'pop3_port': 995,
                  'smtp_host': 'smtp.gmail.com', 'smtp_port': 587, 'smtp_tls': True},
    'yahoo.com': {'imap_host': 'imap.mail.yahoo.com', 'imap_port': 993,
                  'pop3_host': 'pop.mail.yahoo.com', 'pop3_port': 995,
                  'smtp_host': 'smtp.mail.yahoo.com', 'smtp_port': 587, 'smtp_tls': True},
    'outlook.com': {'imap_host': 'outlook.office365.com', 'imap_port': 993,
                    'pop3_host': 'pop3.live.com', 'pop3_port': 995,
                    'smtp_host': 'smtp.office365.com', 'smtp_port': 587, 'smtp_tls': True},
    'hotmail.com': {'imap_host': 'outlook.office365.com', 'imap_port': 993,
                    'pop3_host': 'pop3.live.com', 'pop3_port': 995,
                    'smtp_host': 'smtp.office365.com', 'smtp_port': 587, 'smtp_tls': True},
    'aol.com': {'imap_host': 'imap.aol.com', 'imap_port': 993,
                'pop3_host': 'pop.aol.com', 'pop3_port': 995,
                'smtp_host': 'smtp.aol.com', 'smtp_port': 587, 'smtp_tls': True},
    'icloud.com': {'imap_host': 'imap.mail.me.com', 'imap_port': 993,
                   'pop3_host': 'pop.mail.me.com', 'pop3_port': 995,
                   'smtp_host': 'smtp.mail.me.com', 'smtp_port': 587, 'smtp_tls': True},
    'mail.com': {'imap_host': 'imap.mail.com', 'imap_port': 993,
                 'pop3_host': 'pop.mail.com', 'pop3_port': 995,
                 'smtp_host': 'smtp.mail.com', 'smtp_port': 587, 'smtp_tls': True},
    'gmx.com': {'imap_host': 'imap.gmx.com', 'imap_port': 993,
                'pop3_host': 'pop.gmx.com', 'pop3_port': 995,
                'smtp_host': 'smtp.gmx.com', 'smtp_port': 587, 'smtp_tls': True},
    'zoho.com': {'imap_host': 'imap.zoho.com', 'imap_port': 993,
                 'pop3_host': 'pop.zoho.com', 'pop3_port': 995,
                 'smtp_host': 'smtp.zoho.com', 'smtp_port': 587, 'smtp_tls': True},
    'protonmail.com': {'imap_host': None, 'imap_port': None,
                       'pop3_host': None, 'pop3_port': None,
                       'smtp_host': None, 'smtp_port': None, 'smtp_tls': True},  # требует Bridge
    'yandex.ru': {'imap_host': 'imap.yandex.ru', 'imap_port': 993,
                  'pop3_host': 'pop.yandex.ru', 'pop3_port': 995,
                  'smtp_host': 'smtp.yandex.ru', 'smtp_port': 465, 'smtp_tls': True},
    'rambler.ru': {'imap_host': 'imap.rambler.ru', 'imap_port': 993,
                   'pop3_host': 'pop.rambler.ru', 'pop3_port': 995,
                   'smtp_host': 'smtp.rambler.ru', 'smtp_port': 465, 'smtp_tls': True},
    'mail.ru': {'imap_host': 'imap.mail.ru', 'imap_port': 993,
                'pop3_host': 'pop.mail.ru', 'pop3_port': 995,
                'smtp_host': 'smtp.mail.ru', 'smtp_port': 465, 'smtp_tls': True},
    'fastmail.com': {'imap_host': 'imap.fastmail.com', 'imap_port': 993,
                     'pop3_host': 'pop.fastmail.com', 'pop3_port': 995,
                     'smtp_host': 'smtp.fastmail.com', 'smtp_port': 587, 'smtp_tls': True},
    'web.de': {'imap_host': 'imap.web.de', 'imap_port': 993,
               'pop3_host': 'pop.web.de', 'pop3_port': 995,
               'smtp_host': 'smtp.web.de', 'smtp_port': 587, 'smtp_tls': True},
    'tutanota.com': {'imap_host': None, 'imap_port': None,
                     'pop3_host': None, 'pop3_port': None,
                     'smtp_host': None, 'smtp_port': None, 'smtp_tls': True},  # нет прямого IMAP/POP3
    'hushmail.com': {'imap_host': 'imap.hushmail.com', 'imap_port': 993,
                     'pop3_host': 'pop.hushmail.com', 'pop3_port': 995,
                     'smtp_host': 'smtp.hushmail.com', 'smtp_port': 587, 'smtp_tls': True}
}

# --- SQLite init ---
DB_FILE = "checks.db"
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        protocol TEXT,
        success INTEGER,
        message TEXT,
        response_time REAL,
        created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()
init_db()

# --- Proxy ---
def set_system_proxy(proxy_url):
    if not proxy_url:
        return False, "No proxy"
    if socks is None:
        return False, "PySocks not installed"
    parsed = urllib.parse.urlparse(proxy_url)
    scheme, host, port = parsed.scheme, parsed.hostname, parsed.port
    user, pwd = parsed.username, parsed.password
    if scheme.startswith("socks"):
        proxy_type = socks.SOCKS5 if scheme == "socks5" else socks.SOCKS4
        socks.set_default_proxy(proxy_type, host, port, username=user, password=pwd)
        socket.socket = socks.socksocket
    elif scheme in ("http", "https"):
        socks.set_default_proxy(socks.HTTP, host, port, username=user, password=pwd)
        socket.socket = socks.socksocket
    return True, f"Proxy set {proxy_url}"

# --- Протоколы ---
def check_smtp(email, password, host, port, tls=True):
    start = time.time()
    try:
        server = smtplib.SMTP(host, port, timeout=10)
        server.ehlo()
        if tls:
            server.starttls()
            server.ehlo()
        server.login(email, password)
        server.quit()
        return True, "SMTP login successful", round(time.time() - start, 2)
    except Exception as e:
        return False, f"SMTP error: {e}", round(time.time() - start, 2)

def check_imap(email, password, host, port):
    start = time.time()
    if host is None or port is None:
        return False, "IMAP not supported for this provider", 0.0
    try:
        conn = imaplib.IMAP4_SSL(host, port)
        conn.login(email, password)
        conn.logout()
        return True, "IMAP login successful", round(time.time() - start, 2)
    except Exception as e:
        return False, f"IMAP error: {e}", round(time.time() - start, 2)

def check_pop3(email, password, host, port):
    start = time.time()
    if host is None or port is None:
        return False, "POP3 not supported for this provider", 0.0
    try:
        conn = poplib.POP3_SSL(host, port, timeout=10)
        conn.user(email)
        conn.pass_(password)
        conn.quit()
        return True, "POP3 login successful", round(time.time() - start, 2)
    except Exception as e:
        return False, f"POP3 error: {e}", round(time.time() - start, 2)

# --- Auth helper ---
def check_token(req):
    token = req.headers.get("Authorization")
    return token == f"Bearer {os.getenv('API_TOKEN')}"

# --- API ---
@app.route('/api/check-email', methods=['POST'])
def check_email():
    if not check_token(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    data = request.get_json(force=True)
    email, password = data.get('email'), data.get('password')
    protocol = data.get('protocol', 'imap')
    proxy = data.get('proxy')

    if not email or not password:
        return jsonify({'success': False, 'error': 'Email и пароль обязательны'}), 400

    domain = email.split('@')[-1].lower()
    cfg = PROVIDERS.get(domain)
    if not cfg:
        logging.warning(f"Provider not found for domain: {domain}, using Gmail fallback")
        cfg = PROVIDERS['gmail.com']

    smtp_host, smtp_port = cfg.get('smtp_host', 'smtp.gmail.com'), cfg.get('smtp_port', 587)
    imap_host, imap_port = cfg.get('imap_host', 'imap.gmail.com'), cfg.get('imap_port', 993)
    pop3_host, pop3_port = cfg.get('pop3_host', 'pop.gmail.com'), cfg.get('pop3_port', 995)

    if proxy:
        set_system_proxy(proxy)

    if protocol == 'smtp':
        ok, msg, rt = check_smtp(email, password, smtp_host, smtp_port, cfg.get('smtp_tls', True))
    elif protocol == 'imap':
        ok, msg, rt = check_imap(email, password, imap_host, imap_port)
    elif protocol == 'pop3':
        ok, msg, rt = check_pop3(email, password, pop3_host, pop3_port)
    else:
        return jsonify({'success': False, 'error': 'Bad protocol'}), 400

    logging.info(f"Check result: {email} via {protocol} → {msg}")

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO checks (email, protocol, success, message, response_time) VALUES (?, ?, ?, ?, ?)",
                (email, protocol, 1 if ok else 0, msg, rt))
    conn.commit()
    conn.close()

    return jsonify({
        'success': ok,
        'email': email,
        'protocol': protocol,
        'provider': domain,
        'message': msg,
        'response_time': rt
    })

@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

@app.route('/api/results')
def results():
    if not check_token(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT email, protocol, success, message, response_time, created FROM checks ORDER BY id DESC LIMIT 50")
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows)

@app.route('/api/providers')
def list_providers():
    if not check_token(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    provider_list = []
    for domain, config in PROVIDERS.items():
        provider_info = {
            'domain': domain,
            'supports_imap': bool(config.get('imap_host')),
            'supports_pop3': bool(config.get('pop3_host')),
            'supports_smtp': bool(config.get('smtp_host'))
        }
        provider_list.append(provider_info)
    
    return jsonify({'providers': provider_list, 'total': len(provider_list)})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=os.getenv("DEBUG") == "True")

