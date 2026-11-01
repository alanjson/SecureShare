"""
http_serve.py
─────────────
Standalone HTTP file server extracted from WiFi-Home-Server.
Hosts local files/folders over WiFi so any device on the same
network can browse and download them through a browser.

No ADB, no USB, no app needed on the Android side.
Android just opens:  http://<PC_IP>:8765

How it works:
  1. get_local_ip()       — finds this PC's WiFi IP
  2. build_index_html()   — generates the root HTML listing all shared items
  3. build_dir_html()     — generates HTML for browsing inside a folder
  4. serve_file()         — streams a file to the client for download
  5. make_handler()       — creates the HTTP request handler class bound to your file roots
  6. start_server()       — starts the server (blocking)
  7. start_server_background() — starts the server in a background thread (non-blocking)

Usage example at the bottom of this file.
"""

import os
import hashlib
import hmac
import ipaddress
import json
import getpass
import base64
import secrets
import socket
import ssl
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509.oid import NameOID


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING HELPER
# ─────────────────────────────────────────────────────────────────────────────

LOG_CALLBACK = None
CONNECTION_CALLBACK = None

PBKDF2_ITERATIONS = 600_000
SESSION_LIFETIME = 8 * 60 * 60
CHALLENGE_LIFETIME = 60


def derive_password_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a 256-bit password verifier using PBKDF2-HMAC-SHA256."""
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
    ).derive(password.encode("utf-8"))


def derive_file_key(password_key: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        info=b"SecureShare AES-256-GCM file key",
    ).derive(password_key)


def encrypt_file(data: bytes, key: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    return nonce, AESGCM(key).encrypt(nonce, data, aad)


def decrypt_file(ciphertext: bytes, key: bytes, nonce: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def create_tls_context() -> tuple[ssl.SSLContext, str]:
    """Create or reuse a local self-signed certificate for this WLAN address."""
    address = get_local_ip()
    cert_dir = Path(os.environ.get("APPDATA", Path.home() / ".config")) / "SecureShare"
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "server-cert.pem"
    key_path = cert_dir / "server-key.pem"

    certificate = None
    private_key = None
    if cert_path.exists() and key_path.exists():
        try:
            certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
            private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            if address not in [str(item) for item in sans.get_values_for_type(x509.IPAddress)]:
                certificate = None
                private_key = None
        except (ValueError, OSError, x509.ExtensionNotFound):
            certificate = None
            private_key = None

    if certificate is None or private_key is None:
        private_key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureShare WLAN Server")
        ])
        san_addresses = {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address(address)}
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ip) for ip in san_addresses]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(private_key, hashes.SHA256())
        )
        key_path.write_bytes(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        try:
            key_path.chmod(0o600)
        except OSError:
            pass

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex(":").upper()
    return context, fingerprint


def build_secure_page() -> str:
    return r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureShare</title><style>
:root{color-scheme:dark;font:16px "Segoe UI",sans-serif;background:#101714;color:#edf4ee}*{box-sizing:border-box}body{max-width:820px;margin:0 auto;padding:28px 18px;background:linear-gradient(145deg,#101714,#18251f 55%,#202720);min-height:100vh}h1{font-size:30px;margin:0;color:#d9f36a}p{color:#b4c3b9}.sub{margin-top:5px}.panel{border-top:1px solid #536252;margin-top:24px;padding-top:20px}input,button{font:inherit;border:1px solid #65745f;border-radius:5px;padding:11px;background:#1a241e;color:#f5f8ee}input{width:min(100%,390px)}button{cursor:pointer;background:#d9f36a;color:#172017;border-color:#d9f36a;font-weight:650}button:disabled{opacity:.55;cursor:wait}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.item{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:12px 0;border-bottom:1px solid #334239}.item button{background:#26332b;border-color:#52644f;color:#eef6e7;font-weight:500}.muted{color:#9eaea3;font-size:14px}.error{color:#ff938e}.ok{color:#d9f36a}progress{width:100%;height:12px;accent-color:#d9f36a}.hidden{display:none}.status{min-height:24px;margin-top:12px}
</style></head><body><h1>SecureShare</h1><p class="sub">Secure File Sharing over WLAN</p>
<section id="login" class="panel"><h2>Sign in</h2><p class="muted">The password is used locally to derive authentication and decryption keys; it is not sent to the server.</p><form id="loginForm" class="row"><input id="password" type="password" autocomplete="current-password" required minlength="12" placeholder="Sharing password (12+ characters)"><button>Unlock files</button></form><p id="loginStatus" class="status error" aria-live="polite"></p></section>
<section id="files" class="panel hidden"><div class="row"><h2 id="heading">Shared files</h2><button id="back" class="hidden" type="button">Back</button><button id="logout" type="button">Lock</button></div><div id="items"></div></section>
<section id="transfer" class="panel hidden"><div id="transferName"></div><progress id="progress" max="100" value="0"></progress><p id="status" class="status muted" aria-live="polite"></p></section>
<script>
const enc=new TextEncoder(),hex=b=>Array.from(new Uint8Array(b),v=>v.toString(16).padStart(2,"0")).join("");
let verifier=null,aesKey=null,salt=null,currentRoot=null,currentPath="";
const $=id=>document.getElementById(id),setStatus=(text,kind="muted")=>{$("status").textContent=text;$("status").className=`status ${kind}`};
async function derive(password,challenge){salt=Uint8Array.from(challenge.salt.match(/../g),v=>parseInt(v,16));const base=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);verifier=await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt,iterations:challenge.iterations},base,256);const hmacKey=await crypto.subtle.importKey("raw",verifier,{name:"HMAC",hash:"SHA-256"},false,["sign"]);const proof=hex(await crypto.subtle.sign("HMAC",hmacKey,Uint8Array.from(challenge.nonce.match(/../g),v=>parseInt(v,16))));const hkdf=await crypto.subtle.importKey("raw",verifier,"HKDF",false,["deriveKey"]);aesKey=await crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-256",salt,info:enc.encode("SecureShare AES-256-GCM file key")},hkdf,{name:"AES-GCM",length:256},false,["decrypt"]);return proof}
async function api(url,options={}){const response=await fetch(url,{cache:"no-store",...options});if(!response.ok){let message=`Request failed (${response.status})`;try{message=(await response.json()).error||message}catch{}throw new Error(message)}return response}
$("loginForm").addEventListener("submit",async event=>{event.preventDefault();const button=event.submitter;button.disabled=true;$("loginStatus").textContent="";try{const challenge=await (await api("/api/challenge")).json();const proof=await derive($("password").value,challenge);await api("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({nonce:challenge.nonce,proof})});$("login").classList.add("hidden");$("files").classList.remove("hidden");$("password").value="";await loadItems()}catch(error){$("loginStatus").textContent=error.message;$("login").classList.remove("hidden")}finally{button.disabled=false}});
async function loadItems(){const query=new URLSearchParams();if(currentRoot!==null){query.set("root",currentRoot);query.set("path",currentPath)}const data=await (await api(`/api/list?${query}`)).json();const items=$("items");items.replaceChildren();$("heading").textContent=currentRoot===null?"Shared items":data.location;$("back").classList.toggle("hidden",currentRoot===null);for(const item of data.items){const row=document.createElement("div");row.className="item";const label=document.createElement("span");label.textContent=`${item.is_dir?"Folder":"File"}  ${item.name}${item.is_dir?"":`  ·  ${item.size}`}`;const button=document.createElement("button");button.type="button";button.textContent=item.is_dir?"Open":"Decrypt and save";button.addEventListener("click",()=>item.is_dir?(currentRoot=item.root,currentPath=item.path,loadItems()):download(item));row.append(label,button);items.append(row)}}
$("back").addEventListener("click",()=>{if(currentPath)currentPath=currentPath.split("/").slice(0,-1).join("/");else currentRoot=null;loadItems()});
$("logout").addEventListener("click",async()=>{await fetch("/api/logout",{method:"POST"});verifier=null;aesKey=null;currentRoot=null;currentPath="";$("files").classList.add("hidden");$("login").classList.remove("hidden");setStatus("Locked")});
async function download(item){$("transfer").classList.remove("hidden");$("transferName").textContent=`Preparing ${item.name}`;setStatus("Downloading encrypted data...");$("progress").value=0;try{const query=new URLSearchParams({root:item.root,path:item.path});const response=await api(`/api/file?${query}`);const total=Number(response.headers.get("Content-Length"))||0,reader=response.body.getReader(),chunks=[];let received=0;while(true){const {done,value}=await reader.read();if(done)break;chunks.push(value);received+=value.length;if(total)$("progress").value=Math.floor(received/total*70);setStatus(`Encrypted transfer: ${total?Math.floor(received/total*100):""}%`)}const cipher=new Uint8Array(received);let offset=0;for(const chunk of chunks){cipher.set(chunk,offset);offset+=chunk.length}const nonce=Uint8Array.from(atob(response.headers.get("X-File-Nonce")),c=>c.charCodeAt(0));setStatus("Decrypting and checking SHA-256...");const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:nonce,additionalData:enc.encode(item.name)},aesKey,cipher);$("progress").value=90;const digest=hex(await crypto.subtle.digest("SHA-256",plain));if(digest!==response.headers.get("X-File-SHA256"))throw new Error("Integrity verification failed: SHA-256 mismatch.");const blob=new Blob([plain],{type:"application/octet-stream"}),url=URL.createObjectURL(blob),anchor=document.createElement("a");anchor.href=url;anchor.download=item.name;anchor.click();URL.revokeObjectURL(url);$("progress").value=100;setStatus("Decryption successful. SHA-256 integrity verified.","ok");$("transferName").textContent=item.name}catch(error){setStatus(error.name==="OperationError"?"Decryption failed. Check the password or file integrity.":error.message,"error");$("progress").value=0}}
</script></body></html>'''

def _log(level: str, msg: str):
    """
    If LOG_CALLBACK is set, route messages to it (e.g., for a GUI).
    Otherwise, standard print.
    """
    if LOG_CALLBACK:
        LOG_CALLBACK(level, msg)
    else:
        print(msg)

def _conn(action: str):
    """Notify GUI when a connection starts or ends. action='connect'|'disconnect'"""
    if CONNECTION_CALLBACK:
        CONNECTION_CALLBACK(action)

# ─────────────────────────────────────────────────────────────────────────────
# NETWORK HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    """
    Find this machine's local network IP address (e.g. 192.168.1.42).

    It works by opening a dummy UDP socket toward a public DNS server.
    No actual data is sent — the OS just picks the right local interface
    to route through, and we read that interface's IP.

    Returns "127.0.0.1" as fallback if detection fails.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))          # doesn't actually send anything
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"


def format_size(size_bytes: int) -> str:
    """
    Convert a byte count into a human-readable string.
    e.g. 1048576 → "1.0 MB"
    """
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


# ─────────────────────────────────────────────────────────────────────────────
# HTML BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def html_shell(title: str, body: str) -> str:
    """
    Wraps any HTML body content in a full page with a dark stylesheet.
    Used by both the root index and directory listings.

    Args:
        title: shown in the browser tab
        body:  the inner HTML to embed

    Returns the full HTML string (UTF-8 safe).
    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} — WiFi-Home-Server Server</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: system-ui, sans-serif;
      background: #0f0f0f;
      color: #e0e0e0;
      padding: 28px 20px;
      max-width: 720px;
      margin: 0 auto;
    }}
    h1 {{ font-size: 1.4rem; color: #00c9e0; margin-bottom: 6px; }}
    p.sub {{ color: #555; font-size: 0.85rem; margin-bottom: 24px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{
      text-align: left; padding: 8px 10px;
      font-size: 0.75rem; text-transform: uppercase;
      color: #444; border-bottom: 1px solid #222;
    }}
    td {{ padding: 10px; border-bottom: 1px solid #1a1a1a; }}
    td a {{ color: #7ecfdf; text-decoration: none; }}
    td a:hover {{ text-decoration: underline; }}
    .size {{ color: #555; font-size: 0.85rem; text-align: right; }}
    .badge {{
      display: inline-block; padding: 2px 7px; border-radius: 4px;
      font-size: 0.7rem; font-weight: bold;
      background: #001a1f; color: #00c9e0;
    }}
  </style>
</head>
<body>{body}</body>
</html>"""


def build_index_html(roots: list[dict]) -> str:
    """
    Build the root page HTML that lists all shared files/folders.

    Each entry in `roots` is a dict with keys:
        "local"  : absolute local path (e.g. "C:/Users/me/build")
        "remote" : Android destination (not used here, just for reference)

    The page shows each item as a clickable link.
    Folders open a directory browser; files download directly.

    Args:
        roots: list of sync-pair dicts (from WiFi-Home-Server config)

    Returns full HTML string.
    """
    rows = ""
    for pair in roots:
        local = pair["local"]
        name  = os.path.basename(local.rstrip("/\\")) or local
        is_dir = os.path.isdir(local)
        icon   = "📁" if is_dir else "📄"
        href   = "/" + urllib.parse.quote(name)
        size   = "" if is_dir else format_size(os.path.getsize(local))

        rows += f"""
        <tr>
          <td>{icon} <a href="{href}">{name}</a></td>
          <td class="size">{size}</td>
        </tr>"""

    body = f"""
    <h1>📡 WiFi-Home-Server File Server</h1>
    <p class="sub">Open a file to download it, or tap a folder to browse.</p>
    <table>
      <tr><th>Name</th><th style="text-align:right">Size</th></tr>
      {rows}
    </table>"""

    return html_shell("WiFi-Home-Server", body)


def build_dir_html(full_path: str, url_path: str) -> str:
    """
    Build a directory listing page for browsing inside a shared folder.

    Shows all files and subfolders sorted: folders first, then files.
    Includes a ".." back link (except at root).

    Args:
        full_path: absolute local path to the directory being listed
        url_path:  the URL path (used to build links and the back button)

    Returns full HTML string.
    """
    try:
        entries = sorted(
            os.scandir(full_path),
            key=lambda e: (not e.is_dir(), e.name.lower())   # folders first
        )
    except PermissionError:
        return html_shell("Error", "<h1>Permission denied</h1>")

    rows = ""

    # Back link — strip last segment from url_path
    if "/" in url_path.strip("/"):
        parent = "/" + "/".join(url_path.strip("/").split("/")[:-1])
    else:
        parent = "/"
    rows += f'<tr><td><a href="{parent}">⬆ ..</a></td><td class="size"></td></tr>'

    for entry in entries:
        icon  = "📁" if entry.is_dir() else "📄"
        href  = f"/{url_path.strip('/')}/{urllib.parse.quote(entry.name)}"
        size  = "" if entry.is_dir() else format_size(entry.stat().st_size)
        rows += f"""
        <tr>
          <td>{icon} <a href="{href}">{entry.name}</a></td>
          <td class="size">{size}</td>
        </tr>"""

    body = f"""
    <h1>📁 /{url_path.strip('/')}</h1>
    <p class="sub"><a href="/" style="color:#555">← root</a></p>
    <table>
      <tr><th>Name</th><th style="text-align:right">Size</th></tr>
      {rows}
    </table>"""

    return html_shell(url_path, body)


# ─────────────────────────────────────────────────────────────────────────────
# FILE STREAMING
# ─────────────────────────────────────────────────────────────────────────────

def serve_file(handler: BaseHTTPRequestHandler, full_path: str):
    """
    Stream a local file to the HTTP client as a binary download.

    Sends correct headers so the browser prompts a Save dialog
    instead of trying to display the file inline.

    Reads in 64 KB chunks to avoid loading large files into memory.

    Args:
        handler:   the active BaseHTTPRequestHandler instance
        full_path: absolute local path to the file to send
    """
    try:
        file_size = os.path.getsize(full_path)
        filename  = os.path.basename(full_path)

        handler.send_response(200)
        handler.send_header("Content-Type", "application/octet-stream")
        # "attachment" forces a Save dialog on Android browser
        handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        handler.send_header("Content-Length", str(file_size))
        handler.end_headers()

        # Stream in chunks — safe for large APKs, ZIPs, videos, etc.
        with open(full_path, "rb") as f:
            while True:
                chunk = f.read(65536)   # 64 KB per read
                if not chunk:
                    break
                handler.wfile.write(chunk)

        _log("info", f"  [SENT]  {filename}  ({format_size(file_size)})")

    except (BrokenPipeError, ConnectionResetError):
        # Client disconnected mid-download — not an error, just ignore
        pass
    except Exception as e:
        _log("error", f"  [ERR]   Failed to serve {full_path}: {e}")


def send_html(handler: BaseHTTPRequestHandler, html: str, status: int = 200):
    """
    Send an HTML string response to the client.

    Args:
        handler: active request handler
        html:    the full HTML string to send
        status:  HTTP status code (default 200)
    """
    data = html.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def send_404(handler: BaseHTTPRequestHandler):
    """Send a simple 404 Not Found response."""
    send_html(handler, html_shell("Not Found", "<h1>404 — Not Found</h1>"), 404)


# ─────────────────────────────────────────────────────────────────────────────
# REQUEST HANDLER FACTORY
# ─────────────────────────────────────────────────────────────────────────────

def _legacy_make_handler(roots: list[dict]) -> type:
    """
    Create and return an HTTP request handler class bound to `roots`.

    We use a factory function instead of a global variable so that multiple
    server instances could theoretically serve different sets of files.

    The returned class handles GET requests only:
      GET /              → root index listing all shared items
      GET /FolderName    → directory browser for that folder
      GET /Folder/file   → file download
      anything else      → 404

    Args:
        roots: list of sync-pair dicts, each with a "local" key

    Returns:
        A class (not an instance) that HTTPServer can use.
    """

    class Handler(BaseHTTPRequestHandler):

        # Silence the default per-request log lines (we print our own)
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            _conn("connect")
            try:
                # Decode %20 etc. from the URL path
                url_path = urllib.parse.unquote(self.path.lstrip("/"))
    
                # ── Root: list all shared items ──────────────────────────────
                if not url_path:
                    send_html(self, build_index_html(roots))
                    return
    
                # ── Resolve the URL path against our shared roots ────────────
                # The first segment of the URL is the item name (file or folder).
                # e.g. URL "/MyApp/output/app.apk" → root named "MyApp" + rel path "output/app.apk"
                segments = url_path.split("/", 1)
                root_name = segments[0]
                rel_path  = segments[1] if len(segments) > 1 else ""
    
                # Find which root this name belongs to
                matched_root = None
                for pair in roots:
                    name = os.path.basename(pair["local"].rstrip("/\\"))
                    if name == root_name:
                        matched_root = pair["local"]
                        break
    
                if matched_root is None:
                    send_404(self)
                    return
    
                # Build the full local path
                full_path = os.path.join(matched_root, rel_path) if rel_path else matched_root
                full_path = os.path.normpath(full_path)
    
                # Security: make sure the resolved path is still inside the root
                # (prevents directory traversal attacks like /../../../etc/passwd)
                if not full_path.startswith(os.path.normpath(matched_root)):
                    send_404(self)
                    return
    
                if not os.path.exists(full_path):
                    send_404(self)
                    return
    
                if os.path.isdir(full_path):
                    send_html(self, build_dir_html(full_path, url_path))
                else:
                    serve_file(self, full_path)
                    
            finally:
                _conn("disconnect")

    return Handler


def make_handler(roots: list[dict]) -> type:
    raise RuntimeError("Unauthenticated HTTP serving is disabled. Use start_server_background().")


# ─────────────────────────────────────────────────────────────────────────────
# AUTHENTICATED ENCRYPTED SERVER
# ─────────────────────────────────────────────────────────────────────────────

def make_secure_handler(roots: list[dict], password_key: bytes, salt: bytes) -> type:
    challenges: dict[str, float] = {}
    sessions: dict[str, float] = {}
    state_lock = threading.Lock()
    max_file_size = 256 * 1024 * 1024

    def send_json(handler, value, status=200):
        data = json.dumps(value).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(data)))
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.end_headers()
        handler.wfile.write(data)

    def resolve_path(root_index: int, relative_path: str) -> tuple[str, str]:
        if root_index < 0 or root_index >= len(roots):
            raise ValueError("Invalid shared item")
        root = os.path.realpath(roots[root_index]["local"])
        parts = relative_path.replace("\\", "/").split("/") if relative_path else []
        if any(part in (".", "..") for part in parts):
            raise ValueError("Invalid path")
        candidate = os.path.realpath(os.path.join(root, *parts))
        try:
            if os.path.commonpath((root, candidate)) != root:
                raise ValueError("Path is outside the shared item")
        except ValueError:
            raise ValueError("Invalid path")
        return root, candidate

    class Handler(BaseHTTPRequestHandler):
        server_version = "SecureShare"
        sys_version = ""

        def log_message(self, format, *args):
            pass

        def _session_token(self):
            for part in self.headers.get("Cookie", "").split(";"):
                name, separator, value = part.strip().partition("=")
                if separator and name == "ss_session":
                    return value
            return None

        def _authenticated(self):
            token = self._session_token()
            with state_lock:
                expiry = sessions.get(token) if token else None
                if expiry and expiry > time.time():
                    return True
                if token:
                    sessions.pop(token, None)
            return False

        def _send_auth_error(self):
            send_json(self, {"error": "Authentication required"}, 401)

        def do_GET(self):
            _conn("connect")
            try:
                parsed = urllib.parse.urlsplit(self.path)
                if parsed.path == "/":
                    data = build_secure_page().encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("Referrer-Policy", "no-referrer")
                    self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'")
                    self.end_headers()
                    self.wfile.write(data)
                    return

                if parsed.path == "/api/challenge":
                    nonce = secrets.token_bytes(32)
                    nonce_id = nonce.hex()
                    with state_lock:
                        now = time.time()
                        for challenge_id, expiry in list(challenges.items()):
                            if expiry <= now:
                                challenges.pop(challenge_id, None)
                        if len(challenges) >= 256:
                            oldest = min(challenges, key=challenges.get)
                            challenges.pop(oldest, None)
                        challenges[nonce_id] = now + CHALLENGE_LIFETIME
                    send_json(self, {"nonce": nonce_id, "salt": salt.hex(), "iterations": PBKDF2_ITERATIONS})
                    return

                if parsed.path == "/api/list":
                    if not self._authenticated():
                        self._send_auth_error()
                        return
                    query = urllib.parse.parse_qs(parsed.query)
                    if "root" not in query:
                        items = []
                        for index, pair in enumerate(roots):
                            path = os.path.realpath(pair["local"])
                            if os.path.exists(path):
                                items.append({
                                    "root": index, "path": "",
                                    "name": os.path.basename(path.rstrip("/\\")) or path,
                                    "is_dir": os.path.isdir(path),
                                    "size": format_size(os.path.getsize(path)) if os.path.isfile(path) else "",
                                })
                        send_json(self, {"location": "Shared items", "items": items})
                        return

                    try:
                        root_index = int(query["root"][0])
                        relative = query.get("path", [""])[0]
                        root, directory = resolve_path(root_index, relative)
                        if not os.path.isdir(directory):
                            raise ValueError("Not a folder")
                        items = []
                        for entry in os.scandir(directory):
                            entry_path = os.path.realpath(entry.path)
                            try:
                                if os.path.commonpath((root, entry_path)) != root:
                                    continue
                            except ValueError:
                                continue
                            rel = "/".join(filter(None, (relative, entry.name)))
                            is_dir = os.path.isdir(entry_path)
                            items.append({
                                "root": root_index, "path": rel, "name": entry.name,
                                "is_dir": is_dir,
                                "size": format_size(os.path.getsize(entry_path)) if not is_dir else "",
                            })
                        items.sort(key=lambda item: (not item["is_dir"], item["name"].lower()))
                        send_json(self, {"location": os.path.basename(directory) or directory, "items": items})
                    except (ValueError, OSError, IndexError) as error:
                        send_json(self, {"error": str(error)}, 404)
                    return

                if parsed.path == "/api/file":
                    if not self._authenticated():
                        self._send_auth_error()
                        return
                    query = urllib.parse.parse_qs(parsed.query)
                    try:
                        root_index = int(query["root"][0])
                        relative = query.get("path", [""])[0]
                        _, file_path = resolve_path(root_index, relative)
                        if not os.path.isfile(file_path):
                            raise ValueError("File not found")
                        file_size = os.path.getsize(file_path)
                        if file_size > max_file_size:
                            send_json(self, {"error": "Files larger than 256 MiB are not supported."}, 413)
                            return
                        filename = os.path.basename(file_path)
                        with open(file_path, "rb") as file_handle:
                            plaintext = file_handle.read()
                        file_key = derive_file_key(password_key, salt)
                        nonce, ciphertext = encrypt_file(plaintext, file_key, filename.encode("utf-8"))
                        self.send_response(200)
                        self.send_header("Content-Type", "application/octet-stream")
                        self.send_header("Content-Length", str(len(ciphertext)))
                        self.send_header("X-File-Nonce", base64.b64encode(nonce).decode("ascii"))
                        self.send_header("X-File-SHA256", sha256_hex(plaintext))
                        self.send_header("Cache-Control", "no-store")
                        self.send_header("X-Content-Type-Options", "nosniff")
                        self.end_headers()
                        self.wfile.write(ciphertext)
                        _log("info", f"[ENCRYPTED] Sent {filename} ({format_size(file_size)}); client verifies SHA-256")
                    except (ValueError, OSError, KeyError, IndexError) as error:
                        send_json(self, {"error": str(error)}, 404)
                    return

                send_404(self)
            finally:
                _conn("disconnect")

        def do_POST(self):
            _conn("connect")
            try:
                parsed = urllib.parse.urlsplit(self.path)
                if parsed.path == "/api/login":
                    try:
                        length = int(self.headers.get("Content-Length", "0"))
                        if length <= 0 or length > 4096:
                            raise ValueError("Invalid login request")
                        payload = json.loads(self.rfile.read(length))
                        nonce = payload["nonce"]
                        proof = payload["proof"]
                        with state_lock:
                            expiry = challenges.pop(nonce, None)
                        if not expiry or expiry < time.time():
                            raise ValueError("Login challenge expired. Try again.")
                        expected = hmac.new(password_key, bytes.fromhex(nonce), hashlib.sha256).hexdigest()
                        if not hmac.compare_digest(expected, proof):
                            raise ValueError("Incorrect password")
                        token = secrets.token_urlsafe(32)
                        with state_lock:
                            sessions[token] = time.time() + SESSION_LIFETIME
                        data = b'{"authenticated":true}'
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json; charset=utf-8")
                        self.send_header("Content-Length", str(len(data)))
                        self.send_header("Set-Cookie", f"ss_session={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={SESSION_LIFETIME}")
                        self.send_header("Cache-Control", "no-store")
                        self.end_headers()
                        self.wfile.write(data)
                    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
                        send_json(self, {"error": str(error)}, 401)
                    return

                if parsed.path == "/api/logout":
                    token = self._session_token()
                    with state_lock:
                        if token:
                            sessions.pop(token, None)
                    data = b'{"authenticated":false}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Set-Cookie", "ss_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0")
                    self.end_headers()
                    self.wfile.write(data)
                    return

                send_404(self)
            finally:
                _conn("disconnect")

    return Handler


def _create_secure_server(roots: list[dict], port: int, password: str):
    salt = secrets.token_bytes(16)
    password_key = derive_password_key(password, salt)
    server = ThreadingHTTPServer(("0.0.0.0", port), make_secure_handler(roots, password_key, salt))
    server.daemon_threads = True
    tls_context, fingerprint = create_tls_context()
    server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    return server, fingerprint


def start_server(roots: list[dict], port: int = 8765, password: str | None = None):
    """Start the authenticated HTTPS file server and block until stopped."""
    password = password or getpass.getpass("SecureShare sharing password (12+ characters): ")
    if len(password) < 12:
        raise ValueError("Use a sharing password with at least 12 characters.")
    server, fingerprint = _create_secure_server(roots, port, password)
    ip = get_local_ip()
    _log("info", "\n  SecureShare HTTPS server running")
    _log("info", f"  On this device: https://127.0.0.1:{port}")
    _log("info", f"  WLAN access:   https://{ip}:{port}")
    _log("warning", f"  Certificate SHA-256 fingerprint: {fingerprint}")
    cert_path = Path(os.environ.get("APPDATA", Path.home() / ".config")) / "SecureShare" / "server-cert.pem"
    _log("warning", f"  Client trust file: {cert_path}")
    _log("warning", "  Trust this certificate on clients and compare its fingerprint before sharing.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _log("warning", "\n  Server stopped.")
    finally:
        server.server_close()


def start_server_background(roots: list[dict], port: int = 8765, password: str | None = None) -> ThreadingHTTPServer:
    """Start the authenticated HTTPS server in a background daemon thread."""
    if not password or len(password) < 12:
        raise ValueError("Use a sharing password with at least 12 characters.")
    server, fingerprint = _create_secure_server(roots, port, password)
    ip = get_local_ip()
    _log("info", f"  SecureShare running at https://{ip}:{server.server_port}")
    _log("warning", f"  Certificate SHA-256 fingerprint: {fingerprint}")
    cert_path = Path(os.environ.get("APPDATA", Path.home() / ".config")) / "SecureShare" / "server-cert.pem"
    _log("warning", f"  Client trust file: {cert_path}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
