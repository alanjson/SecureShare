# Codebase Analysis — WiFi Home Server
### Project: Secure File Sharing over WLAN | Course: Introduction to Mobile Computing

---

## 1. Programming Languages & Frameworks

| Component | Technology |
|-----------|-----------|
| **Language** | Python 3.11+ |
| **GUI Framework** | [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) — a modern themed wrapper over Python's built-in `tkinter` |
| **HTTP Server** | Python stdlib `http.server.HTTPServer` + `BaseHTTPRequestHandler` (no external framework like Flask/Django) |
| **Threading** | Python stdlib `threading` module |
| **Networking** | Python stdlib `socket` + `urllib.parse` |
| **Build Tool** | PyInstaller (packages into a standalone `.exe`) |

**No external runtime dependencies other than `customtkinter`.** The HTTP server, file streaming, and networking code rely entirely on Python's standard library.

---

## 2. Project Folder Structure

```
WiFi-Home-Server-main/
│
├── main.py               ← Core HTTP server logic (backend engine)
├── gui.py                ← Desktop GUI application (frontend)
├── icon.ico              ← App icon (used in GUI and .exe)
│
├── Build.bat             ← Windows build script (pip install + PyInstaller)
├── WiFi-Home-Server.spec ← PyInstaller configuration file
│
├── images/               ← Screenshots for README
│   ├── banner.jpg
│   ├── 1.png
│   ├── 2.png
│   └── 3.png
│
├── .github/
│   └── workflows/        ← GitHub Actions CI/CD (not analyzed)
│
├── README.md             ← Setup and usage documentation
├── SECURITY.md           ← Security policy and best practices
├── CONTRIBUTING.md       ← Contribution guidelines
└── LICENSE               ← Apache 2.0 License
```

### Key Files (2 source files total)

| File | Role | Size |
|------|------|------|
| `main.py` | HTTP server engine — 443 lines | 17 KB |
| `gui.py` | Desktop GUI application — 668 lines | 31 KB |

---

## 3. How the Application Currently Works

The app is a **desktop file server** for Windows. Here is the complete flow:

### Step-by-step Flow

```
[User launches gui.py]
       │
       ▼
[WiFiServerApp GUI opens]
  • Reads local IP via get_local_ip()
  • Displays IP in status bar (e.g. 📡 192.168.1.100)
       │
       ▼
[User adds files/folders via GUI]
  • "Add Folder" → tkinter folder dialog → appends to self.roots list
  • "Add Files"  → tkinter file dialog   → appends to self.roots list
       │
       ▼
[User clicks "Start Server"]
  • Calls main.start_server_background(roots, port=8765)
  • Starts HTTPServer on 0.0.0.0:8765 in a daemon background thread
  • GUI remains responsive (non-blocking)
       │
       ▼
[Any device on the same WiFi opens: http://<PC_IP>:8765]
  • Browser receives an HTML directory listing
  • User can browse folders and click files to download them
       │
       ▼
[User clicks "Stop Server"]
  • Calls server.shutdown() in a background thread
  • GUI updates to "Server Stopped"
```

### GUI Panels

| Panel | Description |
|-------|-------------|
| **Home** | Split view: left = list of hosted items, right = controls (Add/Clear/Start/Stop), bottom = live console log |
| **Settings** | Configure server port (default 8765) and GitHub repo URL for update checks |
| **Credits** | About page with project info and links |

---

## 4. How File Transfer is Implemented

File transfer is implemented in `main.py` using **plain HTTP over TCP** — no external libraries.

### Key Functions in `main.py`

#### `get_local_ip()` — IP Detection
```python
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect(("8.8.8.8", 80))   # Dummy UDP — no data sent
ip = sock.getsockname()[0]       # OS reveals the active WiFi interface IP
```
Uses a dummy UDP connection trick to discover which network interface is active without sending any data.

#### `serve_file()` — File Streaming
```python
handler.send_header("Content-Type", "application/octet-stream")
handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
handler.send_header("Content-Length", str(file_size))

with open(full_path, "rb") as f:
    while True:
        chunk = f.read(65536)   # 64 KB chunks
        if not chunk:
            break
        handler.wfile.write(chunk)
```
- Protocol: **HTTP/1.x GET** (unencrypted plain-text)
- Transfer method: **Chunked binary streaming** (64 KB per read)
- Forces browser to show a "Save File" dialog via `Content-Disposition: attachment`
- Memory efficient — large files are never fully loaded into RAM

#### `make_handler()` — HTTP Request Router
Handles only `GET` requests:

| URL Pattern | Action |
|-------------|--------|
| `GET /` | Show root index listing all shared items |
| `GET /FolderName` | Show directory listing for that folder |
| `GET /FolderName/file.ext` | Download that file |
| Anything else | 404 Not Found |

#### `build_index_html()` / `build_dir_html()` — HTML Generation
Dynamically generates dark-themed HTML pages in Python using f-strings. No template engine used.

---

## 5. Client-Server Architecture

**Yes — it uses a classic Client-Server architecture.**

```
┌─────────────────────────────────┐      WiFi Network       ┌──────────────────────┐
│          SERVER (PC)            │◄──────────────────────►│    CLIENT (Any Device) │
│                                 │                         │                        │
│  gui.py → WiFiServerApp         │    HTTP (port 8765)     │  Web Browser           │
│  main.py → HTTPServer           │◄── GET / ─────────────  │  (Chrome, Safari, etc.)│
│  Binds to: 0.0.0.0:8765         │──► HTML response ──────►│                        │
│  Serves: files / directory HTML │◄── GET /file.zip ─────  │                        │
│                                 │──► Binary stream ──────►│  File saved to device  │
└─────────────────────────────────┘                         └──────────────────────┘
```

- **Server role**: The PC running `gui.py` / `main.py` hosts files and responds to HTTP requests
- **Client role**: Any device (phone, tablet, laptop) on the same WiFi — uses a plain web browser
- **No client-side app needed**: Transfer happens via standard HTTP in any browser
- **Protocol**: HTTP (plain-text, unencrypted)
- **Port**: Default `8765` (configurable in Settings)
- **Binding address**: `0.0.0.0` — listens on all network interfaces

---

## 6. Security Mechanisms Already Implemented

### ✅ What IS Implemented

| Mechanism | Location | Description |
|-----------|----------|-------------|
| **Path Traversal Prevention** | `main.py` line 368 | Checks that the resolved file path starts with the shared root path. Blocks `/../../../etc/passwd` style attacks. |
| **Read-Only Server** | `main.py` `make_handler()` | Only `GET` requests are handled. No `PUT`, `POST`, `DELETE` — clients cannot upload or modify files. |
| **Explicit Allowlist** | `main.py` `do_GET()` | Only files/folders explicitly added by the user are accessible. Unknown root names → 404. |
| **Permission Error Handling** | `main.py` `build_dir_html()` | `PermissionError` is caught and returns a user-friendly error page instead of crashing. |
| **Broken Pipe Handling** | `main.py` `serve_file()` | `BrokenPipeError` / `ConnectionResetError` handled silently so mid-download disconnects don't crash the server. |
| **Silent Request Logging** | `main.py` `log_message()` | Default per-request logs are suppressed (custom logging used instead). |

### ❌ What is NOT Implemented (Security Gaps)

| Missing Feature | Risk | Notes in SECURITY.md |
|----------------|------|----------------------|
| **Authentication / Password** | Anyone on the WiFi can access files | Explicitly mentioned in SECURITY.md as intentional for simplicity |
| **HTTPS / TLS Encryption** | Traffic is unencrypted (plain HTTP) | Vulnerable to passive network sniffing |
| **IP Whitelisting** | No ability to restrict which devices connect | Any device on the LAN can connect |
| **Rate Limiting** | No protection against brute force or DoS | Not implemented |
| **CSRF Protection** | Not applicable (read-only GET-only) | N/A |

> **SECURITY.md explicitly states:** *"The server intentionally lacks an authentication mechanism (like passwords or tokens) for maximum simplicity."*

---

## 7. How to Install Dependencies & Run the Project

### Prerequisites
- **Python 3.11 or newer** — [Download from python.org](https://www.python.org/downloads/)
- `pip` (comes bundled with Python)

### Step 1 — Install the only dependency
```bash
pip install customtkinter
```

### Step 2a — Run with GUI (recommended)
```bash
cd c:\Users\ALAN JAISON\Desktop\siuuu\WiFi-Home-Server-main
python gui.py
```
This opens the desktop application. Use the GUI to:
1. Click **＋ Add Folder** or **＋ Add Files** to select what to share
2. Click **▶ Start Server**
3. Note the IP shown in the status bar (e.g. `📡 192.168.1.100`)
4. On another device on the same WiFi, open `http://192.168.1.100:8765`

### Step 2b — Run headless from CLI (no GUI)
Edit the bottom of `main.py` to add your paths, then:
```bash
python main.py
```

### Step 3 (Optional) — Build a standalone .exe
```bash
Build.bat
```
This runs `pip install customtkinter pyinstaller` then `pyinstaller` to produce a single `WiFi-Home-Server.exe`.

---

## Summary Table

| Aspect | Details |
|--------|---------|
| **Language** | Python 3.11+ |
| **GUI** | CustomTkinter (tkinter wrapper) |
| **HTTP Engine** | Python stdlib `http.server` |
| **Transfer Protocol** | Plain HTTP (unencrypted) |
| **Port** | 8765 (configurable) |
| **Architecture** | Client-Server (browser-based client) |
| **File Transfer** | GET requests, chunked binary streaming (64 KB) |
| **Security** | Path traversal prevention, read-only, allowlist; **NO auth, NO HTTPS** |
| **Dependencies** | `customtkinter` only |
| **Entry Point** | `python gui.py` (GUI) or `python main.py` (CLI) |
| **Build** | PyInstaller → single `.exe` |
| **License** | Apache 2.0 |
