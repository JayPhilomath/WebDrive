"""WebDrive - temporary file transfer between devices on a local network.

Single Flask app, one shared password, no user accounts. Served by cheroot.
Not intended to face the internet.
"""

from __future__ import annotations

import argparse
import os
import secrets
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.datastructures import FileStorage
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


# ---------------------------------------------------------------------------
# SECTION: constants, defaults, tunables
# ---------------------------------------------------------------------------

DEFAULT_MAX_UPLOAD_MB = 1024
DEFAULT_THREADS = 16
MAX_FILENAME_LENGTH = 120
MAX_NAME_COLLISION_ATTEMPTS = 500

# Login throttle. There is one shared password, so without a limit anyone who
# can reach the port can brute-force it at network speed.
# Five free attempts is a guess: high enough that a couple of typos cost
# nothing, low enough that automated guessing stalls almost immediately.
LOGIN_FREE_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 5
LOGIN_LOCKOUT_MAX_SECONDS = 15 * 60
LOGIN_FAILURE_TTL = 60 * 60

# ip -> (consecutive failures, monotonic time of the last failure).
# In-process and cleared on restart. Correct for one process; running multiple
# workers would need a shared store, and each worker would throttle separately.
_login_failures: Dict[str, tuple[int, float]] = {}
_login_lock = threading.Lock()


# ---------------------------------------------------------------------------
# SECTION: paths, pyinstaller, frozen bundle, app home
# ---------------------------------------------------------------------------

FROZEN = getattr(sys, "frozen", False)

# PyInstaller unpacks templates/ and static/ into a temp directory
# (sys._MEIPASS) which is not where the .exe sits. Two different roots, and
# mixing them up gives a build that runs from source but not once frozen.
BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))

# User data goes beside the executable, never in cwd. A double-clicked .exe
# inherits whatever working directory Explorer hands it, which is not
# predictable and is occasionally somewhere unwanted.
APP_HOME = Path(sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# SECTION: flask app, session cookies
# ---------------------------------------------------------------------------

app = Flask(
    __name__,
    static_folder=str(BUNDLE_DIR / "static"),
    template_folder=str(BUNDLE_DIR / "templates"),
)
app.config["SECRET_KEY"] = secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
# These are the values in force before configure() runs. An unconfigured
# import must not end up more permissive than a configured one, so Secure
# starts on and configure() turns it off only when there is no TLS to require.
app.config["SESSION_COOKIE_SECURE"] = True
app.config["MAX_CONTENT_LENGTH"] = DEFAULT_MAX_UPLOAD_MB * 1024 * 1024
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)


# ---------------------------------------------------------------------------
# SECTION: runtime config, configure, startup state
# ---------------------------------------------------------------------------


@dataclass
class RuntimeConfig:
    base_dir: Path
    auth_password_hash: Optional[str]
    max_upload_bytes: int
    https_enabled: bool
    csrf_header_name: str = "X-CSRF-Token"
    configured: bool = False


# Starts unconfigured on purpose. configure() applies every security-relevant
# setting, and until it runs prepare_session() rejects all requests with 503.
# Without that, importing this module under a WSGI server would serve the
# working directory with authentication switched off and no warning.
CONFIG = RuntimeConfig(
    base_dir=Path.cwd(),
    auth_password_hash=None,
    max_upload_bytes=DEFAULT_MAX_UPLOAD_MB * 1024 * 1024,
    https_enabled=False,
)


def configure(
    base_dir: Path | str,
    password: Optional[str] = None,
    max_upload_mb: int = DEFAULT_MAX_UPLOAD_MB,
    https_enabled: bool = False,
) -> RuntimeConfig:
    """Apply runtime settings and mark the app ready to serve.

    Must run before the first request, including from a WSGI entry point such
    as gunicorn, waitress or `flask run`.
    """
    global CONFIG

    resolved_base = Path(base_dir).expanduser().resolve()
    ensure_directory_exists(resolved_base)

    app.config["MAX_CONTENT_LENGTH"] = max(1, max_upload_mb) * 1024 * 1024
    app.config["SECRET_KEY"] = secrets.token_hex(32)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
    app.config["SESSION_COOKIE_SECURE"] = bool(https_enabled)
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)

    CONFIG = RuntimeConfig(
        base_dir=resolved_base,
        auth_password_hash=generate_password_hash(password) if password else None,
        max_upload_bytes=app.config["MAX_CONTENT_LENGTH"],
        https_enabled=bool(https_enabled),
        configured=True,
    )
    return CONFIG


# ---------------------------------------------------------------------------
# SECTION: path containment, traversal, share boundary
# ---------------------------------------------------------------------------


def ensure_directory_exists(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)


def is_within_base(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def resolve_subpath(relative_path: str) -> Path:
    """Resolve a client-supplied path and reject anything outside the share.

    Resolve first, then compare. Checking the string for ".." before resolving
    misses symlinks, junctions and Windows short names.
    """
    relative_path = (relative_path or "").strip().strip("/\\")
    target_path = (CONFIG.base_dir / relative_path).resolve()
    if not is_within_base(target_path, CONFIG.base_dir):
        abort(400, "Invalid path")
    return target_path


# ---------------------------------------------------------------------------
# SECTION: formatting, local ip lookup
# ---------------------------------------------------------------------------


def human_readable_size(num_bytes: int) -> str:
    if num_bytes is None:
        return "-"
    step_unit = 1024.0
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < step_unit:
            return f"{num_bytes:.0f} {unit}" if unit == "B" else f"{num_bytes:.1f} {unit}"
        num_bytes /= step_unit
    return f"{num_bytes:.1f} PB"


def get_local_ip() -> str:
    """Best guess at the LAN address to print at startup.

    Opens a UDP socket to a public address to find out which interface the
    routing table prefers. Nothing is sent and no connection is made. Hosts
    with several interfaces may still get the wrong one, in which case pass
    --host explicitly.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except Exception:
        return "127.0.0.1"


# ---------------------------------------------------------------------------
# SECTION: auth, session, csrf tokens
# ---------------------------------------------------------------------------


def auth_enabled() -> bool:
    return bool(CONFIG.auth_password_hash)


def is_authenticated() -> bool:
    return bool(session.get("authenticated"))


def ensure_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def require_csrf() -> None:
    expected = session.get("csrf_token") or ""
    provided = request.headers.get(CONFIG.csrf_header_name, "") or request.form.get("csrf_token", "")
    # Compare bytes, not str. compare_digest raises TypeError on non-ASCII str,
    # which turns a malformed token into a 500 instead of a 403.
    if not expected or not secrets.compare_digest(expected.encode("utf-8"), provided.encode("utf-8")):
        abort(403, "Invalid CSRF token")


def wants_json() -> bool:
    return request.path.startswith("/api/") or request.headers.get("Accept", "").startswith(
        "application/json"
    )


def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(view)
    def wrapped_view(*args: Any, **kwargs: Any) -> Any:
        if not auth_enabled() or is_authenticated():
            return view(*args, **kwargs)

        # API callers get a status code they can act on; browsers get sent to
        # the login page. Redirecting an XHR would hand it back HTML.
        if wants_json():
            return jsonify({"error": "Authentication required"}), 401
        return redirect(url_for("login", next=request.full_path if request.query_string else request.path))

    return wrapped_view


# ---------------------------------------------------------------------------
# SECTION: login throttle, rate limit, lockout, backoff
# ---------------------------------------------------------------------------


def _login_client_key() -> str:
    # remote_addr only. X-Forwarded-For is deliberately not read: nothing sits
    # in front of this app, so the header would be attacker-controlled and
    # anyone could reset their own limit by setting it.
    return request.remote_addr or "unknown"


def login_lockout_remaining() -> float:
    """Seconds the caller must wait before the next attempt. 0 means clear."""
    now = time.monotonic()
    with _login_lock:
        entry = _login_failures.get(_login_client_key())
    if not entry:
        return 0.0

    failures, last_failure = entry
    if failures < LOGIN_FREE_ATTEMPTS:
        return 0.0

    # Wait doubles for each failure past the free allowance, up to the cap.
    penalty = min(
        LOGIN_LOCKOUT_SECONDS * (2 ** (failures - LOGIN_FREE_ATTEMPTS)),
        LOGIN_LOCKOUT_MAX_SECONDS,
    )
    return max(0.0, (last_failure + penalty) - now)


def record_login_failure() -> None:
    key = _login_client_key()
    now = time.monotonic()
    with _login_lock:
        # Prune on write. Keeps the dict bounded without a background thread,
        # and failures are the only thing that adds to it.
        for stale in [k for k, (_, seen) in _login_failures.items() if now - seen > LOGIN_FAILURE_TTL]:
            del _login_failures[stale]
        failures = _login_failures.get(key, (0, now))[0]
        _login_failures[key] = (failures + 1, now)
    print(f"[auth] failed login from {key} (attempt {failures + 1})")


def clear_login_failures() -> None:
    with _login_lock:
        _login_failures.pop(_login_client_key(), None)


# ---------------------------------------------------------------------------
# SECTION: upload filenames, sanitising, collisions
# ---------------------------------------------------------------------------


def bound_filename_length(safe_name: str) -> str:
    """Cap a sanitised name so long uploads do not exceed MAX_PATH on Windows.

    secure_filename() passes 300-character names straight through, so this has
    to be a separate step.
    """
    if len(safe_name) <= MAX_FILENAME_LENGTH:
        return safe_name
    basename, ext = os.path.splitext(safe_name)
    ext = ext[:16]
    return (basename[: MAX_FILENAME_LENGTH - len(ext)] or "unnamed") + ext


def save_without_clobbering(storage: FileStorage, target_dir: Path, safe_name: str) -> Path:
    """Write an upload under a free name, creating the file exclusively.

    Calling exists() and then save() is a race: two uploads of the same name
    can both pick the same free slot, and the second overwrites the first with
    no error. Opening with "x" makes the create atomic, so a collision fails
    and the loop moves to the next candidate.
    """
    basename, ext = os.path.splitext(safe_name)
    for attempt in range(MAX_NAME_COLLISION_ATTEMPTS):
        candidate = target_dir / (safe_name if attempt == 0 else f"{basename} ({attempt}){ext}")
        try:
            with open(candidate, "xb") as handle:
                storage.save(handle)
            return candidate
        except FileExistsError:
            continue
    abort(409, "Could not find a free filename for this upload")


# ---------------------------------------------------------------------------
# SECTION: redirect safety, open redirect
# ---------------------------------------------------------------------------


def safe_next_url(candidate: str) -> str:
    """Return candidate only if a browser will treat it as a site-local path.

    Browsers strip C0 control characters out of URLs and read "\\" as "/", so
    "/\\evil.com" and "/<TAB>/evil.com" both end up at "//evil.com" and leave
    the site. Python's urlsplit does not apply either rule and reports an empty
    netloc for both, so it cannot be used to make this decision. Normalise the
    way a browser would first, then test.
    """
    value = (candidate or "").strip()
    probe = "".join(ch for ch in value if ch >= " " and ch != "\x7f").replace("\\", "/")
    if probe.startswith("/") and not probe.startswith("//"):
        return value
    return url_for("index")


# ---------------------------------------------------------------------------
# SECTION: request hooks, security headers, csp
# ---------------------------------------------------------------------------


@app.before_request
def prepare_session() -> None:
    if not CONFIG.configured:
        abort(503, "WebDrive is not configured - call configure() from your entry point")
    ensure_csrf_token()


@app.after_request
def apply_security_headers(response):  # type: ignore[no-untyped-def]
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if CONFIG.https_enabled:
        # No includeSubDomains. This binds to a LAN address that may also host
        # unrelated services, and forcing HTTPS on all of them is not wanted.
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["Permissions-Policy"] = "clipboard-read=(self), clipboard-write=(self)"
    # All assets are local, so everything can be locked to 'self'. data: and
    # blob: are needed for img-src because pasted images are previewed as blobs.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    return response


# ---------------------------------------------------------------------------
# SECTION: routes - login, logout
# ---------------------------------------------------------------------------


@app.get("/login")
def login():
    if not auth_enabled():
        return redirect(url_for("index"))
    if is_authenticated():
        return redirect(url_for("index"))
    next_url = safe_next_url(request.args.get("next", "/"))
    return render_template("login.html", next_url=next_url)


@app.post("/login")
def login_post() -> Any:
    if not auth_enabled():
        return redirect(url_for("index"))

    next_url = safe_next_url(request.form.get("next", "/"))

    # Checked before the password. Throttling only wrong guesses would let an
    # attacker confirm a correct password while supposedly locked out.
    wait = login_lockout_remaining()
    if wait > 0:
        return (
            render_template(
                "login.html",
                next_url=next_url,
                error=f"Too many failed attempts. Try again in {int(wait) + 1}s.",
            ),
            429,
        )

    password = request.form.get("password", "")
    if not check_password_hash(CONFIG.auth_password_hash or "", password):
        record_login_failure()
        return (
            render_template("login.html", next_url=next_url, error="Incorrect password"),
            401,
        )

    clear_login_failures()
    # Clear before setting. A fresh session id on login stops anyone who
    # planted a known session id from riding it once the password is entered.
    session.clear()
    session["authenticated"] = True
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True
    return redirect(next_url)


@app.post("/logout")
@login_required
def logout() -> Any:
    require_csrf()
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# SECTION: routes - index page
# ---------------------------------------------------------------------------


@app.get("/")
@login_required
def index():
    # Only the folder name reaches the client, never the full path. The
    # absolute path leaks the account name and the layout of the host.
    return render_template(
        "index.html",
        app_config={
            "shareRootName": CONFIG.base_dir.name,
            "csrfToken": ensure_csrf_token(),
            "authEnabled": auth_enabled(),
            "httpsEnabled": CONFIG.https_enabled,
            "maxUploadBytes": CONFIG.max_upload_bytes,
        },
    )


# ---------------------------------------------------------------------------
# SECTION: routes - api list, upload, download, ping
# ---------------------------------------------------------------------------


@app.get("/api/list")
@login_required
def api_list() -> Any:
    rel = request.args.get("p", "")
    target_dir = resolve_subpath(rel)
    if not target_dir.exists() or not target_dir.is_dir():
        abort(404, "Directory not found")

    entries: List[Dict[str, Any]] = []
    for child in target_dir.iterdir():
        try:
            # The listing has to agree with what download will serve.
            # resolve_subpath refuses anything outside the share, so entries
            # that point outside should not appear here exposing their size and
            # mtime either.
            # Tested by resolving rather than calling is_symlink(), which
            # returns False for Windows directory junctions and misses them.
            if not is_within_base(child.resolve(), CONFIG.base_dir):
                continue
            stat = child.stat()
        except OSError:
            # Locked, deleted mid-scan, or permission denied. Skip it rather
            # than failing the whole listing over one bad entry.
            continue

        is_dir = child.is_dir()
        entries.append(
            {
                "name": child.name,
                "is_dir": is_dir,
                "size": None if is_dir else stat.st_size,
                "size_human": None if is_dir else human_readable_size(stat.st_size),
                "mtime": stat.st_mtime,
                "mtime_iso": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                "path": str((Path(rel) / child.name).as_posix()).lstrip("./"),
            }
        )

    # Folders first, then case-insensitive by name.
    entries.sort(key=lambda entry: (not entry["is_dir"], entry["name"].lower()))
    return jsonify(
        {
            "cwd": rel or "",
            "entries": entries,
            "root_name": CONFIG.base_dir.name,
            "auth_enabled": auth_enabled(),
            "https_enabled": CONFIG.https_enabled,
        }
    )


@app.post("/api/upload")
@login_required
def api_upload() -> Any:
    require_csrf()
    rel = request.args.get("p", "")
    target_dir = resolve_subpath(rel)
    ensure_directory_exists(target_dir)

    files = request.files.getlist("files")
    if not files:
        abort(400, "No files uploaded")

    saved: List[Dict[str, Any]] = []
    for storage in files:
        # secure_filename strips any directory part, so a filename cannot be
        # used to escape target_dir. It also transliterates to ASCII, which
        # mangles non-Latin names - see todo.md.
        original_name = storage.filename or "unnamed"
        safe_name = bound_filename_length(secure_filename(original_name) or "unnamed")
        save_path = save_without_clobbering(storage, target_dir, safe_name)
        stat = save_path.stat()
        saved.append(
            {
                "saved_as": save_path.name,
                "size": stat.st_size,
                "size_human": human_readable_size(stat.st_size),
                "mtime_iso": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            }
        )

    return jsonify({"ok": True, "saved": saved})


@app.get("/d/<path:subpath>")
@login_required
def download(subpath: str):
    file_path = resolve_subpath(subpath)
    if not file_path.exists() or not file_path.is_file():
        abort(404, "File not found")
    # as_attachment forces a download rather than rendering in the browser.
    # Without it an uploaded .html or .svg would run as a page on this origin.
    return send_from_directory(
        file_path.parent,
        file_path.name,
        as_attachment=True,
        download_name=file_path.name,
    )


@app.get("/api/ping")
def api_ping() -> Any:
    # Reachability check, intentionally unauthenticated. Returns no
    # configuration detail, since anyone on the network can call it.
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# SECTION: cli arguments, password loading
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WebDrive - local network file share")
    parser.add_argument(
        "--dir",
        dest="directory",
        default=str(APP_HOME / "shared"),
        help="Directory to serve (defaults to a 'shared' folder beside the app, created if missing)",
    )
    parser.add_argument("--host", dest="host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", dest="port", type=int, default=7071, help="Port")
    parser.add_argument(
        "--password",
        dest="password",
        default="",
        help="Optional browser access password. Prefer --password-file on shared systems.",
    )
    parser.add_argument(
        "--password-file",
        dest="password_file",
        default="",
        help="Optional file containing the browser access password.",
    )
    parser.add_argument(
        "--max-upload-mb",
        dest="max_upload_mb",
        type=int,
        default=1024,
        help="Maximum upload size per request in MB (default: 1024)",
    )
    parser.add_argument(
        "--cert",
        dest="cert_file",
        default="",
        help="Optional TLS certificate file for HTTPS.",
    )
    parser.add_argument(
        "--key",
        dest="key_file",
        default="",
        help="Optional TLS private key file for HTTPS.",
    )
    parser.add_argument(
        "--threads",
        dest="threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Worker threads for the HTTP server (default: {DEFAULT_THREADS})",
    )
    return parser.parse_args()


def load_password(args: argparse.Namespace) -> Optional[str]:
    """Read the password from a file if given, otherwise from --password.

    --password-file is preferred because arguments are visible to anyone who
    can list processes on the host.
    """
    if args.password_file:
        password_path = Path(args.password_file).expanduser().resolve()
        if not password_path.exists() or not password_path.is_file():
            raise FileNotFoundError(f"Password file not found: {password_path}")
        # strip() means a password cannot start or end with whitespace, which
        # is worth it to avoid a trailing newline silently breaking login.
        return password_path.read_text(encoding="utf-8").strip()

    password = (args.password or "").strip()
    return password or None


# ---------------------------------------------------------------------------
# SECTION: tls, certificates, ssl adapter
# ---------------------------------------------------------------------------


def build_ssl_context(args: argparse.Namespace) -> Optional[tuple[str, str]]:
    cert_file = (args.cert_file or "").strip()
    key_file = (args.key_file or "").strip()
    if not cert_file and not key_file:
        return None
    # Fail loudly on a half-configured pair. Starting on plain HTTP when the
    # user asked for HTTPS is worse than refusing to start.
    if not cert_file or not key_file:
        raise ValueError("Both --cert and --key are required to enable HTTPS")

    cert_path = Path(cert_file).expanduser().resolve()
    key_path = Path(key_file).expanduser().resolve()
    if not cert_path.exists() or not key_path.exists():
        raise FileNotFoundError("TLS certificate or key file does not exist")
    return (str(cert_path), str(key_path))


def build_ssl_adapter(ssl_context: tuple[str, str]):  # type: ignore[no-untyped-def]
    """Build cheroot's TLS adapter and force a floor of TLS 1.2.

    BuiltinSSLAdapter builds its context from ssl.create_default_context(),
    which still permits TLS 1.0 and 1.1 on some builds.
    """
    from cheroot.ssl.builtin import BuiltinSSLAdapter

    certificate, private_key = ssl_context
    adapter = BuiltinSSLAdapter(certificate=certificate, private_key=private_key)
    adapter.context.minimum_version = ssl.TLSVersion.TLSv1_2
    return adapter


# ---------------------------------------------------------------------------
# SECTION: http server, cheroot, wsgi
# ---------------------------------------------------------------------------


def serve(host: str, port: int, ssl_context: Optional[tuple[str, str]], threads: int) -> None:
    """Run the app on cheroot.

    Flask's built-in server is single-threaded and documented as unsuitable for
    real use; one large upload blocks everyone else from browsing.

    Cheroot rather than waitress, which is the more usual Windows choice,
    because waitress cannot terminate TLS. Using it would have meant dropping
    --cert/--key or requiring a reverse proxy alongside a single-file tool.
    """
    from cheroot.wsgi import Server

    server = Server(
        bind_addr=(host, port),
        wsgi_app=app,
        numthreads=max(1, threads),
        # server_name sets the "Server:" response header. Set explicitly so the
        # header does not carry the machine's hostname.
        server_name="WebDrive",
    )
    # Not the same field as server_name, which took a while to work out.
    # software is the SERVER_SOFTWARE value in the WSGI environ and defaults to
    # "Cheroot/<version> Server". It never reaches the client, but there is no
    # reason to keep the version in it.
    server.software = "WebDrive"
    if ssl_context:
        server.ssl_adapter = build_ssl_adapter(ssl_context)

    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# SECTION: startup banner, entry point, main
# ---------------------------------------------------------------------------


def print_banner(args: argparse.Namespace, ssl_context: Optional[tuple[str, str]]) -> None:
    local_ip = get_local_ip()
    scheme = "https" if ssl_context else "http"
    exposed = args.host not in {"127.0.0.1", "localhost", "::1"}

    print("\nWebDrive running")
    print(f"Share folder: {CONFIG.base_dir}")
    print(f"Open on this device: {scheme}://localhost:{args.port}")
    if exposed:
        print(f"Open on your LAN:   {scheme}://{local_ip}:{args.port}")
    print(f"Browser password: {'enabled' if auth_enabled() else 'disabled'}")
    print(f"HTTPS: {'enabled (certificate supplied)' if ssl_context else 'disabled'}")
    print(f"Server: cheroot, {max(1, args.threads)} threads")

    # Both of these are easy to forget, and neither is obvious from the UI once
    # it is running, so they are stated at startup instead.
    if exposed and not auth_enabled():
        print("\n  WARNING: reachable from the network with no password.")
        print("           Anyone on this network can browse, upload, and download.")
        print("           Use --password-file to protect it.")
    if exposed and not ssl_context:
        print("\n  NOTE: traffic is unencrypted, including the password at login.")
        print("        Use --cert/--key for HTTPS.")
    print("")


def main() -> int:
    args = parse_args()
    # TLS is resolved first because configure() needs to know whether to mark
    # the session cookie Secure.
    ssl_context = build_ssl_context(args)
    configure(
        base_dir=args.directory,
        password=load_password(args),
        max_upload_mb=args.max_upload_mb,
        https_enabled=bool(ssl_context),
    )
    print_banner(args, ssl_context)
    serve(args.host, args.port, ssl_context, args.threads)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001 - top-level guard for a console app
        print(f"\nWebDrive failed to start: {exc}", file=sys.stderr)
        if FROZEN and sys.stdin is not None and sys.stdin.isatty():
            # A double-clicked .exe closes its console as soon as it exits, so
            # without this the error is never readable. Only pause for a real
            # console: with stdin redirected, input() raises EOFError and the
            # message is lost again.
            try:
                input("\nPress Enter to close...")
            except (EOFError, KeyboardInterrupt):
                pass
        sys.exit(1)
