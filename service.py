#
#  GoogleFindMyTools - Traccar sync microservice
#
#  Exposes a Flask REST API that bridges Google Find My Device trackers
#  with a self-hosted Traccar GPS tracking server.
#
#  Usage:
#      python -m Traccar.service --server-url http://localhost:8082 --port 5002
#  or:
#      python Traccar/service.py  --server-url http://localhost:8082 --port 5002
#

import sys
import os
import io
import json
import random
import hashlib
import logging
import threading
import argparse
from datetime import date, datetime

import requests
from flask import Flask, jsonify, request as flask_request

# ---------------------------------------------------------------------------
# Make sure the project root is on sys.path so all NovaApi/* imports resolve
# regardless of how this file is launched.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from NovaApi.ListDevices.nbe_list_devices import request_device_list
from ProtoDecoders.decoder import parse_device_list_protobuf, get_canonic_ids
from Traccar.NopaApiExtend.location_request_extend import get_location_data_for_device_extended
from Traccar.notifier import send_notification

# ---------------------------------------------------------------------------
# Load .env from the Traccar/ directory before any os.environ.get() call.
# This is a no-op in Docker (env vars are already injected by docker-compose)
# and has no effect on env vars that are already set in the shell.
# ---------------------------------------------------------------------------
from dotenv import load_dotenv
load_dotenv(
    dotenv_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'),
    override=False,   # system / docker env vars always win
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

class _ColorFormatter(logging.Formatter):
    """Console formatter that colorizes log lines by level using ANSI codes."""
    _COLORS = {
        logging.DEBUG:    '\033[36m',    # cyan
        logging.WARNING:  '\033[33m',    # yellow
        logging.ERROR:    '\033[31m',    # red
        logging.CRITICAL: '\033[1;31m',  # bold red
    }
    _RESET = '\033[0m'

    def format(self, record: logging.LogRecord) -> str:
        color = self._COLORS.get(record.levelno, '')
        msg = super().format(record)
        return f'{color}{msg}{self._RESET}' if color else msg


def _setup_logging() -> logging.Logger:
    """Configures file + console logging in UTF-8, compatible with Windows."""
    log_dir = os.path.join(_PROJECT_ROOT, 'logs')
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, f"{date.today().strftime('%Y-%m-%d')}_service.log")

    _fmt     = '%(asctime)s.%(msecs)03d [%(levelname)-8s] %(message)s'
    _datefmt = '%Y-%m-%d %H:%M:%S'

    # File handler – plain text, UTF-8
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(fmt=_fmt, datefmt=_datefmt))

    # Console handler – colored output, UTF-8 for Windows compatibility
    if hasattr(sys.stdout, 'buffer'):
        utf8_stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
    else:
        utf8_stdout = sys.stdout
    console_handler = logging.StreamHandler(utf8_stdout)
    console_handler.setFormatter(_ColorFormatter(fmt=_fmt, datefmt=_datefmt))

    log = logging.getLogger('traccar_service')
    log.setLevel(logging.DEBUG)
    log.addHandler(file_handler)
    log.addHandler(console_handler)

    # Route werkzeug access logs through our formatter.
    # Clear its default stderr handler, inject ours, and suppress /health noise.
    class _NoHealthFilter(logging.Filter):
        def filter(self, record):
            return '/health' not in record.getMessage()

    wz = logging.getLogger('werkzeug')
    wz.handlers.clear()
    wz.addHandler(console_handler)
    wz.addHandler(file_handler)
    wz.addFilter(_NoHealthFilter())
    wz.propagate = False

    return log


# Module-level logger – handlers added at startup via _setup_logging()
logger = logging.getLogger('traccar_service')

# ---------------------------------------------------------------------------
# App & config
# ---------------------------------------------------------------------------

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Authentication – Bearer token
# Set API_TOKEN in the environment to enable; leave unset to disable (dev mode)
# ---------------------------------------------------------------------------

# Read once at startup; None → authentication disabled
_API_TOKEN: str | None = os.environ.get('API_TOKEN') or None

# ---------------------------------------------------------------------------
# Auto-registration config – read once at startup from environment
# ---------------------------------------------------------------------------
_AUTO_REGISTER: bool = os.environ.get('AUTO_REGISTER_SERVICES', 'true').strip().lower() not in ('0', 'false', 'no')
_AUTO_REGISTER_TIMER: int = int(os.environ.get('AUTO_REGISTER_TIMER', '120'))
_AUTO_REGISTER_DELTA: int = int(os.environ.get('AUTO_REGISTER_DELTA', '5'))


@app.before_request
def _log_request():
    body = flask_request.get_data(as_text=True)
    args = flask_request.args.to_dict()
    logger.debug(f"--> {flask_request.method} {flask_request.path} args={args} body={body} ")


@app.before_request
def _check_auth():
    if flask_request.endpoint in ('route_health', 'route_versions'):
        return  # public endpoints — no auth required
    if not _API_TOKEN:
        return  # authentication disabled (API_TOKEN not set)
    auth = flask_request.headers.get('Authorization', '')
    if not (auth.startswith('Bearer ') and auth[7:] == _API_TOKEN):
        logger.warning(
            f"[auth] Unauthorized {flask_request.method} {flask_request.path}"
            f" from {flask_request.remote_addr}"
        )
        return jsonify({'error': 'Unauthorized'}), 401


@app.route('/health', methods=['GET'])
def route_health():
    """Lightweight liveness probe — always public, no external calls."""
    if _auth_needs_reauth:
        return jsonify({'status': 'auth_required', 'services': len(_service_threads)}), 503
    return jsonify({'status': 'ok', 'services': len(_service_threads)})


_BUILD_INFO_FILE = os.path.join(os.path.dirname(__file__), '_build_info.json')


@app.route('/auth/aas-token', methods=['PUT'])
def route_put_aas_token():
    """
    Injects a new aas_token into Auth/secrets.json without restarting the service.
    Resets the auth_required flag and restarts all registered sync services.
    """
    global _auth_needs_reauth
    data = flask_request.get_json(silent=True) or {}
    new_token = data.get('aas_token', '').strip()
    if not new_token:
        return jsonify({'error': 'aas_token is required'}), 400

    # Persist the new token
    try:
        if os.path.exists(_AUTH_SECRETS_FILE):
            with open(_AUTH_SECRETS_FILE, 'r', encoding='utf-8') as f:
                secrets = json.load(f)
        else:
            secrets = {}
        secrets['aas_token'] = new_token
        with open(_AUTH_SECRETS_FILE, 'w', encoding='utf-8') as f:
            json.dump(secrets, f, indent=2)
        logger.info("[auth] aas_token updated via PUT /auth/aas-token")
    except Exception as exc:
        logger.error(f"[auth] Failed to write aas_token: {exc}")
        return jsonify({'error': str(exc)}), 500

    # Reset auth failure flag
    with _auth_lock:
        _auth_needs_reauth = False

    # Restart all registered services
    services = _load_services()
    for svc in services:
        did   = svc['id']
        name  = svc.get('name') or did
        timer = svc.get('timer', _AUTO_REGISTER_TIMER)
        delta = svc.get('delta', _AUTO_REGISTER_DELTA)
        _start_device_service(did, name, timer, delta)
    logger.info(f"[auth] {len(services)} sync service(s) restarted after token update")
    return jsonify({'status': 'ok', 'services_restarted': len(services)})


@app.route('/auth/secrets', methods=['PUT'])
def route_put_secrets():
    """
    Replaces the full contents of Auth/secrets.json.
    Use this to inject credentials into a fresh container that has no valid secrets file.
    Resets the auth_required flag and restarts all registered sync services.
    """
    global _auth_needs_reauth
    data = flask_request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'a JSON object is required'}), 400
    if not data.get('aas_token'):
        return jsonify({'error': 'aas_token is required in the secrets body'}), 400

    try:
        os.makedirs(os.path.dirname(_AUTH_SECRETS_FILE), exist_ok=True)
        with open(_AUTH_SECRETS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        logger.info("[auth] secrets.json replaced via PUT /auth/secrets")
    except Exception as exc:
        logger.error(f"[auth] Failed to write secrets.json: {exc}")
        return jsonify({'error': str(exc)}), 500

    # Reset auth failure flag
    with _auth_lock:
        _auth_needs_reauth = False

    # Restart all registered services
    services = _load_services()
    for svc in services:
        did   = svc['id']
        name  = svc.get('name') or did
        timer = svc.get('timer', _AUTO_REGISTER_TIMER)
        delta = svc.get('delta', _AUTO_REGISTER_DELTA)
        _start_device_service(did, name, timer, delta)
    logger.info(f"[auth] {len(services)} sync service(s) restarted after secrets upload")
    return jsonify({'status': 'ok', 'services_restarted': len(services)})


@app.route('/auth/token-status', methods=['POST'])
def route_post_token_status():
    """
    Sends an email reporting the current state, age, and expiry of the cached credentials.
    - AAS token age  : derived from secrets.json modification time
    - FCM token expiry: mtime + fcm_credentials.fcm.installation.expires_in
    """
    expired = _auth_needs_reauth
    secrets       = {}
    mtime         = None
    token_present = False
    fcm_exp       = None
    fcm_days_left = None

    if os.path.exists(_AUTH_SECRETS_FILE) and os.path.getsize(_AUTH_SECRETS_FILE) > 2:
        with open(_AUTH_SECRETS_FILE, 'r', encoding='utf-8') as f:
            try:
                secrets = json.load(f)
            except json.JSONDecodeError:
                pass
        token_present = bool(secrets.get('aas_token'))
        mtime         = datetime.fromtimestamp(os.path.getmtime(_AUTH_SECRETS_FILE))

        expires_in = (secrets
                      .get('fcm_credentials', {})
                      .get('fcm', {})
                      .get('installation', {})
                      .get('expires_in'))
        if mtime and expires_in:
            from datetime import timedelta
            fcm_exp       = mtime + timedelta(seconds=int(expires_in))
            fcm_days_left = (fcm_exp - datetime.now()).days

    # --- formatted strings ---
    mtime_str   = mtime.strftime('%Y-%m-%d %H:%M:%S')   if mtime   else None
    fcm_exp_str = fcm_exp.strftime('%Y-%m-%d %H:%M:%S') if fcm_exp else None
    delta       = datetime.now() - mtime if mtime else None
    age_str     = None
    if delta:
        d, h, m = delta.days, delta.seconds // 3600, (delta.seconds % 3600) // 60
        age_str = f"{d}j {h}h {m}min" if d else f"{h}h {m}min"

    # --- alert level ---
    if expired:
        level, status_line = 'error',   'EXPIRÉ — ré-authentification requise'
    elif not token_present:
        level, status_line = 'warning', 'ABSENT — aucun token dans secrets.json'
    elif fcm_days_left is not None and fcm_days_left <= 3:
        level, status_line = 'warning', f'VALIDE — token FCM expire dans {fcm_days_left}j'
    else:
        level, status_line = 'success', 'VALIDE'

    # --- email body ---
    sep = '─' * 48
    lines = [
        f"Rapport généré le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        sep,
        "  TOKEN AAS  (authentification Google)",
        sep,
        f"  Statut            : {'⚠ EXPIRÉ' if expired else ('✗ Absent' if not token_present else '✓ Valide')}",
    ]
    if mtime_str:
        lines += [
            f"  Dernière mise à jour : {mtime_str}",
            f"  Âge                  : {age_str}",
        ]
    lines += [
        "",
        sep,
        "  TOKEN FCM  (installation Firebase)",
        sep,
    ]
    if fcm_exp_str:
        if fcm_days_left is not None and fcm_days_left < 0:
            fcm_status = "✗ Expiré"
        elif fcm_days_left is not None and fcm_days_left <= 3:
            fcm_status = f"⚠ Expire dans {fcm_days_left}j"
        else:
            fcm_status = f"✓ Valide ({fcm_days_left}j restants)"
        lines += [
            f"  Statut            : {fcm_status}",
            f"  Expiration        : {fcm_exp_str}",
            f"    (= dernière mise à jour + {secrets.get('fcm_credentials',{}).get('fcm',{}).get('installation',{}).get('expires_in',0) // 86400}j)",
        ]
    else:
        lines.append("  Non disponible")
    lines += [
        "",
        sep,
        "  ACTIONS",
        sep,
        "  PUT /auth/aas-token  → renouveler le token AAS seul",
        "  PUT /auth/secrets    → remplacer le fichier complet",
    ]

    send_notification(
        subject=f"FineTrack — Statut du token : {status_line}",
        body='\n'.join(lines),
        alert_level=level,
    )
    logger.info(f"[auth] token-status email sent — {status_line}")

    return jsonify({
        'status':          'expired' if expired else ('absent' if not token_present else 'ok'),
        'token_present':   token_present,
        'last_updated':    mtime_str,
        'age':             age_str,
        'fcm_token_exp':   fcm_exp_str,
        'fcm_days_left':   fcm_days_left,
    })


@app.route('/notify/test', methods=['POST'])
def route_notify_test():
    """Sends a test email to verify SMTP configuration. Requires auth if API_TOKEN is set."""
    try:
        send_notification(
            subject="FineTrack — Test de notification",
            body=(
                "Ceci est un email de test envoyé depuis le service FineTrack.\n\n"
                f"Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                "Si vous recevez cet email, la configuration SMTP est correcte.\n"
            ),
        )
        logger.info("[notify] Test email triggered via POST /notify/test")
        return jsonify({'status': 'sent'})
    except Exception as exc:
        logger.error(f"[notify] Test email failed: {exc}")
        return jsonify({'status': 'error', 'message': str(exc)}), 500


@app.route('/versions', methods=['GET'])
def route_versions():
    """Returns the service version (git commit) and build date — always public."""
    try:
        with open(_BUILD_INFO_FILE) as f:
            info = json.load(f)
    except (FileNotFoundError, ValueError):
        info = {'version': 'dev', 'built_at': None}
    return jsonify(info)


@app.after_request
def _log_response(response):
    logger.debug(f"<-- {response.status_code} {flask_request.method} {flask_request.path}")
    return response


_DATA_DIR       = os.path.join(_PROJECT_ROOT, 'Data')
os.makedirs(_DATA_DIR, exist_ok=True)

_SERVICES_FILE          = os.path.join(_DATA_DIR, 'services.json')
_LOCATIONS_FILE         = os.path.join(_DATA_DIR, 'locations.json')
_DEVICES_FILE           = os.path.join(_DATA_DIR, 'devices.json')
_LOCATIONS_LOG_FILE     = os.path.join(_DATA_DIR, 'locations.log')
_EXCLUDED_DEVICES_FILE  = os.path.join(_DATA_DIR, 'excluded_devices.json')

_AUTH_SECRETS_FILE = os.path.join(_PROJECT_ROOT, 'Auth', 'secrets.json')

# Set at startup via --server-url argument
TRACCAR_SERVER_URL: str | None = None

# Background service registry  { device_id -> (Thread, Event) }
_service_threads:     dict[str, threading.Thread] = {}
_service_stop_events: dict[str, threading.Event]  = {}
# Timestamp (float) of last completed sync per device; None = never run yet
_service_last_sync:   dict[str, float | None]     = {}
# Timestamp (float) of next scheduled sync per device; None = first cycle not done yet
_service_next_sync:   dict[str, float | None]     = {}

# Auth failure state — set to True when a KeyError('Auth') is detected
_auth_needs_reauth: bool         = False
_auth_lock:         threading.Lock = threading.Lock()


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def _load_services() -> list:
    # Migrate legacy service.json → services.json on first run after rename
    _LEGACY_FILE = os.path.join(_DATA_DIR, 'service.json')
    if not os.path.exists(_SERVICES_FILE) and os.path.exists(_LEGACY_FILE):
        logger.info(f"[startup] Migrating {_LEGACY_FILE} → {_SERVICES_FILE}")
        with open(_LEGACY_FILE, 'r') as f:
            data = json.load(f)
        with open(_SERVICES_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    if not os.path.exists(_SERVICES_FILE):
        return []
    with open(_SERVICES_FILE, 'r') as f:
        services = json.load(f)
    needs_save = False
    for svc in services:
        # Migrate legacy device_id → id
        if 'device_id' in svc and 'id' not in svc:
            svc['id'] = svc.pop('device_id')
            needs_save = True
        # Backfill delta=5 for legacy entries that pre-date the field
        if 'delta' not in svc:
            svc['delta'] = 5
            needs_save = True
        # Backfill name from devices cache
        if 'name' not in svc:
            svc['name'] = _load_device_name(svc['id'])
            needs_save = True
    if needs_save:
        _save_services(services)
    return services


def _save_services(services: list) -> None:
    with open(_SERVICES_FILE, 'w') as f:
        json.dump(services, f, indent=2)


def _load_locations_db() -> dict:
    if not os.path.exists(_LOCATIONS_FILE):
        return {}
    with open(_LOCATIONS_FILE, 'r') as f:
        return json.load(f)


def _save_locations_db(data: dict) -> None:
    with open(_LOCATIONS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def _load_devices_db() -> list:
    if not os.path.exists(_DEVICES_FILE):
        return []
    with open(_DEVICES_FILE, 'r') as f:
        return json.load(f)


def _save_devices_db(devices: list) -> None:
    with open(_DEVICES_FILE, 'w') as f:
        json.dump(devices, f, indent=2)


def _load_excluded_devices() -> set[str]:
    if not os.path.exists(_EXCLUDED_DEVICES_FILE):
        return set()
    with open(_EXCLUDED_DEVICES_FILE, 'r') as f:
        return set(json.load(f))


def _save_excluded_devices(excluded: set[str]) -> None:
    with open(_EXCLUDED_DEVICES_FILE, 'w') as f:
        json.dump(sorted(excluded), f, indent=2)


def _refresh_devices() -> list:
    """Fetches device list from Google Find My, persists to devices.json, returns the list."""
    result_hex  = request_device_list()
    device_list = parse_device_list_protobuf(result_hex)
    canonic_ids = get_canonic_ids(device_list)
    devices = [{'id': cid, 'name': name} for name, cid in canonic_ids]

    # Detect devices absent from the previous devices.json.
    # Skip notification on first run (empty DB) to avoid a false-positive burst.
    known_ids   = {d['id'] for d in _load_devices_db()}
    new_devices = [d for d in devices if d['id'] not in known_ids]
    if known_ids and new_devices:
        logger.info(f"[devices] {len(new_devices)} new device(s): {[d['name'] for d in new_devices]}")
        device_lines = "\n".join(f"  • {d['name']} ({d['id']})" for d in new_devices)
        send_notification(
            subject=f"FineTrack — {len(new_devices)} nouveau(x) périphérique(s) détecté(s)",
            body=(
                f"{len(new_devices)} nouveau(x) périphérique(s) sont apparus dans votre compte Google :\n\n"
                f"{device_lines}\n\n"
                f"Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            ),
            alert_level='info',
        )

    _save_devices_db(devices)
    logger.info(f"[devices] Refreshed — {len(devices)} device(s): {[d['name'] for d in devices]}")
    return devices


def _load_device_name(device_id: str) -> str | None:
    """Returns the name of a device from the cached devices.json, or None if not found."""
    for d in _load_devices_db():
        if d['id'] == device_id:
            return d['name']
    return None


# ---------------------------------------------------------------------------
# Location helpers
# ---------------------------------------------------------------------------

def _compute_location_hash(location: dict) -> str:
    """Returns the MD5 hash of a location resource (id+lat+lon+timestamp)."""
    raw = f"{location['id']}{location['lat']}{location['lon']}{location['timestamp']}"
    return hashlib.md5(raw.encode()).hexdigest()


def _enrich_location(location: dict) -> dict:
    """Returns a copy of location with name, human-readable date and Google Maps URL added."""
    enriched = dict(location)
    enriched['name']     = _load_device_name(enriched['id'])
    enriched['date']     = datetime.fromtimestamp(enriched['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
    enriched['maps_url'] = f"https://www.google.com/maps/search/?api=1&query={enriched['lat']},{enriched['lon']}"
    return enriched


def _to_location_resource(device_id: str, loc: dict) -> dict:
    """Converts a raw location dict (from extract_locations) to a Location resource (4.8)."""
    return {
        'id':        device_id,
        'lat':       loc['latitude'],
        'lon':       loc['longitude'],
        'timestamp': loc['time'],
        'loc_status': loc['status'],
    }


def _fetch_device_locations(device_id: str) -> list:
    """Calls get_location_data_for_device_extended and returns Location resources."""
    raw = get_location_data_for_device_extended(device_id, _load_device_name(device_id) or device_id)
    # Keep only geo locations (semantic locations have no lat/lon)
    return [_to_location_resource(device_id, loc) for loc in raw if 'latitude' in loc]


def _get_new_locations(device_id: str, locations: list) -> list:
    """Returns only locations whose hash is not already stored in locations.json."""
    db = _load_locations_db()
    known = set(db.get(device_id, []))
    return [loc for loc in locations if _compute_location_hash(loc) not in known]


def _append_location_log(location: dict, traccar_http_status: int | None) -> None:
    """Appends one JSON line to locations.log for every Traccar push attempt."""
    entry = {
        **_enrich_location(location),
        'traccar_status': traccar_http_status,
        'synced_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    with open(_LOCATIONS_LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')


def _persist_location(location: dict) -> str:
    """Adds a location hash to locations.json. Returns the hash."""
    device_id = location['id']
    h = _compute_location_hash(location)
    db = _load_locations_db()
    if device_id not in db:
        db[device_id] = []
    if h not in db[device_id]:
        db[device_id].append(h)
    _save_locations_db(db)
    return h


def _send_to_traccar(device_id: str, location: dict) -> tuple[bool, int | None, str]:
    """POSTs a single location to the Traccar server. Returns (ok, http_status, message)."""
    if not TRACCAR_SERVER_URL:
        return False, None, "Traccar server URL not configured (use --server-url)"
    url = TRACCAR_SERVER_URL #f"{TRACCAR_SERVER_URL.rstrip('/')}" #/api/positions"
    payload = {
        'id':        device_id,
        'lat':       location['lat'],
        'lon':       location['lon'],
        'timestamp': location['timestamp'],
    }
    try:
        logger.debug(f"--> POST {url}  body={payload}")
        resp = requests.post(url, data=payload, timeout=10)
        logger.debug(f"<-- {resp.status_code} POST {url}  body={resp.text}")
        return resp.status_code in (200, 204), resp.status_code, resp.text
    except Exception as exc:
        logger.error(f"<-- ERROR POST {url}  {exc}")
        return False, None, str(exc)


# ---------------------------------------------------------------------------
# 4.1  GET /devices
# ---------------------------------------------------------------------------

@app.route('/devices', methods=['GET'])
def route_get_devices():
    """Fetches devices from Google Find My, updates devices.json, and returns the list."""
    devices = _refresh_devices()
    return jsonify(devices)


# ---------------------------------------------------------------------------
# 4.2 / 4.3  GET /devices/<device_id>/locations[?last]
# ---------------------------------------------------------------------------

@app.route('/devices/<device_id>/locations', methods=['GET'])
def route_get_device_locations(device_id):
    """
    Without ?last: returns all available Location resources for a device.
    With    ?last:  returns only the most recent Location resource.
    """
    want_last = 'last' in flask_request.args
    logger.info(f"[GET /devices/{device_id}/locations{'?last' if want_last else ''}] Fetching locations...")
    locations = _fetch_device_locations(device_id)
    if want_last:
        if not locations:
            logger.warning(f"[GET /devices/{device_id}/locations?last] No locations found")
            return jsonify({'error': 'No locations found'}), 404
        most_recent = max(locations, key=lambda x: x['timestamp'])
        logger.info(f"[GET /devices/{device_id}/locations?last] Most recent: lat={most_recent['lat']} lon={most_recent['lon']} ts={most_recent['timestamp']}")
        return jsonify(_enrich_location(most_recent))
    logger.info(f"[GET /devices/{device_id}/locations] {len(locations)} location(s) returned")
    return jsonify([_enrich_location(l) for l in locations])


# ---------------------------------------------------------------------------
# 4.4 / 4.5  PUT /traccar/devices/<device_id>/locations[?single]
# ---------------------------------------------------------------------------

@app.route('/traccar/devices/<device_id>/locations', methods=['PUT'])
def route_put_traccar_locations(device_id):
    """
    Without ?single: full sync pipeline for a device.
      1. Fetch all locations from Google Find My
      2. Filter out already-synced ones
      3. Push each new location to Traccar
      4. On success, record it locally
    Returns a list of per-location sync results.

    With ?single: pushes a single Location resource supplied in the request body.
    Returns {"status": "ok"} on success.
    """
    want_single = 'single' in flask_request.args

    if want_single:
        location = flask_request.get_json()
        logger.info(f"[PUT /traccar/devices/{device_id}/locations?single] Pushing ts={location.get('timestamp')} lat={location.get('lat')} lon={location.get('lon')}")
        ok, http_status, msg = _send_to_traccar(device_id, location)
        _append_location_log(location, http_status)
        if ok:
            logger.info(f"[PUT /traccar/devices/{device_id}/locations?single] Push OK")
            return jsonify({'status': 'ok'})
        logger.error(f"[PUT /traccar/devices/{device_id}/locations?single] Push failed: {msg}")
        return jsonify({'error': msg}), 500

    logger.info(f"[PUT /traccar/devices/{device_id}/locations] Starting full sync...")
    # Step 1 – fetch
    locations = _fetch_device_locations(device_id)
    logger.info(f"[PUT /traccar/devices/{device_id}/locations] {len(locations)} location(s) fetched")
    # Step 2 – filter
    new_locations = _get_new_locations(device_id, locations)
    logger.info(f"[PUT /traccar/devices/{device_id}/locations] {len(new_locations)} new (not yet synced)")
    results = []
    for loc in new_locations:
        # Step 3 – push to Traccar
        ok, http_status, msg = _send_to_traccar(device_id, loc)
        _append_location_log(loc, http_status)
        if ok:
            # Step 4 – persist
            _persist_location(loc)
            logger.info(f"[PUT /traccar/devices/{device_id}/locations]   synced ts={loc['timestamp']}")
            results.append({'location': _enrich_location(loc), 'status': 'synced'})
        else:
            logger.error(f"[PUT /traccar/devices/{device_id}/locations]   failed ts={loc['timestamp']}: {msg}")
            results.append({'location': _enrich_location(loc), 'status': 'error', 'message': msg})
    logger.info(f"[PUT /traccar/devices/{device_id}/locations] Done: {sum(1 for r in results if r['status']=='synced')}/{len(new_locations)} synced")
    return jsonify(results)


# ---------------------------------------------------------------------------
# 4.6  GET /services
# ---------------------------------------------------------------------------

@app.route('/services', methods=['GET'])
def route_list_services():
    """Returns all registered sync services with next_refresh_in_s indicator."""
    services = _load_services()
    now      = datetime.now().timestamp()
    result   = []
    for svc in services:
        did       = svc['id']
        last_sync = _service_last_sync.get(did)
        next_sync = _service_next_sync.get(did)
        last_sync_str     = datetime.fromtimestamp(last_sync).strftime('%Y-%m-%d %H:%M:%S') if last_sync else None
        next_refresh_in_s = max(0, round(next_sync - now)) if next_sync else 0
        result.append({
            **svc,
            'name':              _load_device_name(did),
            'last_sync':         last_sync_str,
            'next_refresh_in_s': next_refresh_in_s,
        })
    logger.info(f"[GET /services] {len(result)} service(s) listed")
    return jsonify(result)

# ---------------------------------------------------------------------------
# 4.6  GET /devices/<device_id>/services
# ---------------------------------------------------------------------------

@app.route('/devices/<device_id>/services', methods=['GET'])
def route_get_device_service(device_id):
    """Returns the sync service registered for a specific device."""
    services = _load_services()
    svc = next((s for s in services if s['id'] == device_id), None)
    if svc is None:
        logger.warning(f"[GET /devices/{device_id}/services] Service not found")
        return jsonify({'error': 'Service not found'}), 404
    logger.info(f"[GET /devices/{device_id}/services] timer={svc['timer']}s")
    return jsonify({**svc, 'name': _load_device_name(device_id)})


# ---------------------------------------------------------------------------
# 4.6  PUT /devices/<device_id>/services
# ---------------------------------------------------------------------------

@app.route('/devices/<device_id>/services', methods=['PUT'])
def route_put_device_service(device_id):
    """Adds or updates a periodic sync service for a device (Service resource 4.9)."""
    if device_id in _load_excluded_devices():
        logger.warning(f"[PUT /devices/{device_id}/service] Device is excluded — refusing")
        return jsonify({'error': 'Device is excluded from sync services'}), 403
    data  = flask_request.get_json()
    timer = int(data.get('timer', 60))
    delta = int(data.get('delta', 5))
    services = _load_services()
    for svc in services:
        if svc['id'] == device_id:
            svc['timer'] = timer
            svc['delta'] = delta
            svc['name']  = _load_device_name(device_id)
            _save_services(services)
            _start_device_service(device_id, svc['name'], timer, delta)
            logger.info(f"[PUT /devices/{device_id}/service] Updated timer={timer}s delta=±{delta}s")
            return jsonify({'id': device_id, 'name': svc['name'], 'timer': timer, 'delta': delta})
    name = _load_device_name(device_id)
    services.append({'id': device_id, 'name': name, 'timer': timer, 'delta': delta})
    _save_services(services)
    _start_device_service(device_id, name, timer, delta)
    logger.info(f"[PUT /devices/{device_id}/service] Created timer={timer}s delta=±{delta}s")
    return jsonify({'id': device_id, 'name': name, 'timer': timer, 'delta': delta}), 201


# ---------------------------------------------------------------------------
# 4.7  DELETE /devices/<device_id>/service
# ---------------------------------------------------------------------------

@app.route('/devices/<device_id>/services', methods=['DELETE'])
def route_delete_device_service(device_id):
    """Stops and removes a periodic sync service for a device."""
    services     = _load_services()
    new_services = [s for s in services if s['id'] != device_id]
    if len(new_services) == len(services):
        logger.warning(f"[DELETE /devices/{device_id}/service] Service not found")
        return jsonify({'error': 'Service not found'}), 404
    _save_services(new_services)
    _stop_device_service(device_id)
    logger.info(f"[DELETE /devices/{device_id}/service] Service deleted")
    return jsonify({'status': 'deleted'})


# ---------------------------------------------------------------------------
# Excluded devices – CRUD
# ---------------------------------------------------------------------------

@app.route('/excluded-devices', methods=['GET'])
def route_get_excluded_devices():
    """Returns the list of device IDs excluded from auto-registration."""
    excluded = _load_excluded_devices()
    names    = {d['id']: d.get('name', d['id']) for d in _load_devices_db()}
    result   = [{'id': did, 'name': names.get(did, did)} for did in sorted(excluded)]
    logger.info(f"[GET /excluded-devices] {len(result)} excluded device(s)")
    return jsonify(result)


@app.route('/excluded-devices/<device_id>', methods=['PUT'])
def route_put_excluded_device(device_id):
    """Adds a device to the exclusion list and stops its sync service if running."""
    excluded = _load_excluded_devices()
    already  = device_id in excluded
    excluded.add(device_id)
    _save_excluded_devices(excluded)
    services = _load_services()
    had_service = any(s['id'] == device_id for s in services)
    if had_service:
        _save_services([s for s in services if s['id'] != device_id])
        _stop_device_service(device_id)
        logger.info(f"[PUT /excluded-devices/{device_id}] Excluded — service stopped")
    else:
        logger.info(f"[PUT /excluded-devices/{device_id}] Excluded — no active service")
    return jsonify({'id': device_id, 'excluded': True}), (200 if already else 201)


@app.route('/excluded-devices/<device_id>', methods=['DELETE'])
def route_delete_excluded_device(device_id):
    """Removes a device from the exclusion list."""
    excluded = _load_excluded_devices()
    if device_id not in excluded:
        logger.warning(f"[DELETE /excluded-devices/{device_id}] Not in exclusion list")
        return jsonify({'error': 'Device not in exclusion list'}), 404
    excluded.discard(device_id)
    _save_excluded_devices(excluded)
    logger.info(f"[DELETE /excluded-devices/{device_id}] Removed from exclusion list")
    return jsonify({'id': device_id, 'excluded': False})


# ---------------------------------------------------------------------------
# 4.11  GET /locations?filter=<json-encoded-location-array>
# ---------------------------------------------------------------------------

@app.route('/locations', methods=['GET'])
def route_filter_locations():
    """
    Without ?filter: fetches the most recent live location for every registered device.
    With ?filter=<json>: filters the supplied Location array and returns only those
    not yet recorded in locations.json (checked by MD5 hash).
    """
    filter_param = flask_request.args.get('filter')

    # ---- No filter → live locations for all devices -------------------------
    if not filter_param:
        logger.info("[GET /locations] No filter — fetching live locations for all devices")
        devices = _load_devices_db() or _refresh_devices()
        logger.info(f"[GET /locations] {len(devices)} device(s) in cache")
        result = []
        for dev in devices:
            cid, name = dev['id'], dev['name']
            logger.info(f"[GET /locations]   fetching location for {name} ({cid})...")
            locations = _fetch_device_locations(cid)
            if not locations:
                logger.warning(f"[GET /locations]   no locations for {name} ({cid})")
                continue
            most_recent = max(locations, key=lambda x: x['timestamp'])
            logger.info(f"[GET /locations]   {name}: lat={most_recent['lat']} lon={most_recent['lon']} ts={most_recent['timestamp']}")
            result.append(_enrich_location(most_recent))
        logger.info(f"[GET /locations] Done — {len(result)}/{len(devices)} device(s) have a location")
        return jsonify(result)

    # ---- filter= → return only locations not yet synced ---------------------
    try:
        input_locations = json.loads(filter_param)
    except json.JSONDecodeError:
        logger.warning("[GET /locations] Invalid JSON in filter parameter")
        return jsonify({'error': 'filter must be a valid JSON array'}), 400

    db     = _load_locations_db()
    result = []
    for loc in input_locations:
        device_id = loc['id']
        h         = _compute_location_hash(loc)
        known     = set(db.get(device_id, []))
        if h not in known:
            result.append(_enrich_location(loc))
    logger.info(f"[GET /locations] filter: {len(input_locations)} in → {len(result)} new")
    return jsonify(result)


# ---------------------------------------------------------------------------
# 4.12  POST /locations
# ---------------------------------------------------------------------------

@app.route('/locations', methods=['POST'])
def route_add_location():
    """Records a Location resource as synced in locations.json."""
    loc = flask_request.get_json()
    h   = _persist_location(loc)
    logger.info(f"[POST /locations] Saved device={loc.get('id')} ts={loc.get('timestamp')} hash={h}")
    return jsonify({'status': 'saved', 'hash': h}), 201


# ---------------------------------------------------------------------------
# 4.10  Background periodic sync service
# ---------------------------------------------------------------------------

def _sync_device(device_id: str, name: str) -> None:
    """Runs one sync cycle for a device (replicates task 4.5 logic)."""
    tag = f"[sync] {name} ({device_id})"
    logger.info(f"{tag} Cycle starting...")
    locations = _fetch_device_locations(device_id)
    logger.info(f"{tag} {len(locations)} location(s) fetched from Google Find My")
    new_locations = _get_new_locations(device_id, locations)
    logger.info(f"{tag} {len(new_locations)} new (not yet synced to Traccar)")
    synced = 0
    failed = 0
    for loc in new_locations:
        ok, http_status, msg = _send_to_traccar(device_id, loc)
        _append_location_log(loc, http_status)
        if ok:
            _persist_location(loc)
            logger.info(f"{tag}   ✓ ts={loc['timestamp']}")
            synced += 1
        else:
            logger.error(f"{tag}   ✗ ts={loc['timestamp']}  reason={msg}")
            failed += 1
    _service_last_sync[device_id] = datetime.now().timestamp()
    if new_locations:
        logger.info(f"{tag} Cycle done — {synced} synced, {failed} failed")
    else:
        logger.info(f"{tag} Cycle done — nothing new to sync")


def _clear_cached_aas_token() -> None:
    """Removes the expired aas_token from Auth/secrets.json so the next startup triggers re-auth."""
    try:
        if not os.path.exists(_AUTH_SECRETS_FILE):
            logger.warning("[auth] Auth/secrets.json not found — nothing to clear")
            return
        with open(_AUTH_SECRETS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if 'aas_token' not in data:
            logger.warning("[auth] aas_token already absent from Auth/secrets.json")
            return
        del data['aas_token']
        with open(_AUTH_SECRETS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        logger.warning("[auth] Expired aas_token removed from Auth/secrets.json")
    except Exception as exc:
        logger.error(f"[auth] Failed to clear aas_token: {exc}")


def _stop_all_device_services() -> None:
    """Signals every background sync thread to stop and clears the registry."""
    device_ids = list(_service_stop_events.keys())
    for did in device_ids:
        _service_stop_events[did].set()
    for did in device_ids:
        _service_threads.pop(did, None)
        _service_stop_events.pop(did, None)
        _service_last_sync.pop(did, None)
        _service_next_sync.pop(did, None)
    logger.warning(f"[auth] {len(device_ids)} sync service(s) stopped")


def _handle_auth_failure(tag: str) -> None:
    """Called when KeyError('Auth') is detected. Clears the token and stops all services (once)."""
    global _auth_needs_reauth
    with _auth_lock:
        if _auth_needs_reauth:
            return  # another thread already handled it
        _auth_needs_reauth = True
    logger.error(f"{tag} Google OAuth token expired (KeyError: 'Auth')")
    logger.error("[auth] The cached AAS token is no longer accepted by Google")
    logger.error("[auth] Action required: restart the service to trigger re-authentication via Chrome")
    _clear_cached_aas_token()
    _stop_all_device_services()
    send_notification(
        subject="FineTrack — Ré-authentification Google requise",
        body=(
            "Le token OAuth Google (AAS token) a expiré.\n\n"
            "Action requise :\n"
            "  1. Obtenez un nouveau token via Auth/aas_token_retrieval.py\n"
            "     puis injectez-le sans redémarrer :\n"
            "     PUT /auth/aas-token  { \"aas_token\": \"aas_et/...\" }\n\n"
            "  Ou :\n"
            "  2. Redémarrez le service — le flux Chrome se relancera automatiquement.\n\n"
            f"Détail technique : {tag}\n"
            f"Heure           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        ),
        alert_level='error',
    )


def _run_device_service(device_id: str, name: str, timer: int, delta: int, stop_event: threading.Event) -> None:
    """Worker thread: runs immediately then waits `timer ± random(delta)` seconds between cycles."""
    tag   = f"[service] {name} ({device_id})"
    cycle = 0
    while True:
        if stop_event.is_set():
            logger.info(f"{tag} Stop signal received, exiting thread")
            break
        cycle += 1
        logger.info(f"{tag} --- Cycle #{cycle} ---")
        try:
            _sync_device(device_id, name)
        except KeyError as exc:
            if exc.args and exc.args[0] == 'Auth':
                _handle_auth_failure(tag)
                break
            logger.error(f"{tag} Unhandled error in cycle #{cycle}: {exc}")
        except Exception as exc:
            logger.error(f"{tag} Unhandled error in cycle #{cycle}: {exc}")
        jitter = random.uniform(-delta, delta)
        wait   = max(0, timer + jitter)
        _service_next_sync[device_id] = datetime.now().timestamp() + wait
        logger.info(f"{tag} Sleeping {wait:.1f}s (base={timer}s jitter={jitter:+.1f}s)")
        if stop_event.wait(wait):
            logger.info(f"{tag} Stop signal received during sleep, exiting thread")
            break


def _start_device_service(device_id: str, name: str, timer: int, delta: int = 5) -> None:
    """Starts (or restarts) the background sync thread for a device."""
    _stop_device_service(device_id)
    stop_event = threading.Event()
    thread = threading.Thread(
        target=_run_device_service,
        args=(device_id, name, timer, delta, stop_event),
        daemon=True,
        name=f"traccar-service-{device_id}",
    )
    _service_threads[device_id]     = thread
    _service_stop_events[device_id] = stop_event
    _service_last_sync[device_id]   = None
    _service_next_sync[device_id]   = None
    thread.start()
    logger.info(f"[service:{device_id}] Started — interval={timer}s delta=±{delta}s, thread={thread.name}")


def _stop_device_service(device_id: str) -> None:
    """Signals and removes the background sync thread for a device."""
    if device_id in _service_stop_events:
        logger.info(f"[service:{device_id}] Stopping...")
        _service_stop_events[device_id].set()
        _service_threads.pop(device_id, None)
        _service_stop_events.pop(device_id, None)
        _service_last_sync.pop(device_id, None)
        _service_next_sync.pop(device_id, None)
        logger.info(f"[service:{device_id}] Stopped and removed")


def _run_devices_refresh(stop_event: threading.Event) -> None:
    """Worker: refreshes devices.json immediately then every 3600 seconds."""
    cycle = 0
    while True:
        cycle += 1
        logger.info(f"[devices-refresh] Cycle #{cycle} — refreshing devices.json...")
        try:
            _refresh_devices()
        except KeyError as exc:
            if exc.args and exc.args[0] == 'Auth':
                _handle_auth_failure("[devices-refresh]")
                break
            logger.error(f"[devices-refresh] Error in cycle #{cycle}: {exc}")
        except Exception as exc:
            logger.error(f"[devices-refresh] Error in cycle #{cycle}: {exc}")
        if stop_event.wait(3600):
            logger.info("[devices-refresh] Stop signal received, exiting thread")
            break


def _start_devices_refresh() -> None:
    """Starts the hourly background thread that keeps devices.json up to date."""
    stop_event = threading.Event()
    thread = threading.Thread(
        target=_run_devices_refresh,
        args=(stop_event,),
        daemon=True,
        name="traccar-devices-refresh",
    )
    thread.start()
    logger.info("[devices-refresh] Started — interval=3600s, thread=traccar-devices-refresh")


def _auto_register_services() -> None:
    """Registers a sync service for every cached device not already registered and not excluded."""
    devices = _load_devices_db()
    if not devices:
        logger.info("[auto-register] Device cache empty, skipping cycle")
        return
    excluded     = _load_excluded_devices()
    services     = _load_services()
    registered   = {s['id'] for s in services}
    new_count    = 0
    new_devices: list[tuple[str, str]] = []
    for dev in devices:
        did  = dev['id']
        name = dev.get('name', did)
        if did in excluded:
            logger.info(f"[auto-register] {name} ({did}) — excluded")
            continue
        if did in registered:
            logger.debug(f"[auto-register] {name} ({did}) — already registered")
            continue
        services.append({'id': did, 'name': name, 'timer': _AUTO_REGISTER_TIMER, 'delta': _AUTO_REGISTER_DELTA})
        _save_services(services)
        registered.add(did)
        _start_device_service(did, name, _AUTO_REGISTER_TIMER, _AUTO_REGISTER_DELTA)
        logger.info(f"[auto-register] {name} ({did}) — registered timer={_AUTO_REGISTER_TIMER}s delta=±{_AUTO_REGISTER_DELTA}s")
        new_devices.append((did, name))
        new_count += 1
    if new_count == 0:
        logger.info("[auto-register] No new devices to register")
    else:
        logger.info(f"[auto-register] {new_count} new service(s) registered")
        device_lines = "\n".join(f"  • {name} ({did})" for did, name in new_devices)
        send_notification(
            subject=f"FineTrack — {new_count} nouveau(x) dispositif(s) enregistré(s)",
            body=(
                f"{new_count} nouveau(x) dispositif(s) ont été auto-enregistrés pour la synchronisation :\n\n"
                f"{device_lines}\n\n"
                f"Intervalle de sync : {_AUTO_REGISTER_TIMER}s ± {_AUTO_REGISTER_DELTA}s\n"
                f"Heure             : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            ),
            alert_level='success',
        )


def _run_auto_register(stop_event: threading.Event) -> None:
    """Worker: waits for the first device refresh, then auto-registers every 600 seconds."""
    # Give the devices-refresh thread time to complete its first fetch before cycle 1
    if stop_event.wait(5):
        return
    cycle = 0
    while True:
        cycle += 1
        logger.info(f"[auto-register] Cycle #{cycle} — checking devices...")
        try:
            _auto_register_services()
        except Exception as exc:
            logger.error(f"[auto-register] Error in cycle #{cycle}: {exc}")
        if stop_event.wait(600):
            logger.info("[auto-register] Stop signal received, exiting thread")
            break


def _start_auto_register() -> None:
    """Starts the background thread that periodically auto-registers sync services."""
    if not _AUTO_REGISTER:
        logger.info("[auto-register] Disabled via AUTO_REGISTER_SERVICES=false")
        return
    stop_event = threading.Event()
    thread = threading.Thread(
        target=_run_auto_register,
        args=(stop_event,),
        daemon=True,
        name="traccar-auto-register",
    )
    thread.start()
    excluded = _load_excluded_devices()
    excluded_label = ', '.join(sorted(excluded)) if excluded else 'none'
    logger.info(f"[auto-register] Started — interval=600s timer={_AUTO_REGISTER_TIMER}s delta=±{_AUTO_REGISTER_DELTA}s excluded=[{excluded_label}]")


def _enforce_exclusions() -> None:
    """Stops and removes any registered service whose device is in the exclusion list."""
    excluded = _load_excluded_devices()
    if not excluded:
        return
    services   = _load_services()
    to_remove  = [s for s in services if s['id'] in excluded]
    if not to_remove:
        return
    for svc in to_remove:
        did = svc['id']
        _stop_device_service(did)
        logger.info(f"[exclusions] Stopped service for excluded device {did}")
    _save_services([s for s in services if s['id'] not in excluded])
    logger.info(f"[exclusions] Removed {len(to_remove)} excluded service(s)")


def _start_all_services() -> None:
    """Loads services.json and starts a background thread for every registered service."""
    services = _load_services()
    logger.info(f"[startup] Loading {len(services)} service(s) from {_SERVICES_FILE}")
    for svc in services:
        delta = svc.get('delta', 5)
        name  = svc.get('name') or svc['id']
        logger.info(f"[startup]   → {name} ({svc['id']})  timer={svc['timer']}s  delta=±{delta}s")
        _start_device_service(svc['id'], name, svc['timer'], delta)
    if not services:
        logger.info("[startup] No services to restore")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Traccar sync microservice for Google Find My')
    parser.add_argument(
        '--server-url',
        type=str,
        default=os.environ.get('TRACCAR_SERVER_URL'),
        help='Traccar server base URL, e.g. http://localhost:8082 (env: TRACCAR_SERVER_URL)',
    )
    parser.add_argument(
        '--port',
        type=int,
        default=int(os.environ.get('PORT', 5002)),
        help='Port to expose the Flask service on (env: PORT, default: 5002)',
    )
    args = parser.parse_args()

    TRACCAR_SERVER_URL = args.server_url

    _setup_logging()
    logger.info(f"Starting Traccar sync service on port {args.port}")
    if _API_TOKEN:
        logger.info("Bearer token authentication enabled")
    else:
        logger.warning("API_TOKEN not set — authentication disabled (open access)")
    if TRACCAR_SERVER_URL:
        logger.info(f"Traccar server: {TRACCAR_SERVER_URL}")
    else:
        logger.warning("No --server-url provided; Traccar push routes will be disabled")

    _start_devices_refresh()
    _start_all_services()
    _enforce_exclusions()
    _start_auto_register()

    app.run(host='0.0.0.0', port=args.port, debug=False)
