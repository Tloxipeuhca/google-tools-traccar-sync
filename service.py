#
#  GoogleFindMyTools - Traccar sync microservice
#
#  Exposes a Flask REST API that bridges Google Find My Device trackers
#  with a self-hosted Traccar GPS tracking server.
#
#  Usage:
#      python -m Traccar.service --server-url http://localhost:8082 --port 5001
#  or:
#      python Traccar/service.py  --server-url http://localhost:8082 --port 5001
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

def _setup_logging() -> logging.Logger:
    """Configures file + console logging in UTF-8, compatible with Windows."""
    log_dir = os.path.join(_PROJECT_ROOT, 'logs')
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, f"{date.today().strftime('%Y-%m-%d')}_service.log")

    formatter = logging.Formatter(
        fmt='%(asctime)s [%(levelname)-8s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    # File handler – UTF-8
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)

    # Console handler – wrap stdout in UTF-8 for Windows compatibility
    if hasattr(sys.stdout, 'buffer'):
        utf8_stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
    else:
        utf8_stdout = sys.stdout
    console_handler = logging.StreamHandler(utf8_stdout)
    console_handler.setFormatter(formatter)

    log = logging.getLogger('traccar_service')
    log.setLevel(logging.DEBUG)
    log.addHandler(file_handler)
    log.addHandler(console_handler)
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


@app.before_request
def _log_request():
    body = flask_request.get_data(as_text=True)
    args = flask_request.args.to_dict()
    logger.debug(f"--> {flask_request.method} {flask_request.path} args={args} body={body} ")


@app.before_request
def _check_auth():
    if not _API_TOKEN:
        return  # authentication disabled (API_TOKEN not set)
    auth = flask_request.headers.get('Authorization', '')
    if not (auth.startswith('Bearer ') and auth[7:] == _API_TOKEN):
        logger.warning(
            f"[auth] Unauthorized {flask_request.method} {flask_request.path}"
            f" from {flask_request.remote_addr}"
        )
        return jsonify({'error': 'Unauthorized'}), 401


@app.after_request
def _log_response(response):
    logger.debug(f"<-- {response.status_code} {flask_request.method} {flask_request.path}")
    return response


_DATA_DIR       = os.path.join(_PROJECT_ROOT, 'Data')
os.makedirs(_DATA_DIR, exist_ok=True)

_SERVICES_FILE  = os.path.join(_DATA_DIR, 'services.json')
_LOCATIONS_FILE = os.path.join(_DATA_DIR, 'locations.json')
_DEVICES_FILE   = os.path.join(_DATA_DIR, 'devices.json')

# Set at startup via --server-url argument
TRACCAR_SERVER_URL: str | None = None

# Background service registry  { device_id -> (Thread, Event) }
_service_threads:     dict[str, threading.Thread] = {}
_service_stop_events: dict[str, threading.Event]  = {}
# Timestamp (float) of last completed sync per device; None = never run yet
_service_last_sync:   dict[str, float | None]     = {}
# Timestamp (float) of next scheduled sync per device; None = first cycle not done yet
_service_next_sync:   dict[str, float | None]     = {}


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
    # Backfill delta=5 for legacy entries that pre-date the field
    needs_save = False
    for svc in services:
        if 'delta' not in svc:
            svc['delta'] = 5
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


def _refresh_devices() -> list:
    """Fetches device list from Google Find My, persists to devices.json, returns the list."""
    result_hex  = request_device_list()
    device_list = parse_device_list_protobuf(result_hex)
    canonic_ids = get_canonic_ids(device_list)
    devices = [{'id': cid, 'name': name} for name, cid in canonic_ids]
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
    }


def _fetch_device_locations(device_id: str) -> list:
    """Calls get_location_data_for_device_extended and returns Location resources."""
    raw = get_location_data_for_device_extended(device_id, "Device")
    # Keep only geo locations (semantic locations have no lat/lon)
    return [_to_location_resource(device_id, loc) for loc in raw if 'latitude' in loc]


def _get_new_locations(device_id: str, locations: list) -> list:
    """Returns only locations whose hash is not already stored in locations.json."""
    db = _load_locations_db()
    known = set(db.get(device_id, []))
    return [loc for loc in locations if _compute_location_hash(loc) not in known]


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


def _send_to_traccar(device_id: str, location: dict) -> tuple[bool, str]:
    """POSTs a single location to the Traccar server. Returns (ok, message)."""
    if not TRACCAR_SERVER_URL:
        return False, "Traccar server URL not configured (use --server-url)"
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
        return resp.status_code in (200, 204), resp.text
    except Exception as exc:
        logger.error(f"<-- ERROR POST {url}  {exc}")
        return False, str(exc)


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
        ok, msg = _send_to_traccar(device_id, location)
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
        ok, msg = _send_to_traccar(device_id, loc)
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
        did       = svc['device_id']
        last_sync = _service_last_sync.get(did)
        next_sync = _service_next_sync.get(did)
        last_sync_str     = datetime.fromtimestamp(last_sync).strftime('%Y-%m-%d %H:%M:%S') if last_sync else None
        next_refresh_in_s = max(0, round(next_sync - now)) if next_sync else 0
        result.append({
            **svc,
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
    svc = next((s for s in services if s['device_id'] == device_id), None)
    if svc is None:
        logger.warning(f"[GET /devices/{device_id}/services] Service not found")
        return jsonify({'error': 'Service not found'}), 404
    logger.info(f"[GET /devices/{device_id}/services] timer={svc['timer']}s")
    return jsonify(svc)


# ---------------------------------------------------------------------------
# 4.6  PUT /devices/<device_id>/services
# ---------------------------------------------------------------------------

@app.route('/devices/<device_id>/services', methods=['PUT'])
def route_put_device_service(device_id):
    """Adds or updates a periodic sync service for a device (Service resource 4.9)."""
    data  = flask_request.get_json()
    timer = int(data.get('timer', 60))
    delta = int(data.get('delta', 5))
    services = _load_services()
    for svc in services:
        if svc['device_id'] == device_id:
            svc['timer'] = timer
            svc['delta'] = delta
            _save_services(services)
            _start_device_service(device_id, timer, delta)
            logger.info(f"[PUT /devices/{device_id}/service] Updated timer={timer}s delta=±{delta}s")
            return jsonify({'device_id': device_id, 'timer': timer, 'delta': delta})
    services.append({'device_id': device_id, 'timer': timer, 'delta': delta})
    _save_services(services)
    _start_device_service(device_id, timer, delta)
    logger.info(f"[PUT /devices/{device_id}/service] Created timer={timer}s delta=±{delta}s")
    return jsonify({'device_id': device_id, 'timer': timer, 'delta': delta}), 201


# ---------------------------------------------------------------------------
# 4.7  DELETE /devices/<device_id>/service
# ---------------------------------------------------------------------------

@app.route('/devices/<device_id>/services', methods=['DELETE'])
def route_delete_device_service(device_id):
    """Stops and removes a periodic sync service for a device."""
    services     = _load_services()
    new_services = [s for s in services if s['device_id'] != device_id]
    if len(new_services) == len(services):
        logger.warning(f"[DELETE /devices/{device_id}/service] Service not found")
        return jsonify({'error': 'Service not found'}), 404
    _save_services(new_services)
    _stop_device_service(device_id)
    logger.info(f"[DELETE /devices/{device_id}/service] Service deleted")
    return jsonify({'status': 'deleted'})


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

def _sync_device(device_id: str) -> None:
    """Runs one sync cycle for a device (replicates task 4.5 logic)."""
    logger.info(f"[sync:{device_id}] Cycle starting...")
    locations = _fetch_device_locations(device_id)
    logger.info(f"[sync:{device_id}] {len(locations)} location(s) fetched from Google Find My")
    new_locations = _get_new_locations(device_id, locations)
    logger.info(f"[sync:{device_id}] {len(new_locations)} new (not yet synced to Traccar)")
    synced = 0
    failed = 0
    for loc in new_locations:
        ok, msg = _send_to_traccar(device_id, loc)
        if ok:
            _persist_location(loc)
            logger.info(f"[sync:{device_id}]   ✓ ts={loc['timestamp']}")
            synced += 1
        else:
            logger.error(f"[sync:{device_id}]   ✗ ts={loc['timestamp']}  reason={msg}")
            failed += 1
    _service_last_sync[device_id] = datetime.now().timestamp()
    if new_locations:
        logger.info(f"[sync:{device_id}] Cycle done — {synced} synced, {failed} failed")
    else:
        logger.info(f"[sync:{device_id}] Cycle done — nothing new to sync")


def _run_device_service(device_id: str, timer: int, delta: int, stop_event: threading.Event) -> None:
    """Worker thread: runs immediately then waits `timer ± random(delta)` seconds between cycles."""
    cycle = 0
    while True:
        if stop_event.is_set():
            logger.info(f"[service:{device_id}] Stop signal received, exiting thread")
            break
        cycle += 1
        logger.info(f"[service:{device_id}] --- Cycle #{cycle} ---")
        try:
            _sync_device(device_id)
        except Exception as exc:
            logger.error(f"[service:{device_id}] Unhandled error in cycle #{cycle}: {exc}")
        jitter = random.uniform(-delta, delta)
        wait   = max(0, timer + jitter)
        _service_next_sync[device_id] = datetime.now().timestamp() + wait
        logger.info(f"[service:{device_id}] Sleeping {wait:.1f}s (base={timer}s jitter={jitter:+.1f}s)")
        if stop_event.wait(wait):
            logger.info(f"[service:{device_id}] Stop signal received during sleep, exiting thread")
            break


def _start_device_service(device_id: str, timer: int, delta: int = 5) -> None:
    """Starts (or restarts) the background sync thread for a device."""
    _stop_device_service(device_id)
    stop_event = threading.Event()
    thread = threading.Thread(
        target=_run_device_service,
        args=(device_id, timer, delta, stop_event),
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


def _start_all_services() -> None:
    """Loads services.json and starts a background thread for every registered service."""
    services = _load_services()
    logger.info(f"[startup] Loading {len(services)} service(s) from {_SERVICES_FILE}")
    for svc in services:
        delta = svc.get('delta', 5)
        logger.info(f"[startup]   → device={svc['device_id']}  timer={svc['timer']}s  delta=±{delta}s")
        _start_device_service(svc['device_id'], svc['timer'], delta)
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
        default=int(os.environ.get('PORT', 5001)),
        help='Port to expose the Flask service on (env: PORT, default: 5001)',
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

    app.run(host='0.0.0.0', port=args.port, debug=False)
