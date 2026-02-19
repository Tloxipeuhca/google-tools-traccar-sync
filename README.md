# Traccar Sync Microservice

A Flask REST API that bridges **Google Find My Device** trackers with a self-hosted
[Traccar](https://www.traccar.org/) GPS tracking server.

It periodically fetches encrypted location data from the Google Find My API,
decrypts it locally, filters out already-synced positions, and pushes new ones
to your Traccar instance.

---

## Directory layout

```
<project root>/
├── Data/                   # Runtime data (auto-created at project root)
│   ├── services.json       # Persisted sync services
│   ├── devices.json        # Cached device list, refreshed hourly
│   └── locations.json      # Persisted location hashes
└── Traccar/
    ├── __init__.py
    ├── service.py              # Flask app + background sync service
    ├── Dockerfile              # Docker image definition
    ├── docker-compose.yml      # Docker Compose stack
    ├── .env.example            # Environment variable template
    ├── requirements.txt        # Traccar-specific dependencies (flask, requests)
    ├── README.md               # This file
    └── NopaApiExtend/
        ├── __init__.py
        └── location_request_extend.py   # Extends NovaApi location request
```

---

## Deployment

### Option A: Docker Compose (recommended)

The Docker image is **self-contained**: the Dockerfile clones both
[GoogleFindMyTools](https://github.com/leonboe1/GoogleFindMyTools) (base) and
this repository (Traccar sync module) at build time and merges their
`requirements.txt` — no local source files are copied into the image.

```bash
# 1. Clone this repository
git clone https://github.com/Tloxipeuhca/google-tools-traccar-sync.git
cd google-tools-traccar-sync/Traccar

# 2. Configure environment variables
cp .env.example .env
# Edit .env — set at minimum TRACCAR_SERVER_URL and API_TOKEN

# 3. Generate Google credentials (interactive, runs once)
mkdir -p ../Auth
docker compose run --rm traccar-sync python main.py
# Follow the on-screen prompts → writes Auth/secrets.json on the host

# 4. Start the service
docker compose up -d
docker compose logs -f      # stream logs
docker compose down         # stop
```

| Variable | Default | Description |
| --- | --- | --- |
| `TRACCAR_SERVER_URL` | `http://traccar:8082` | Traccar OsmAnd HTTP endpoint |
| `PORT` | `5001` | Host port exposed by the Flask service |
| `API_TOKEN` | *(empty)* | Bearer token — set to enable authentication |

### Option B: Python virtual environment

```bash
# 1. Clone both repositories
git clone https://github.com/leonboe1/GoogleFindMyTools.git
git clone https://github.com/Tloxipeuhca/google-tools-traccar-sync.git

cd GoogleFindMyTools

# 2. Merge the Traccar sync module into GoogleFindMyTools
mkdir -p Traccar Data logs
cp -r ../google-tools-traccar-sync/Traccar .

# 3. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows

# 4. Install all dependencies
pip install -r requirements.txt 
pip install -r ./Traccar/requirements.txt 

# 5. Generate Google credentials (interactive, runs once)
python main.py
# Follow the on-screen prompts → writes Auth/secrets.json

# 6. Start the service
cp ./Traccar/.env.example ./Traccar/.env
# Edit .env — set at minimum TRACCAR_SERVER_URL and API_TOKEN
python -m Traccar.service
```

The service will be available at `http://localhost:5001`.
Stop it with `Ctrl+C`; the `.venv/` directory can be reused across restarts.

### CLI arguments

| Argument | Default | Description |
| --- | --- | --- |
| `--server-url` | `None` | Traccar server base URL, e.g. `http://localhost:8082` |
| `--port` | `5001` | Port for the Flask service |

If `--server-url` is omitted, all `/traccar/*` push routes will return an error.

---

## Authentication

All API endpoints are protected by a Bearer token when `API_TOKEN` is set.

Set the variable in `.env` (Docker) or in your shell (Python venv):

```bash
API_TOKEN=change-me-to-a-strong-random-secret
```

Pass the token in every request:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:5001/devices
```

| Behaviour | Condition |
| --- | --- |
| All requests pass through | `API_TOKEN` not set or empty — **dev mode only** |
| `401 Unauthorized` | Token missing or incorrect |

To generate a strong random token:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Prerequisites (manual install)

- Python 3.10+
- All dependencies installed (from project root):

  ```bash
  pip install -r requirements.txt
  ```

- Google Find My credentials configured in `Auth/secrets.json`
  (see step 2 above)
- A running Traccar server (required only for push routes)

---

## Persistent files

| File | Purpose |
|---|---|
| `Data/services.json` | List of registered periodic sync services; loaded automatically at startup |
| `Data/devices.json` | Cached device list (id + name); refreshed hourly by a background thread and on every `GET /devices` call |
| `Data/locations.json` | MD5 hashes of already-synced locations per device; used to avoid duplicate pushes |

All files are created automatically on first use.

---

## API reference

### Resources

#### Device (4.14)

```json
{
  "id":   "canonic_device_id",
  "name": "Device Name"
}
```

#### Location (4.8)

```json
{
  "id":        "canonic_device_id",
  "name":      "Device Name",
  "lat":       48.8566,
  "lon":       2.3522,
  "timestamp": 1700000000,
  "date":      "2023-11-14 22:13:20",
  "maps_url":  "https://www.google.com/maps/search/?api=1&query=48.8566,2.3522"
}
```

#### Service (4.9)

```json
{
  "device_id": "canonic_device_id",
  "timer":     60,
  "delta":     5
}
```

#### Locations store – `locations.json` (4.13)

```json
{
  "canonic_device_id": ["md5_hash_1", "md5_hash_2"]
}
```

---

### Devices

#### `GET /devices`

Returns the list of registered Find My trackers.

**Response** – array of [Device](#device-414)

```bash
curl http://localhost:5001/devices
```

---

#### `GET /devices/<device_id>/locations`

Returns **all available** locations for a device.

**Response** – array of [Location](#location-48)

```bash
curl http://localhost:5001/devices/abc123/locations
```

---

#### `GET /devices/<device_id>/locations?last`

Returns only the **most recent** location for a device.

**Response** – [Location](#location-48) — `404` if no locations available

```bash
curl http://localhost:5001/devices/abc123/locations?last
```

---

### Services

#### `GET /services`

Returns all registered periodic sync services.

**Response** – array of [Service](#service-49)

```bash
curl http://localhost:5001/services
```

---

#### `GET /devices/<device_id>/services`

Returns the sync service registered for a specific device.

**Response** – [Service](#service-49) — `404` if none registered

```bash
curl http://localhost:5001/devices/abc123/services
```

---

#### `PUT /devices/<device_id>/services`

Creates or updates a periodic sync service for a device.
Also starts (or restarts) the background sync thread immediately.

**Body** – [Service](#service-49)

**Response** – [Service](#service-49) — `201 Created` on insert, `200 OK` on update

```bash
curl -X PUT http://localhost:5001/devices/abc123/services \
  -H 'Content-Type: application/json' \
  -d '{"timer": 120, "delta": 10}'
```

---

#### `DELETE /devices/<device_id>/services`

Stops and removes the periodic sync service for a device.

**Response** – `{"status": "deleted"}`

```bash
curl -X DELETE http://localhost:5001/devices/abc123/services
```

---

### Traccar push

#### `PUT /traccar/devices/<device_id>/locations`

Full sync pipeline for a device:

1. Fetches all locations from Google Find My (`GET /devices/<id>/locations`)
2. Filters out already-synced ones (`GET /locations?filter=...`)
3. Pushes each new location to Traccar
4. On success, records each location locally (`POST /locations`)

**Response** – array of per-location results

```json
[
  {"location": {...}, "status": "synced"},
  {"location": {...}, "status": "error", "message": "..."}
]
```

```bash
curl -X PUT http://localhost:5001/traccar/devices/abc123/locations
```

---

#### `PUT /traccar/devices/<device_id>/locations?single`

Pushes a single Location resource (supplied in the request body) to the Traccar server.

**Body** – [Location](#location-48)

**Response** – `{"status": "ok"}` on success

```bash
curl -X PUT http://localhost:5001/traccar/devices/abc123/locations?single \
  -H 'Content-Type: application/json' \
  -d '{"id":"abc123","lat":48.8566,"lon":2.3522,"timestamp":1700000000}'
```

---

### Location store

#### `GET /locations`

Returns the **most recent live location** for every registered Find My tracker
(calls Google Find My for each device, same as `GET /devices/<id>/location`).

**Response** – array of [Location](#location-48)

```bash
curl http://localhost:5001/locations
```

---

#### `GET /locations?filter=<json>`

Filters a JSON-encoded array of Location resources and returns only those
**not yet recorded** in `locations.json`. Uses MD5 hash comparison.

**Query param** – `filter` — URL-encoded JSON array of [Location](#location-48)

**Response** – array of [Location](#location-48) (the new ones only)

```bash
# URL-encode the JSON list before passing it as a query param
curl "http://localhost:5001/locations?filter=%5B%7B%22id%22%3A%22abc123%22%2C%22lat%22%3A48.8%2C%22lon%22%3A2.3%2C%22timestamp%22%3A1700000000%7D%5D"
```

---

#### `POST /locations`

Records a location as synced in `locations.json` (stores its MD5 hash).

**Body** – [Location](#location-48)

**Response** – `{"status": "saved", "hash": "<md5>"}` — `201 Created`

```bash
curl -X POST http://localhost:5001/locations \
  -H 'Content-Type: application/json' \
  -d '{"id":"abc123","lat":48.8566,"lon":2.3522,"timestamp":1700000000}'
```

---

## Background sync service

When a `PUT /devices/<device_id>/services` is called (or when previously
registered services are loaded from `services.json` on startup), a daemon
thread is started for that device.

The thread runs the full sync pipeline (equivalent to
`PUT /traccar/devices/<device_id>/locations`) immediately, then repeats
every `timer + random(−delta, +delta)` seconds. The jitter is re-drawn each cycle.

A separate daemon thread refreshes `devices.json` every **3600 seconds**
(and immediately at startup), keeping device names available for all location
responses without blocking requests.

```
startup
  ├─ start devices-refresh thread
  │       ├─ fetch + save devices.json immediately
  │       ├─ wait 3600 s
  │       └─ (loop)
  │
  └─ load services.json
       └─ for each entry → start background sync thread
                               ├─ sync immediately
                               ├─ wait timer ± random(delta) seconds
                               └─ (loop)
```

A `DELETE /devices/<device_id>/services` stops the thread and removes the
entry from `services.json`.

---

## Architecture overview

```
Google Find My API
        │
        ▼
NopaApiExtend.get_location_data_for_device_extended()
        │  (FCM push ← Nova API)
        ▼
   service.py  (Flask, port 5001)
        │
        ├── GET  /devices                         → list trackers
        ├── GET  /devices/<id>/locations          → all locations
        ├── GET  /devices/<id>/locations?last     → most recent location
        │
        ├── PUT  /traccar/devices/<id>/locations          → full sync    ──► Traccar HTTP API
        ├── PUT  /traccar/devices/<id>/locations?single  → push 1 loc ──► Traccar HTTP API
        │
        ├── GET  /services                        → list all sync services
        ├── GET  /devices/<id>/services           → get service for a device
        ├── PUT  /devices/<id>/services           → register periodic sync
        ├── DELETE /devices/<id>/services         → unregister sync
        │
        ├── GET  /locations?filter=[...]          → filter new locations
        └── POST /locations                       → mark location as synced
                │
                ▼
          ../Data/locations.json  (MD5 hashes per device)
          ../Data/services.json   (sync services)
          ../Data/devices.json    (cached device list, refreshed hourly)
```
