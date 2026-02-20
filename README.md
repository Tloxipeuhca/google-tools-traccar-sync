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
│   ├── locations.json      # Persisted location hashes
│   ├── locations.log       # NDJSON push log (one line per Traccar push attempt)
│   └── excluded_devices.json  # Device IDs excluded from auto-registration
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

## Features

- **Automatic periodic sync** – register a sync service per device; a background thread runs the full pipeline (fetch → filter → push) on a configurable schedule with random jitter to avoid API rate bursts.
- **Deduplication** – locations are fingerprinted with MD5 hashes stored in `Data/locations.json`; already-synced positions are never pushed twice to Traccar.
- **REST API** – a Flask service exposes endpoints to list devices, query locations, manage sync services, and trigger one-off manual pushes.
- **Bearer token authentication** – all endpoints are optionally protected by a configurable `API_TOKEN`; unset the variable to run in dev mode without auth.
- **Device caching** – the device list is fetched from Google Find My and cached in `Data/devices.json`, refreshed every hour by a dedicated background thread.
- **Persistent state** – sync services and synced-location hashes survive restarts; all data files are created automatically on first use.
- **Push audit log** – every Traccar push attempt (success or failure) is appended as a JSON line to `Data/locations.log`, including the HTTP response status and the `loc_status` indicator from the Google decryption layer.
- **Auto-registration** – at startup and every 10 minutes, the service automatically registers a sync service for every discovered device not present in `Data/excluded_devices.json`; managed via the `/excluded-devices` CRUD API; can be disabled globally via `AUTO_REGISTER_SERVICES=false`.
- **Flexible deployment** – ships as a self-contained Docker Compose stack or runs directly in a plain Python virtual environment.

---

## Deployment

### Option A: Docker Compose (recommended)

The Docker image is **self-contained**: the Dockerfile clones both
[GoogleFindMyTools](https://github.com/leonboe1/GoogleFindMyTools) (base) and
this repository (Traccar sync module) at build time and merges their
`requirements.txt` — no local source files are copied into the image.

Only three files are needed locally: `Dockerfile`, `docker-compose.yml`, and `.env`.

```bash
# 1. Download only the required files (no full clone needed)
mkdir traccar-sync && cd traccar-sync
curl -LO https://raw.githubusercontent.com/Tloxipeuhca/google-tools-traccar-sync/main/Traccar/Dockerfile
curl -LO https://raw.githubusercontent.com/Tloxipeuhca/google-tools-traccar-sync/main/Traccar/docker-compose.yml
curl -LO https://raw.githubusercontent.com/Tloxipeuhca/google-tools-traccar-sync/main/Traccar/.env.example

# 2. Configure environment variables
cp .env.example .env
# Edit .env — set at minimum TRACCAR_SERVER_URL and API_TOKEN

# 3. Generate Google credentials (interactive, runs once)
mkdir -p Auth
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
| `AUTO_REGISTER_SERVICES` | `true` | Enable automatic sync service registration for all devices |
| `AUTO_REGISTER_TIMER` | `60` | Sync interval (seconds) applied when auto-registering |
| `AUTO_REGISTER_DELTA` | `5` | Jitter (seconds) applied when auto-registering |

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
| `Data/locations.log` | Newline-delimited JSON push log; one entry per Traccar push attempt (REST or background sync), including `traccar_status` and `loc_status` |
| `Data/excluded_devices.json` | JSON array of device IDs excluded from auto-registration; managed via `PUT/DELETE /excluded-devices/<id>` |

All files are created automatically on first use.

---

## API reference

Full endpoint documentation (resources, authentication, all routes, background sync internals, and architecture diagram) is available in [API.md](API.md).

---

## Usage examples

The examples below assume the service runs on `http://localhost:5001` and that `TOKEN` holds a valid Bearer token. Omit the `-H "Authorization: ..."` header when `API_TOKEN` is not set.

```bash
export $BASE=$http://localhost:5001
export TOKEN=your-secret-token
```

### List all tracked devices

```bash
curl -H "Authorization: Bearer $TOKEN" $BASE/devices
```

### Get the latest location for a device

```bash
curl -H "Authorization: Bearer $TOKEN" $BASE/devices/abc123/locations?last
```

### Get all recorded locations for a device

```bash
curl -H "Authorization: Bearer $TOKEN" $BASE/devices/abc123/locations
```

### Trigger a one-off manual sync to Traccar

Runs the full fetch → deduplicate → push pipeline immediately for a single device.

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" $BASE/traccar/devices/abc123/locations
```

### Register an automatic periodic sync service

Syncs `abc123` every 2 minutes (±30 s jitter). The background thread starts immediately.

```bash
curl -X PUT $BASE/devices/abc123/services \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"timer": 120, "delta": 30}'
```

### List all active sync services

```bash
curl -H "Authorization: Bearer $TOKEN" $BASE/services
```

### Stop a periodic sync service

```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" $BASE/devices/abc123/services
```

### Push a single location manually

Useful for testing or replaying a specific data point.

```bash
curl -X PUT $BASE/traccar/devices/abc123/locations?single \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id":"abc123","lat":48.8566,"lon":2.3522,"timestamp":1700000000}'
```

### Check which locations have not yet been synced

Supply a JSON array of Location objects; the endpoint returns only the new ones.

```bash
LOCATIONS='[{"id":"abc123","lat":48.8566,"lon":2.3522,"timestamp":1700000000}]'
curl -G $BASE/locations \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "filter=$LOCATIONS"
```
