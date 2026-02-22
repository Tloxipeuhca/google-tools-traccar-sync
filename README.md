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
    ├── notifier.py             # Email notifier (SMTP via stdlib)
    ├── Dockerfile              # Docker image definition
    ├── docker-compose.yml      # Docker Compose stack
    ├── deploy.sh               # Pull + rebuild script
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
- **Email notifications** – optional SMTP notifications (via Python `smtplib`) for three events: Google OAuth token expiry, new device detected in `devices.json`, new device auto-registered for sync. Configured via `NOTIFY_SMTP_*` environment variables; entirely disabled when `NOTIFY_SMTP_HOST` is unset.
- **Authentication failure handling** – when the Google OAuth token expires (`KeyError: 'Auth'`), all background sync threads stop gracefully, the expired `aas_token` is removed from `Auth/secrets.json`, an email is sent, and `/health` returns `503 auth_required` until the service is restarted.
- **Flexible deployment** – ships as a self-contained Docker Compose stack or runs directly in a plain Python virtual environment.

---

## Deployment

### Option A: Docker Compose (recommended)

The Docker image is **self-contained**: the Dockerfile clones both
[GoogleFindMyTools](https://github.com/leonboe1/GoogleFindMyTools) (base) and
this repository (Traccar sync module) at build time and merges their
`requirements.txt` — no local source files are copied into the image.

The Docker image is built entirely at image-build time — only four files are needed locally.

```bash
# 1. Download only the required files (no full clone needed)
mkdir traccar-sync && cd traccar-sync
curl -sSfLO https://raw.githubusercontent.com/Tloxipeuhca/google-tools-traccar-sync/main/Dockerfile
curl -sSfLO https://raw.githubusercontent.com/Tloxipeuhca/google-tools-traccar-sync/main/docker-compose.yml
curl -sSfLO https://raw.githubusercontent.com/Tloxipeuhca/google-tools-traccar-sync/main/.env.example
curl -sSfLO https://raw.githubusercontent.com/Tloxipeuhca/google-tools-traccar-sync/main/deploy.sh
chmod +x deploy.sh

# 2. Configure environment variables
cp .env.example .env
# Edit .env — set at minimum TRACCAR_SERVER_URL and API_TOKEN

# 3. Generate Google credentials
# The credential generation requires Chrome and an interactive terminal — it cannot run inside Docker.
# Choose one of the two options below.
```

#### Option A — generate credentials on a local machine first (recommended)

```bash
# On any machine where Chrome is installed and Python is available:
git clone https://github.com/leonboe1/GoogleFindMyTools.git
cd GoogleFindMyTools && pip install -r requirements.txt
python main.py
# Follow the on-screen prompts → writes Auth/secrets.json

# Copy the generated file to the server deployment directory:
scp Auth/secrets.json user@server:/path/to/traccar-sync/data/secrets.json
```

#### Option B — start without credentials, upload via API

```bash
# Create an empty JSON file so Docker can bind-mount it (not a directory)
mkdir -p data && echo '{}' > data/secrets.json

# Start the service — it will run but sync will fail until credentials are uploaded
docker compose up --build -d

# On a local machine with Chrome, generate secrets.json (same as Option A above)
# then upload the full file to the running service:
TOKEN=$(grep '^API_TOKEN=' .env | cut -d'=' -f2)
curl -X PUT http://server:5001/auth/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @Auth/secrets.json
# → {"status": "ok", "services_restarted": 0}
# Sync services start automatically once credentials are accepted.
```

```bash
# Start / stop
docker compose up --build -d
docker compose logs -f      # stream logs
docker compose down         # stop
```

| Variable | Default | Description |
| --- | --- | --- |
| `TRACCAR_SERVER_URL` | `http://traccar:8082` | Traccar OsmAnd HTTP endpoint |
| `PORT` | `5002` | Host port exposed by the Flask service |
| `API_TOKEN` | *(empty)* | Bearer token — set to enable authentication |
| `AUTO_REGISTER_SERVICES` | `true` | Enable automatic sync service registration for all devices |
| `AUTO_REGISTER_TIMER` | `600` | Sync interval (seconds) applied when auto-registering |
| `AUTO_REGISTER_DELTA` | `5` | Jitter (seconds) applied when auto-registering |
| `NOTIFY_SMTP_HOST` | *(empty)* | SMTP server hostname — **leave empty to disable all notifications** |
| `NOTIFY_SMTP_PORT` | `587` | SMTP port (`587` for STARTTLS, `465` for SSL) |
| `NOTIFY_SMTP_USER` | *(empty)* | SMTP login username |
| `NOTIFY_SMTP_PASS` | *(empty)* | SMTP login password (use an App Password for Gmail) |
| `NOTIFY_EMAIL_FROM` | `NOTIFY_SMTP_USER` | Sender address (defaults to `NOTIFY_SMTP_USER`) |
| `NOTIFY_EMAIL_TO` | *(empty)* | Recipient address(es), comma-separated |
| `NOTIFY_SMTP_SSL` | `false` | Set to `true` to use SSL-on-connect instead of STARTTLS |

#### Update / redeploy

Use `deploy.sh` to pull the latest code and rebuild the image only if something changed.
Docker's build cache ensures layers are reused when the Dockerfile is unchanged.

```bash
./deploy.sh
```

What `deploy.sh` does:

1. Re-downloads `Dockerfile`, `docker-compose.yml`, and `deploy.sh` itself via curl
2. `docker compose up --build -d` — rebuilds the image if any layer changed, otherwise reuses the cache
3. Prints the last 30 log lines to confirm the service restarted correctly

| Situation | Rebuild time |
| --- | --- |
| Nothing changed | ~1 s (100 % cache hit) |
| Only `service.py` changed | ~2 s (re-copies files, no reinstall) |
| `Dockerfile` or `requirements.txt` changed | Full rebuild from the changed layer |

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

The service will be available at `http://localhost:5002`.
Stop it with `Ctrl+C`; the `.venv/` directory can be reused across restarts.

### CLI arguments

| Argument | Default | Description |
| --- | --- | --- |
| `--server-url` | `None` | Traccar server base URL, e.g. `http://localhost:8082` |
| `--port` | `5002` | Port for the Flask service |

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

## Notifications email

Le service peut envoyer des notifications SMTP pour trois événements :

| Événement | Déclencheur |
|---|---|
| **Nouveau périphérique dans le compte Google** | `_refresh_devices()` — toutes les heures, si un ID absent de `devices.json` apparaît |
| **Nouveau périphérique auto-enregistré** | `_auto_register_services()` — quand un service est créé pour un device non encore suivi |
| **Token OAuth expiré** | `_handle_auth_failure()` — une seule fois, avant l'arrêt de tous les threads |

> La notification de premier démarrage est supprimée : si `devices.json` était vide au moment du refresh, aucun email n'est envoyé (faux positif).

### Configuration Gmail

```ini
NOTIFY_SMTP_HOST=smtp.gmail.com
NOTIFY_SMTP_PORT=587
NOTIFY_SMTP_USER=moi@gmail.com
NOTIFY_SMTP_PASS=xxxx-xxxx-xxxx-xxxx   # App Password Google (pas le mot de passe principal)
NOTIFY_EMAIL_TO=moi@gmail.com
```

Générer un App Password : **Compte Google → Sécurité → Validation en deux étapes → Mots de passe des applications**.

### Tester la configuration

```bash
curl -X POST http://localhost:5001/notify/test
# → {"status": "sent"}
```

Log attendu en cas de succès :

```text
[INFO ] [notify] Email sent → moi@gmail.com | FineTrack — Test de notification
```

---

## Gestion de l'expiration du token Google OAuth

Le token `aas_token` mis en cache dans `Auth/secrets.json` a une durée de vie limitée.
Quand Google le rejette, le service détecte l'erreur `KeyError: 'Auth'` et :

1. Arrête proprement tous les threads de sync
2. Supprime le `aas_token` expiré de `Auth/secrets.json`
3. Envoie un email de notification (si SMTP configuré)
4. Fait retourner `503 auth_required` à `GET /health`

```bash
curl http://localhost:5001/health
# → {"status": "auth_required", "services": 0}   ← action requise
# → {"status": "ok", "services": 4}               ← service sain
```

**Pour récupérer :**

Générer un nouveau `secrets.json` sur un poste local avec Chrome, puis l'uploader via l'API sans redémarrer le conteneur :

```bash
# 1. Sur le poste local — regénérer le fichier complet
cd GoogleFindMyTools && python main.py
# → réécrit Auth/secrets.json avec un aas_token frais

# 2. Uploader le fichier vers le service en cours d'exécution
curl -X PUT http://localhost:5001/auth/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @Auth/secrets.json
# → {"status": "ok", "services_restarted": 4}
```

Si seul le `aas_token` a expiré (le reste de `secrets.json` est valide), on peut injecter uniquement le token :

```bash
# 1. Extraire le token depuis le poste local
python -c "from Auth.aas_token_retrieval import _generate_aas_token; print(_generate_aas_token())"

# 2. L'injecter via l'API
curl -X PUT http://localhost:5001/auth/aas-token \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"aas_token": "aas_et/AKppIN..."}'
# → {"status": "ok", "services_restarted": 4}
```

> **Remarque** : le flux Chrome ne fonctionne pas à l'intérieur du conteneur Docker (pas d'affichage graphique). Toute génération de credentials doit se faire sur un poste local.

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

The examples below assume the service runs on `http://localhost:5002` and that `TOKEN` holds a valid Bearer token. Omit the `-H "Authorization: ..."` header when `API_TOKEN` is not set.

### Quick setup — read token from `.env`

```bash
TOKEN=$(grep '^API_TOKEN=' .env | cut -d'=' -f2)
PORT=$(grep '^PORT=' .env | cut -d'=' -f2)
BASE=http://localhost:${PORT:-5002}
```

Or add a persistent alias to `~/.bash_aliases` (replace the path with your deployment directory):

```bash
_ENV=/srv/docker/traccar-sync/.env
alias traccar='curl -s -H "Authorization: Bearer $(grep "^API_TOKEN=" $_ENV | cut -d= -f2)"'
BASE=http://localhost:$(grep '^PORT=' $_ENV | cut -d= -f2)
```

Then use it directly:

```bash
traccar $BASE/services
traccar $BASE/devices
traccar -X DELETE $BASE/devices/abc123/services
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
