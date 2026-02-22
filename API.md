# API Reference – Traccar Sync Microservice

Complete reference for all REST endpoints exposed by the Flask service on port `5002`.

---

## Authentication

All API endpoints are protected by a Bearer token when `API_TOKEN` is set.

Set the variable in `.env` (Docker) or in your shell (Python venv):

```bash
API_TOKEN=change-me-to-a-strong-random-secret
```

Pass the token in every request:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:5002/devices
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

## Resources

### Device

```json
{
  "id":   "canonic_device_id",
  "name": "Device Name"
}
```

### Location

```json
{
  "id":         "canonic_device_id",
  "name":       "Device Name",
  "lat":        48.8566,
  "lon":        2.3522,
  "timestamp":  1700000000,
  "date":       "2023-11-14 22:13:20",
  "maps_url":   "https://www.google.com/maps/search/?api=1&query=48.8566,2.3522",
  "loc_status": 0
}
```

`loc_status` is the raw integer value of `Common_pb2.Status` returned by `_parse_locations`:
`0` = geo location (standard GPS fix), `1` = semantic location (named place, no coordinates).

### Service

```json
{
  "id":    "canonic_device_id",
  "name":  "Device Name",
  "timer": 60,
  "delta": 5
}
```

### Locations store – `locations.json`

```json
{
  "canonic_device_id": ["md5_hash_1", "md5_hash_2"]
}
```

### Push log – `locations.log`

Newline-delimited JSON file. One entry is appended for **every Traccar push attempt**
(success or failure) from either the REST endpoints or the background sync threads.

```json
{
  "id":             "canonic_device_id",
  "name":           "Device Name",
  "lat":            48.8566,
  "lon":            2.3522,
  "timestamp":      1700000000,
  "date":           "2023-11-14 22:13:20",
  "maps_url":       "https://www.google.com/maps/search/?api=1&query=48.8566,2.3522",
  "loc_status":     0,
  "traccar_status": 200,
  "synced_at":      "2023-11-15 08:00:05"
}
```

| Field | Type | Description |
| --- | --- | --- |
| `date` | `string` | Human-readable timestamp of the **location itself** (when the tracker was seen) |
| `synced_at` | `string` | Timestamp of the **push execution** (when this log entry was written) |
| `loc_status` | `int` | `Common_pb2.Status` value from `_parse_locations` (`0` = geo, `1` = semantic) |
| `traccar_status` | `int \| null` | HTTP status code returned by the Traccar server; `null` if a network exception occurred |

---

## Endpoints

### Utilitaires

#### `GET /health`

Sonde de liveness — toujours publique, aucun appel externe.

**Response** – objet JSON avec les champs `status` et `services`

| `status` | Code HTTP | Signification |
| --- | --- | --- |
| `ok` | `200` | Service opérationnel |
| `auth_required` | `503` | Token Google OAuth expiré — redémarrage requis |

```bash
curl http://localhost:5002/health
# → {"status": "ok", "services": 4}
```

---

#### `GET /versions`

Retourne la version du service (commit git) et la date de build.
Toujours publique, aucune authentification requise.

**Response** – `{"version": "abc1234", "built_at": "2026-02-20T08:00:00"}`

```bash
curl http://localhost:5002/versions
```

---

#### `POST /notify/test`

Envoie un email de test pour vérifier la configuration SMTP.
Requiert l'authentification Bearer si `API_TOKEN` est défini.

**Response** – `{"status": "sent"}` — `500` si l'envoi échoue (détail dans `message`)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:5002/notify/test
```

---

#### `PUT /auth/aas-token`

Injecte un nouvel `aas_token` dans `Auth/secrets.json` sans redémarrer le service.
Utile pour renouveler le token Google OAuth expiré depuis l'API plutôt qu'en éditant le fichier manuellement.
Remet à zéro l'état `auth_required` et redémarre tous les services de sync enregistrés.

**Body** – `application/json`

```json
{ "aas_token": "aas_et/AKppIN..." }
```

**Response** – objet JSON

| Cas | Code HTTP | Corps |
| --- | --- | --- |
| Succès | `200` | `{"status": "ok", "services_restarted": 4}` |
| Champ manquant | `400` | `{"error": "aas_token is required"}` |
| Erreur d'écriture | `500` | `{"error": "..."}` |

```bash
curl -X PUT http://localhost:5002/auth/aas-token \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"aas_token": "aas_et/AKppIN..."}'
```

---

#### `PUT /auth/secrets`

Remplace le contenu complet de `Auth/secrets.json`.
Utilisé pour injecter les credentials dans un conteneur démarré sans fichier de secrets valide (premier déploiement ou réinitialisation complète).
Remet à zéro l'état `auth_required` et redémarre tous les services de sync enregistrés.

Le corps est le contenu JSON de `Auth/secrets.json` généré par `python main.py` sur un poste local avec Chrome.

**Body** – `application/json` (contenu de `Auth/secrets.json`)

```json
{
  "aas_token": "aas_et/AKppIN...",
  "username": "user@gmail.com",
  "androidId": "...",
  "...": "..."
}
```

**Response** – objet JSON

| Cas | Code HTTP | Corps |
| --- | --- | --- |
| Succès | `200` | `{"status": "ok", "services_restarted": 0}` |
| Corps invalide | `400` | `{"error": "a JSON object is required"}` |
| `aas_token` manquant | `400` | `{"error": "aas_token is required in the secrets body"}` |
| Erreur d'écriture | `500` | `{"error": "..."}` |

```bash
# Upload du fichier secrets.json généré localement
curl -X PUT http://localhost:5002/auth/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @Auth/secrets.json
```

---

### Devices

#### `GET /devices`

Returns the list of registered Find My trackers.

**Response** – array of [Device](#device)

```bash
curl http://localhost:5002/devices
```

---

#### `GET /devices/<device_id>/locations`

Returns **all available** locations for a device.

**Response** – array of [Location](#location)

```bash
curl http://localhost:5002/devices/abc123/locations
```

---

#### `GET /devices/<device_id>/locations?last`

Returns only the **most recent** location for a device.

**Response** – [Location](#location) — `404` if no locations available

```bash
curl http://localhost:5002/devices/abc123/locations?last
```

---

### Services

#### `GET /services`

Returns all registered periodic sync services.

**Response** – array of [Service](#service)

```bash
curl http://localhost:5002/services
```

---

#### `GET /devices/<device_id>/services`

Returns the sync service registered for a specific device.

**Response** – [Service](#service) — `404` if none registered

```bash
curl http://localhost:5002/devices/abc123/services
```

---

#### `PUT /devices/<device_id>/services`

Creates or updates a periodic sync service for a device.
Also starts (or restarts) the background sync thread immediately.

Returns `403 Forbidden` if the device is present in `Data/excluded_devices.json`.

**Body** – [Service](#service)

**Response** – [Service](#service) — `201 Created` on insert, `200 OK` on update

```bash
curl -X PUT http://localhost:5002/devices/abc123/services \
  -H 'Content-Type: application/json' \
  -d '{"timer": 120, "delta": 10}'
```

---

#### `DELETE /devices/<device_id>/services`

Stops and removes the periodic sync service for a device.

**Response** – `{"status": "deleted"}`

```bash
curl -X DELETE http://localhost:5002/devices/abc123/services
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
curl -X PUT http://localhost:5002/traccar/devices/abc123/locations
```

---

#### `PUT /traccar/devices/<device_id>/locations?single`

Pushes a single Location resource (supplied in the request body) to the Traccar server.

**Body** – [Location](#location)

**Response** – `{"status": "ok"}` on success

```bash
curl -X PUT http://localhost:5002/traccar/devices/abc123/locations?single \
  -H 'Content-Type: application/json' \
  -d '{"id":"abc123","lat":48.8566,"lon":2.3522,"timestamp":1700000000}'
```

---

### Location store

#### `GET /locations`

Returns the **most recent live location** for every registered Find My tracker
(calls Google Find My for each device, same as `GET /devices/<id>/location`).

**Response** – array of [Location](#location)

```bash
curl http://localhost:5002/locations
```

---

#### `GET /locations?filter=<json>`

Filters a JSON-encoded array of Location resources and returns only those
**not yet recorded** in `locations.json`. Uses MD5 hash comparison.

**Query param** – `filter` — URL-encoded JSON array of [Location](#location)

**Response** – array of [Location](#location) (the new ones only)

```bash
# URL-encode the JSON list before passing it as a query param
curl "http://localhost:5002/locations?filter=%5B%7B%22id%22%3A%22abc123%22%2C%22lat%22%3A48.8%2C%22lon%22%3A2.3%2C%22timestamp%22%3A1700000000%7D%5D"
```

---

#### `POST /locations`

Records a location as synced in `locations.json` (stores its MD5 hash).

**Body** – [Location](#location)

**Response** – `{"status": "saved", "hash": "<md5>"}` — `201 Created`

```bash
curl -X POST http://localhost:5002/locations \
  -H 'Content-Type: application/json' \
  -d '{"id":"abc123","lat":48.8566,"lon":2.3522,"timestamp":1700000000}'
```

### Excluded devices

#### `GET /excluded-devices`

Returns the list of device IDs excluded from auto-registration, enriched with their name when available.

**Response** – array of `{"id": "...", "name": "..."}`

```bash
curl http://localhost:5002/excluded-devices
```

---

#### `PUT /excluded-devices/<device_id>`

Adds a device to the exclusion list. If a sync service is currently running for that device, it is stopped and removed from `services.json` immediately.

**Response** – `{"id": "...", "excluded": true}` — `201 Created` on insert, `200 OK` if already excluded

```bash
curl -X PUT http://localhost:5002/excluded-devices/abc123
```

---

#### `DELETE /excluded-devices/<device_id>`

Removes a device from the exclusion list. The auto-register thread will pick it up again on the next cycle.

**Response** – `{"id": "...", "excluded": false}` — `404` if not in the list

```bash
curl -X DELETE http://localhost:5002/excluded-devices/abc123
```

---

## Auto-registration of sync services

At startup (after a 5-second delay to let the device cache warm up) and then every **600 seconds**,
a background thread automatically registers a periodic sync service for every device that is:

- present in `Data/devices.json`, **and**
- **not** listed in `Data/excluded_devices.json`, **and**
- **not** already registered in `Data/services.json`.

The feature is controlled by four environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `AUTO_REGISTER_SERVICES` | `true` | Set to `false` to disable the feature entirely |
| `AUTO_REGISTER_TIMER` | `600` | Sync interval (seconds) used when creating the service |
| `AUTO_REGISTER_DELTA` | `5` | Jitter (seconds) used when creating the service |

The exclusion list is managed at runtime via the [Excluded devices](#excluded-devices) CRUD endpoints
and persisted in `Data/excluded_devices.json` — no restart required.

Already-registered services are never modified; only new devices are picked up.
To override the timer/delta for a specific device, register it manually with
`PUT /devices/<device_id>/services` before the auto-register cycle runs.

At startup, `_enforce_exclusions()` automatically stops and removes any service
whose device appears in the exclusion list (e.g. a device excluded while the service was offline).

### Startup sequence with auto-registration

```
startup
  ├─ start devices-refresh thread      (fetches devices.json immediately, then every 3600 s)
  ├─ load services.json                → start one sync thread per registered device
  └─ start auto-register thread
          ├─ wait 5 s                  (lets devices-refresh complete its first fetch)
          ├─ register new devices      (skips excluded and already-registered ones)
          ├─ wait 600 s
          └─ (loop)
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
   service.py  (Flask, port 5002)
        │
        ├── GET  /devices                         → list trackers
        ├── GET  /devices/<id>/locations          → all locations
        ├── GET  /devices/<id>/locations?last     → most recent location
        │
        ├── PUT  /traccar/devices/<id>/locations         → full sync  ──► Traccar HTTP API
        ├── PUT  /traccar/devices/<id>/locations?single  → push 1 loc ──► Traccar HTTP API
        │
        ├── GET  /services                        → list all sync services
        ├── GET  /devices/<id>/services           → get service for a device
        ├── PUT  /devices/<id>/services           → register periodic sync
        ├── DELETE /devices/<id>/services         → unregister sync
        │
        ├── GET  /locations?filter=[...]          → filter new locations
        ├── POST /locations                       → mark location as synced
        │
        ├── GET    /excluded-devices              → list excluded devices
        ├── PUT    /excluded-devices/<id>         → add to exclusion list
        └── DELETE /excluded-devices/<id>         → remove from exclusion list
                │
                ▼
          ../Data/locations.json         (MD5 hashes per device)
          ../Data/locations.log          (NDJSON push log — one line per Traccar push attempt)
          ../Data/services.json          (sync services — also written by auto-register thread)
          ../Data/devices.json           (cached device list, refreshed hourly)
          ../Data/excluded_devices.json  (device IDs excluded from auto-registration)
```
