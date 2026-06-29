# buff-market-auto-trades

Automatically delivers sold items on [Buff.market](https://buff.market) (CS2 / P2P).

When you sell an item, Buff.market holds the funds until you deliver. This bot watches for new sales and handles the full delivery cycle hands-free:

1. Logs into Buff.market via Steam OpenID — no API key or manual cookie needed
2. Polls for new `TO_DELIVER` orders every 15 seconds
3. Encrypts your Steam session cookies and submits them to Buff so their servers can send the trade offer on your behalf
4. Confirms the offer via Steam Guard (mobile authenticator secrets)

---

## How it works

**Login:** Uses `aiosteampy` to authenticate with Steam, then runs the Steam OpenID flow against `https://api.buff.market/account/login/steam` automatically.

**Delivery flow (per order):**

1. `GET /api/message/notification` — fast poll for pending delivery count
2. `GET /api/market/sell_order/to_deliver` — fetch the full order list
3. Collect all Steam session cookies, serialize as JSON, encrypt with the Buff.market RSA-4096 public key (hybrid RSA + AES-128-CBC, replicated from the Android APK)
4. `POST /api/market/manual_plus/seller_send_offer` — Buff's server decrypts, authenticates as you, sends the trade offer to the buyer
5. Confirm the offer via Steam Guard (`identity_secret`)

---

## Setup

### 1. Get your Steam secrets

Export your Steam Mobile Authenticator `.maFile` using [Steam Desktop Authenticator](https://github.com/Jessecar96/SteamDesktopAuthenticator) or similar. You need:

- `shared_secret` — generates 2FA login codes
- `identity_secret` — confirms trade offers

### 2. Configure

```bash
cp config.example.json config.json
# Fill in your credentials
```

### 3. Run

Pick **one** of the two options below.

---

## Run with Docker Compose (recommended)

The easiest way to run the bot — no Python or dependency setup needed, and it restarts automatically.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) with the Compose plugin (`docker compose version` should work).

### Steps

1. Create your config (if you haven't already):

   ```bash
   cp config.example.json config.json
   # edit config.json and fill in your credentials
   ```

   > ⚠️ `config.json` **must exist as a file** before you start. Compose bind-mounts it; if it's missing, Docker will create an empty *directory* in its place and the bot will fail to start.

2. Build and start in the background:

   ```bash
   docker compose up -d --build
   ```

3. Follow the logs:

   ```bash
   docker compose logs -f
   ```

4. Stop it:

   ```bash
   docker compose down
   ```

That's it. The container reads `config.json` (mounted read-only) and persists your logged-in Buff session to a named volume (`buff-data`) so it survives restarts and rebuilds.

### What the Compose setup does

- **Builds** the image from the included `Dockerfile` (Python 3.12 slim + the deps in `requirements.txt`).
- **Mounts** `./config.json` → `/app/config.json` (read-only).
- **Persists** Steam cookies to a `/data` named volume (`--cookies /data/cookies.json`) so you don't re-login on every restart.
- **Auto-restarts** (`restart: unless-stopped`). The bot exits and re-authenticates from scratch after a fatal auth failure; Docker brings it right back up. To stop it for good, run `docker compose down` (or `docker compose stop`).
- **Graceful shutdown** — `docker compose stop` sends `SIGTERM`, and the bot finishes its current cycle before exiting (30s grace period).

### Customizing the Compose run

Change logging or other CLI flags by uncommenting and editing the `command:` line in `docker-compose.yml`:

```yaml
    command: ["--config", "/app/config.json", "--cookies", "/data/cookies.json", "--log-level", "DEBUG"]
```

After changing config or flags, apply with:

```bash
docker compose up -d
```

(Add `--build` if you changed the code or `requirements.txt`.)

---

## Run with Python (local)

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run

```bash
python main.py
```

Optional flags:

```
--config   PATH    Config file path (default: config.json)
--cookies  PATH    Steam cookie cache path (default: cookies.json)
--log-level LEVEL  DEBUG / INFO / WARNING / ERROR (default: INFO)
--log-file  PATH   Write logs to a rotating file (10 MB × 5)
--trace-http       Log full HTTP request/response bodies
```

---

## Configuration

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `steam_id64` | ✓ | — | Your SteamID64 |
| `steam_login` | ✓ | — | Steam username |
| `steam_password` | ✓ | — | Steam password |
| `shared_secret` | ✓ | — | From `.maFile` — 2FA code generation |
| `identity_secret` | ✓ | — | From `.maFile` — trade confirmation |
| `buff_session` | | — | Pre-existing Buff.market `session` cookie. Leave blank to auto-login on startup |
| `game` | | `csgo` | Game to monitor: `csgo`, `dota2`, `tf2`, `rust` |
| `steam_api_key` | | — | Steam Web API key (optional, improves reliability) |
| `client_proxy` | | — | SOCKS5 proxy for Buff HTTP traffic, e.g. `socks5://user:pass@host:port` |
| `steam_use_proxy` | | `false` | Route Steam through the same proxy |
| `notif_interval_seconds` | | `15` | How often to poll the notification count |
| `heartbeat_interval_seconds` | | `60` | Fallback full-order-list poll interval |
| `post_run_delay_seconds` | | `5` | Extra cycle run after delivery, to catch orders that arrived mid-cycle |
| `session_keepalive_seconds` | | `864000` | How often to verify the Buff session is still active (default: 10 days; regular API traffic keeps it alive implicitly) |

---

## Project structure

```
main.py               Entry point, CLI, startup/shutdown
src/
  buff_client.py      Buff.market REST API + seller_info encryption
  processor.py        Delivery cycle orchestration + notification poller
  steam_trader.py     Steam Guard confirmation
  config.py           Config loading and validation
config.example.json   Config template
requirements.txt      Python dependencies
Dockerfile            Container image definition
docker-compose.yml    One-command Docker deployment
```
