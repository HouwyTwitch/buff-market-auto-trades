# buff-market-auto-sales

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

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Get your Steam secrets

Export your Steam Mobile Authenticator `.maFile` using [Steam Desktop Authenticator](https://github.com/Jessecar96/SteamDesktopAuthenticator) or similar. You need:

- `shared_secret` — generates 2FA login codes
- `identity_secret` — confirms trade offers

### 3. Configure

```bash
cp config.example.json config.json
# Fill in your credentials
```

### 4. Run

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
```
