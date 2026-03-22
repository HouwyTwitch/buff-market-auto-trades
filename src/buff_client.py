"""
Buff.market REST API client (api.buff.market).

Handles all communication with the Buff.market API:
 - Steam OpenID auto-login (no API key needed)
 - Fetching account info and pending to-deliver orders
 - Polling notification counts for new sold items
 - Encrypting seller Steam credentials (seller_info) for server-side offer dispatch
 - Submitting encrypted credentials so buff.market sends the trade offer

Authentication flow:
  1. Call ``login_with_steam(steam_session)`` after the aiosteampy Steam login.
     This completes the Steam OpenID flow and stores the Buff session cookie.
  2. The session is kept alive by ``keepalive_loop()``.
  3. If the session ever expires, ``keepalive_loop`` re-authenticates automatically.

Delivery flow (CS2 / P2P):
  buff.market is a P2P platform — the buyer pays buff.market, buff.market holds the
  funds, and then the seller must deliver directly to the buyer.  For CS2 the app
  delegates offer-sending to buff.market's servers: the seller uploads their encrypted
  Steam session cookies so buff.market can authenticate as the seller and send
  the trade offer on their behalf.

  1. GET  /api/message/notification         — poll to_deliver_order count
  2. GET  /api/market/sell_order/to_deliver — list pending orders
  3. POST /api/market/manual_plus/seller_send_offer
         { seller_info: <RSA-4096 + AES-128-CBC encrypted cookie JSON array>,
           bill_orders: [...], steamid: "..." }
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
from typing import Any

import aiohttp
from aiosteampy.utils import do_session_steam_auth, get_cookie_value_from_session
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import load_der_public_key

log = logging.getLogger(__name__)

_BASE = "https://api.buff.market"

# ---------------------------------------------------------------------------
# API endpoints (confirmed from captured Android traffic)
# ---------------------------------------------------------------------------
URL_ACCOUNT          = f"{_BASE}/account/api/user/info"
URL_NOTIFICATION     = f"{_BASE}/api/message/notification"                           # to_deliver_order counts
URL_SELL_TO_DELIVER  = f"{_BASE}/api/market/sell_order/to_deliver"              # pending delivery orders
URL_SEND_OFFER       = f"{_BASE}/api/market/manual_plus/seller_send_offer"      # POST: submit
URL_PREVIEW_OFFER    = f"{_BASE}/api/market/manual_plus/seller_send_offer/preview"  # GET: preview before POST
URL_LOGIN_STATUS     = f"{_BASE}/account/api/login/status"
URL_LOGIN_REFRESH    = f"{_BASE}/account/api/login/status/refresh"
URL_LOGIN_STEAM      = f"{_BASE}/account/login/steam"

# appid values per game slug
_GAME_APPID: dict[str, int] = {
    "csgo":  730,
    "dota2": 570,
    "tf2":   440,
    "rust":  252490,
}

# ---------------------------------------------------------------------------
# seller_info encryption constants (from APK decompilation)
# ---------------------------------------------------------------------------

# Android WebView version bundled with buff.market APK 1.15.0.0
_WEBVIEW_VERSION = "91.0.4472.114"

# RSA-4096 public key from R6.c.API_PUBLIC_KEY_DEFAULT (buff.market APK).
# ApiCrypt.b() uses this key to RSA-encrypt a random AES-128 key, then
# AES-128-CBC/PKCS7-encrypts the steamLoginSecure cookie string.
# The server decrypts with the matching private key to obtain the seller's
# Steam session and send the trade offer on their behalf.
_API_PUBLIC_KEY_B64 = (
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwOJgwFvjy4L1J26X4mdl"
    "4al9U0b0/Ku/ETYIkugVFwW9Y4aYQA3VOpb3RT4xOtC7aSqiJsZO22d5lONRdv6k"
    "FGWOiSjXcbUK3hKLFiGgdw8KqoXiSUQbRVL+B59KcHksUeB9t33696+a6iMsZPUt"
    "6iEtXqC55GjhwaYE8hU1QZ8w2hlxCsaoJ6s7oDu5KMJXgYPAMh8rcapiAL8rc/N6"
    "+3V/GZxuJVaoHJt/7SX0uT1Oi8ILzkZsaCEBmbCRy6vmPhHk+GPeR1vKt9/D4UkC"
    "W9w3eKkIkQuKiJrjbPSU0LsbdL1y/9K7n+XZYG5zRadmtnanIs2cu1rEgB8qc1CZ"
    "bTYyWxFtPqWFOKFnZHQuA1ZX5VGWnoTV1Ap/m/L+dsod3crxxkW66M7GJmH3/oFX"
    "E5OHuUx0vXToSMdzXllcLM/Bg5hxcYxg6XkQVk8hQ5rugBe1TA7p2Qaut9nZ+uXW"
    "EJPYQS72iQN8+PitBgjsmvKKjtgd72A/VNx66ZF3tfopzdxaFrKBdPFp4M9ublOq"
    "7mObguLlJBkLdnkxmNYBAduIL74wQi9bq2Lsmr97TmayKuMKN25z9Jf0ecJ9Zl6O"
    "QEawm0pDKOE84CKZr2zwvDTShbbQD+eExwjfNiU+23C+/DDYTKxEHnk0lKsj3Z2h"
    "5NcDOPQNaxY2Waskrc6oFesCAwoBFQ=="
)

# Load once at import time — safe, public key only
_RSA_PUBLIC_KEY = load_der_public_key(base64.b64decode(_API_PUBLIC_KEY_B64))


# ---------------------------------------------------------------------------
# Public utility: seller_info encryption
# ---------------------------------------------------------------------------

# Steam domains to collect cookies from, in the order the Android app sends them.
# Captured via Frida hook on ApiCrypt.b() in buff.market APK 1.15.0.0.
_STEAM_COOKIE_SOURCES: tuple[tuple[str, str], ...] = (
    ("store.steampowered.com", "https://store.steampowered.com/"),
    ("login.steampowered.com", "https://login.steampowered.com/"),
    ("steamcommunity.com",     "https://steamcommunity.com/"),
)

# Cookies set by the Android WebView that may not be present in our headless session.
_WEBVIEW_STATIC_COOKIES: tuple[tuple[str, str, str], ...] = (
    ("steamcommunity.com", "timezoneOffset",          "0,0"),
    ("steamcommunity.com", "strResponsiveViewPrefs",  "touch"),
)


def build_seller_info(steam_session: aiohttp.ClientSession) -> str:
    """
    Build and encrypt seller credentials for buff.market.

    Replicates ``ApiCrypt.b()`` from the buff.market Android APK.  Frida
    analysis confirmed the plaintext is a JSON array of **all** Steam session
    cookies across every relevant domain — not just ``steamLoginSecure``.

    Encryption scheme (``ApiCrypt.a()``):
      1. Collect all Steam cookies from the session as a JSON array:
         ``[{"domain": ..., "path": "/", "key": ..., "value": ...}, ...]``
      2. Generate 16-byte random AES-128 key and IV.
      3. RSA-4096 / PKCS1v15 encrypt the AES key → 512-byte ciphertext.
      4. AES-128-CBC / PKCS7 encrypt the UTF-8 JSON payload.
      5. Return Base64(RSA_ct | IV | AES_ct).

    Args:
        steam_session: The authenticated aiohttp session from aiosteampy.

    Returns:
        Base64-encoded binary blob for the ``seller_info`` POST field.
    """
    # --- Collect cookies from all Steam domains ---
    entries: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for domain, url in _STEAM_COOKIE_SOURCES:
        for name, morsel in steam_session.cookie_jar.filter_cookies(url).items():
            pair = (domain, name)
            if pair in seen:
                continue
            seen.add(pair)
            entries.append({"domain": domain, "path": "/", "key": name, "value": morsel.value})

    # Append Android WebView defaults for any cookies absent from the session
    for domain, name, value in _WEBVIEW_STATIC_COOKIES:
        if (domain, name) not in seen:
            entries.append({"domain": domain, "path": "/", "key": name, "value": value})

    if not any(e["key"] == "steamLoginSecure" and e["domain"] == "steamcommunity.com"
               for e in entries):
        log.warning(
            "steamLoginSecure not found in Steam session cookies — "
            "buff.market delivery will likely fail. "
            "Ensure aiosteampy login completed successfully."
        )

    payload = json.dumps(entries, separators=(",", ":")).encode("utf-8")
    log.debug("seller_info plaintext: %d cookies, %d bytes", len(entries), len(payload))

    # --- Encrypt: RSA-4096/PKCS1v15 key-wrap + AES-128-CBC/PKCS7 ---
    aes_key = os.urandom(16)
    iv      = os.urandom(16)

    enc_aes_key = _RSA_PUBLIC_KEY.encrypt(aes_key, PKCS1v15())   # 512 bytes

    padder = PKCS7(128).padder()
    padded = padder.update(payload) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    enc    = cipher.encryptor()
    aes_ct = enc.update(padded) + enc.finalize()

    return base64.b64encode(enc_aes_key + iv + aes_ct).decode("ascii")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class BuffAPIError(Exception):
    """Raised on non-OK responses from Buff.market."""

    def __init__(self, status: int, code: str, body: str) -> None:
        super().__init__(f"Buff API error HTTP {status} code={code!r}: {body[:300]}")
        self.status = status
        self.code   = code
        self.body   = body


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class BuffClient:
    """
    Async wrapper around the Buff.market REST API.

    Args:
        game:           Game slug (``csgo``, ``dota2``, ``tf2``, ``rust``).
        http_session:   A shared aiohttp.ClientSession for Buff API calls.
        session_cookie: Optional pre-existing ``session`` cookie value.
                        Leave empty to authenticate via ``login_with_steam()``.
        user_agent:     Override the default User-Agent header.
        retry_max:      Max retry attempts on transient errors.
        retry_delay:    Base retry delay in seconds (doubles each attempt).
        trace_requests: Log full request/response bodies at DEBUG level.
    """

    def __init__(
        self,
        game: str,
        http_session: aiohttp.ClientSession,
        *,
        session_cookie: str = "",
        user_agent: str = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/136.0.0.0 Safari/537.36"
        ),
        retry_max: int = 6,
        retry_delay: float = 2.0,
        trace_requests: bool = False,
    ) -> None:
        self._cookie  = session_cookie
        self._game    = game
        self._session = http_session
        self._ua      = user_agent
        self._retry_max   = retry_max
        self._retry_delay = retry_delay
        self._trace   = trace_requests
        self._csrf: str | None = None
        self._session_valid: bool = bool(session_cookie)
        self._steam_session: aiohttp.ClientSession | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _base_headers(self) -> dict[str, str]:
        hdrs = {
            "User-Agent": self._ua,
            "Referer":    f"{_BASE}/",
            "Cookie":     f"session={self._cookie}; game={self._game}",
        }
        if self._csrf:
            hdrs["X-CSRFToken"] = self._csrf
        return hdrs

    def _extract_csrf(self, response: aiohttp.ClientResponse) -> None:
        for morsel in response.cookies.values():
            if morsel.key == "csrf_token":
                self._csrf = morsel.value
                break

    # Auth error codes Buff.market returns when the session has expired.
    _AUTH_ERROR_CODES = frozenset({"login_required", "auth_required", "not_login"})

    async def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        data: dict | None = None,
        json: Any = None,
        label: str = "",
        _reauth_done: bool = False,  # internal: avoid infinite reauth recursion
    ) -> Any:
        """Execute a request with exponential-backoff retry and auto-reauth."""
        _trace = self._trace or log.isEnabledFor(logging.DEBUG)
        delay  = self._retry_delay
        error_attempts = 0
        rate_attempts  = 0

        while True:
            if _trace:
                log.debug("Buff → %s %s params=%s body=%s", method, url, params, data or json)

            try:
                async with self._session.request(
                    method, url,
                    headers=self._base_headers(),
                    params=params,
                    data=data,
                    json=json,
                ) as resp:
                    self._extract_csrf(resp)
                    text = await resp.text()

                    if _trace:
                        log.debug("Buff ← %s [%d] %s", url, resp.status, text[:1000])

                    if resp.status == 429:
                        rate_attempts += 1
                        wait = float(resp.headers.get("Retry-After", delay * rate_attempts))
                        log.warning("Rate-limited by Buff.market (%d); sleeping %.0fs", rate_attempts, wait)
                        if rate_attempts > 10:
                            raise BuffAPIError(resp.status, "rate_limit", text)
                        await asyncio.sleep(wait)
                        continue

                    # Auto-reauth on HTTP 401/403 (session expired)
                    if resp.status in (401, 403) and not _reauth_done:
                        log.warning("HTTP %d on %s — session expired, re-authenticating…", resp.status, label or url)
                        if await self._reauth():
                            return await self._request(
                                method, url, params=params, data=data, json=json,
                                label=label, _reauth_done=True,
                            )

                    if not resp.ok:
                        raise BuffAPIError(resp.status, "http_error", text)

                    payload: dict = await resp.json(content_type=None)
                    code = str(payload.get("code", ""))
                    if code not in ("OK", ""):
                        # Auto-reauth on known auth error codes
                        if code.lower().replace(" ", "_") in self._AUTH_ERROR_CODES and not _reauth_done:
                            log.warning("Auth error '%s' on %s — re-authenticating…", code, label or url)
                            if await self._reauth():
                                return await self._request(
                                    method, url, params=params, data=data, json=json,
                                    label=label, _reauth_done=True,
                                )
                        raise BuffAPIError(resp.status, code, text)

                    return payload.get("data", payload)

            except BuffAPIError:
                raise
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                error_attempts += 1
                if error_attempts > self._retry_max:
                    log.error("Giving up on %s after %d attempts: %s", label or url, error_attempts, exc)
                    raise
                log.warning(
                    "Transient error %s (attempt %d/%d): %s — retrying in %.1fs",
                    label or url, error_attempts, self._retry_max, exc, delay,
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60.0)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    async def login_with_steam(self, steam_session: aiohttp.ClientSession) -> bool:
        """
        Log into Buff.market using an already-authenticated Steam session.

        Uses ``aiosteampy.utils.do_session_steam_auth`` which:
          1. GETs ``/account/login/steam`` on Buff → follows redirect to Steam OpenID.
          2. Parses the hidden form fields from Steam.
          3. POSTs to ``https://steamcommunity.com/openid/login`` with the Steam
             session cookies (steamLoginSecure, sessionid, etc.).
          4. Follows the redirect back to
             ``https://api.buff.market/account/login/steam/verification?...``
             which sets the Buff ``session`` cookie.
        """
        log.info("Logging into Buff.market via Steam OpenID…")
        self._steam_session = steam_session

        # Snapshot the existing cookie so we can detect a stale-cookie false-positive.
        # If do_session_steam_auth completes but buff.market never issues a new
        # session (e.g. the verification redirect failed silently), the cookie jar
        # still contains the old, already-expired value — and the login would
        # appear successful while every subsequent request would return "Login Required".
        old_session = get_cookie_value_from_session(steam_session, _BASE, "session") or ""
        log.debug("DEBUG [login_with_steam] old buff 'session' cookie: %r", old_session[:20] + "…" if old_session else "<none>")

        # Log all cookies currently in the steam_session jar before the flow
        log.debug("DEBUG [login_with_steam] steam_session cookies before do_session_steam_auth:")
        for cookie in steam_session.cookie_jar:
            log.debug("  domain=%r  name=%r  value=%r", cookie.get("domain"), cookie.key, str(cookie.value)[:40])

        try:
            await do_session_steam_auth(steam_session, URL_LOGIN_STEAM)
        except Exception as exc:
            log.error("Steam OpenID flow failed: %s", exc, exc_info=True)
            return False

        # Log all cookies after the flow so we can see what buff.market set
        log.debug("DEBUG [login_with_steam] steam_session cookies after do_session_steam_auth:")
        for cookie in steam_session.cookie_jar:
            log.debug("  domain=%r  name=%r  value=%r", cookie.get("domain"), cookie.key, str(cookie.value)[:40])

        session_val = get_cookie_value_from_session(steam_session, _BASE, "session")
        log.debug("DEBUG [login_with_steam] new buff 'session' cookie: %r", session_val[:20] + "…" if session_val else "<none>")

        if not session_val:
            log.error("Buff.market 'session' cookie not found after Steam OpenID login.")
            return False

        if session_val == old_session:
            log.error(
                "Buff.market 'session' cookie unchanged after Steam OpenID login — "
                "the verification redirect may not have set a new session. "
                "Treating login as failed to prevent an infinite re-auth loop."
            )
            return False

        self._cookie = session_val
        self._session_valid = True

        # Verify the freshly-issued session actually works before declaring success.
        if not await self._verify_session_direct():
            log.error(
                "Buff.market session check failed immediately after Steam OpenID login — "
                "the new session cookie is invalid."
            )
            self._session_valid = False
            return False

        log.info("Buff.market Steam OpenID login successful.")
        return True

    async def _verify_session_direct(self) -> bool:
        """
        Verify the current session cookie is accepted by Buff.market.

        Unlike ``check_session()``, this method makes a raw request that bypasses
        ``_request()``'s reauth logic, preventing infinite recursion when called
        from within the login flow.
        """
        try:
            headers = self._base_headers()
            log.debug("DEBUG [_verify_session_direct] GET %s", URL_LOGIN_STATUS)
            log.debug("DEBUG [_verify_session_direct] request headers: %s", dict(headers))
            async with self._session.request(
                "GET", URL_LOGIN_STATUS,
                headers=headers,
            ) as resp:
                log.debug("DEBUG [_verify_session_direct] response status: %s", resp.status)
                log.debug("DEBUG [_verify_session_direct] response headers: %s", dict(resp.headers))
                raw = await resp.text()
                log.debug("DEBUG [_verify_session_direct] response body: %s", raw[:2000])
                try:
                    payload = __import__("json").loads(raw)
                except Exception:
                    payload = {}
                data = payload.get("data", payload) if isinstance(payload, dict) else {}
                state = data.get("state") if isinstance(data, dict) else None
                log.debug("DEBUG [_verify_session_direct] parsed state=%r", state)
                return state in ("Logged", 2)
        except Exception as exc:
            log.debug("Direct session verification request failed: %s", exc, exc_info=True)
            return False

    async def check_session(self) -> bool:
        """Verify the Buff.market session is active."""
        try:
            data  = await self._request("GET", URL_LOGIN_STATUS, label="check_session")
            state = data.get("state", "") if isinstance(data, dict) else ""
            if state in ("Logged", 2):
                self._session_valid = True
                return True
            log.warning("Buff.market session state: %r (not logged in)", state)
            self._session_valid = False
            return False
        except BuffAPIError as exc:
            log.warning("Session check failed: %s", exc)
            self._session_valid = False
            return False

    async def refresh_session(self) -> bool:
        """Extend the Buff.market session lifetime without re-authentication."""
        try:
            await self._request("POST", URL_LOGIN_REFRESH, label="refresh_session")
            log.debug("Buff.market session refreshed.")
            self._session_valid = True
            return True
        except BuffAPIError as exc:
            log.warning("Session refresh failed: %s", exc)
            self._session_valid = False
            return False

    async def _reauth(self) -> bool:
        """Try refresh_session first; fall back to full Steam re-login."""
        log.warning("Buff.market session invalid — attempting refresh…")
        if await self.refresh_session():
            return True
        if self._steam_session is not None:
            log.warning("Refresh failed — re-logging in via Steam OpenID…")
            ok = await self.login_with_steam(self._steam_session)
            if not ok:
                log.error(
                    "Buff.market re-login failed. The Steam session may also "
                    "have expired. Restart the bot to re-authenticate."
                )
            return ok
        return False

    async def keepalive_loop(self, interval_seconds: float = 864000.0) -> None:
        """
        Background coroutine that keeps the Buff.market session alive.

        Every *interval_seconds* (default 10 days):
          - Calls ``check_session()`` to verify the session is still active.
          - If valid: does nothing (regular API activity keeps the session alive).
          - If expired: tries ``refresh_session()``, then full Steam re-login.
        """
        while True:
            await asyncio.sleep(interval_seconds)
            log.info("Buff.market periodic session check…")
            ok = await self.check_session()
            if ok:
                log.info("Buff.market session still active — no refresh needed.")
            else:
                await self._reauth()

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    async def get_account_info(self) -> dict:
        """Return account info (uid, nickname, steam_id, balance, etc.)."""
        return await self._request("GET", URL_ACCOUNT, label="get_account_info")

    async def get_to_deliver_count(self) -> int:
        """
        Poll ``/api/message/notification`` and return the number of pending
        delivery orders for the current game.

        The response includes a ``to_deliver_order`` dict keyed by game slug
        (e.g. ``{"csgo": 1, "dota2": 0, "pubg": 0}``).  This is the cheapest
        way to check whether there is anything to process without fetching the
        full order list.

        Returns 0 on any error so the caller can safely call it in a tight loop.
        """
        try:
            data = await self._request("GET", URL_NOTIFICATION, label="get_to_deliver_count")
            if isinstance(data, dict):
                return int(data.get("to_deliver_order", {}).get(self._game, 0))
            return 0
        except BuffAPIError:
            return 0

    async def get_pending_sell_orders(self) -> list[dict]:
        """
        Return all sell orders currently awaiting delivery from the seller.

        Endpoint: ``GET /api/market/sell_order/to_deliver?force=0&game=<g>&appid=<id>``

        The response only contains TO_DELIVER orders — no client-side filtering
        is required.  Each item includes at minimum:
          ``id``             — sell order ID (e.g. "260303T1097074736")
          ``state``          — "TO_DELIVER"
          ``has_sent_offer`` — false until buff.market dispatches the offer
          ``seller_steamid`` — the seller's SteamID64 string
          ``asset_info``     — ``{assetid, classid, contextid, appid, ...}``
        """
        appid = _GAME_APPID.get(self._game, 730)
        data  = await self._request(
            "GET",
            URL_SELL_TO_DELIVER,
            params={"force": "0", "game": self._game, "appid": str(appid)},
            label="get_pending_sell_orders",
        )
        items = data.get("items", []) if isinstance(data, dict) else []
        return items

    async def preview_send_offer(
        self,
        order_ids: list[str],
        steamid: str,
    ) -> dict[str, dict]:
        """
        Call the preview endpoint before submitting seller_info.

        Endpoint: ``GET /api/market/manual_plus/seller_send_offer/preview``

        The Android app always calls this before the POST.  It returns
        ``buyer_info`` keyed by order ID, including ``send_offer_mode``:
          - mode 3: buff.market sends on behalf of seller (use seller_info POST)
          - other modes: different delivery path (not implemented here)

        Returns the ``buyer_info`` dict, or empty dict on failure.
        """
        params: list[tuple[str, str]] = [("order_ids", oid) for oid in order_ids]
        params.append(("game", self._game))
        params.append(("steamid", steamid))
        try:
            data = await self._request(
                "GET",
                URL_PREVIEW_OFFER,
                params=params,
                label=f"preview_send_offer({order_ids})",
            )
            return data.get("buyer_info", {}) if isinstance(data, dict) else {}
        except BuffAPIError as exc:
            log.warning("preview_send_offer failed (continuing anyway): %s", exc)
            return {}

    async def submit_send_offer(
        self,
        order_ids: list[str],
        seller_info: str,
        steamid: str,
    ) -> bool:
        """
        Ask buff.market to send a Steam trade offer on behalf of the seller.

        Endpoint: ``POST /api/market/manual_plus/seller_send_offer``

        Calls the preview endpoint first (as the Android app does), then
        POSTs the encrypted seller credentials.  buff.market decrypts
        ``seller_info`` server-side to obtain the seller's ``steamLoginSecure``
        cookie, authenticates as the seller, and sends the trade offer to the
        buyer.  After this succeeds the order transitions to ``DELIVERING``
        with ``has_sent_offer=true``.

        Args:
            order_ids:   List of bill-order IDs to deliver (e.g. ["260303T…"]).
            seller_info: Base64-encoded blob from ``build_seller_info()``.
            steamid:     Seller's SteamID64 as a string.

        Returns:
            True if the server accepted the submission, False otherwise.
        """
        # Step 1 — preview (required by the Android app before every POST)
        buyer_info = await self.preview_send_offer(order_ids, steamid)
        if buyer_info:
            for oid, info in buyer_info.items():
                mode = info.get("send_offer_mode")
                log.debug("Order %s: send_offer_mode=%s", oid, mode)
                if mode is not None and mode != 3:
                    log.warning(
                        "Order %s has send_offer_mode=%s (expected 3); "
                        "proceeding with seller_info anyway",
                        oid, mode,
                    )

        # Step 2 — POST seller credentials
        body = {
            "buff_android_webview_version": _WEBVIEW_VERSION,
            "seller_info": seller_info,
            "bill_orders": order_ids,
            "steamid":     steamid,
        }
        try:
            await self._request(
                "POST",
                URL_SEND_OFFER,
                json=body,
                label=f"submit_send_offer({order_ids})",
            )
            return True
        except BuffAPIError as exc:
            log.error("submit_send_offer failed: %s", exc)
            return False
