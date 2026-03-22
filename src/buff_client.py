"""
Buff.market REST API client (api.buff.market).

Handles all communication with the Buff.market API:
 - Steam OpenID auto-login (no API key needed)
 - Fetching account info and pending trades
 - Polling notifications for new sold items
 - Querying Steam trades in WaitForSend state
 - Reporting sent Steam offer IDs back to Buff

Authentication flow:
  1. Call ``login_with_steam(steam_session)`` after the aiosteampy Steam login.
     This completes the Steam OpenID flow and stores the Buff session cookie.
  2. The session is kept alive by ``keepalive_loop()``.
  3. If the session ever expires, ``keepalive_loop`` re-authenticates automatically.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import aiohttp
from aiosteampy.utils import do_session_steam_auth, get_cookie_value_from_session

log = logging.getLogger(__name__)

_BASE = "https://api.buff.market"

# API endpoints (confirmed from APK decompilation + web API observation)
URL_ACCOUNT        = f"{_BASE}/account/api/user/info"
URL_MESSAGES       = f"{_BASE}/api/message/messages"           # type=trade notifications
URL_SELL_HISTORY   = f"{_BASE}/api/market/sell_order/history"  # order history / TO_DELIVER
URL_STEAM_TRADE    = f"{_BASE}/api/market/steam_trade"          # P2P: returns buyer trade URL + items_to_give
URL_SELL_ORDER_INFO = f"{_BASE}/api/market/sell_order/info"     # order detail (may include trade_offer_url)
URL_SELL_ORDER     = f"{_BASE}/api/market/sell_order/on_sale"
URL_LOGIN_STATUS   = f"{_BASE}/account/api/login/status"
URL_LOGIN_REFRESH  = f"{_BASE}/account/api/login/status/refresh"
URL_LOGIN_STEAM    = f"{_BASE}/account/login/steam"


class BuffAPIError(Exception):
    """Raised on non-OK responses from Buff.market."""

    def __init__(self, status: int, code: str, body: str) -> None:
        super().__init__(f"Buff API error HTTP {status} code={code!r}: {body[:300]}")
        self.status = status
        self.code = code
        self.body = body


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
        self._cookie = session_cookie
        self._game = game
        self._session = http_session
        self._ua = user_agent
        self._retry_max = retry_max
        self._retry_delay = retry_delay
        self._trace = trace_requests
        self._csrf: str | None = None
        self._session_valid: bool = bool(session_cookie)
        # Set after login_with_steam(); used by keepalive_loop for re-login
        self._steam_session: aiohttp.ClientSession | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _base_headers(self) -> dict[str, str]:
        hdrs = {
            "User-Agent": self._ua,
            "Referer": f"{_BASE}/",
            "Cookie": f"session={self._cookie}",
        }
        if self._csrf:
            hdrs["X-CSRFToken"] = self._csrf
        return hdrs

    def _extract_csrf(self, response: aiohttp.ClientResponse) -> None:
        """Update cached CSRF token from Set-Cookie headers."""
        for morsel in response.cookies.values():
            if morsel.key == "csrf_token":
                self._csrf = morsel.value
                break

    async def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        data: dict | None = None,
        json: Any = None,
        label: str = "",
    ) -> Any:
        """Execute a request with exponential-backoff retry."""
        _trace = self._trace or log.isEnabledFor(logging.DEBUG)
        delay = self._retry_delay
        error_attempts = 0
        rate_attempts = 0

        while True:
            if _trace:
                log.debug("Buff → %s %s params=%s body=%s", method, url, params, data or json)

            try:
                async with self._session.request(
                    method,
                    url,
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

                    if not resp.ok:
                        raise BuffAPIError(resp.status, "http_error", text)

                    payload: dict = await resp.json(content_type=None)
                    code = str(payload.get("code", ""))
                    if code not in ("OK", ""):
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
          1. GETs ``/account/login/steam`` on Buff → follows redirect to Steam OpenID page.
          2. Parses the hidden ``openidparams`` + ``nonce`` form fields from Steam.
          3. POSTs to ``https://steamcommunity.com/openid/login`` with the Steam
             session cookies (steamLoginSecure, sessionid, etc.).
          4. Follows the redirect back to
             ``https://api.buff.market/account/login/steam/verification?...``
             which sets the Buff ``session`` cookie.

        Args:
            steam_session: The aiosteampy SteamClient's ``session`` — must be
                           logged in (``steamLoginSecure`` cookie present).
        """
        log.info("Logging into Buff.market via Steam OpenID…")
        self._steam_session = steam_session

        # Snapshot existing cookie to detect a stale-cookie false-positive.
        # If do_session_steam_auth completes but buff.market never issues a new
        # session (e.g. the verification redirect failed silently), the cookie jar
        # still contains the old expired value — login would appear successful
        # while every subsequent request would return "Login Required".
        old_session = get_cookie_value_from_session(steam_session, _BASE, "session") or ""

        try:
            await do_session_steam_auth(steam_session, URL_LOGIN_STEAM)
        except Exception as exc:
            log.error("Steam OpenID flow failed: %s", exc)
            return False

        # The Buff session cookie is set on the steam_session's cookie jar
        # after the redirect chain lands on api.buff.market
        session_val = get_cookie_value_from_session(steam_session, _BASE, "session")
        if not session_val:
            log.error("Buff.market 'session' cookie not found after Steam OpenID login.")
            return False

        if session_val == old_session:
            log.error(
                "Buff.market 'session' cookie unchanged after Steam OpenID login — "
                "the verification redirect may not have issued a new session."
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

        Bypasses ``_request()`` to avoid triggering reauth recursion when
        called from within the login flow itself.
        """
        try:
            async with self._session.request(
                "GET", URL_LOGIN_STATUS,
                headers=self._base_headers(),
            ) as resp:
                payload = await resp.json(content_type=None)
                data = payload.get("data", payload) if isinstance(payload, dict) else {}
                return isinstance(data, dict) and data.get("state") == "Logged"
        except Exception as exc:
            log.debug("Direct session verification failed: %s", exc)
            return False

    async def check_session(self) -> bool:
        """
        Verify the Buff.market session is active.

        Calls ``GET /account/api/login/status``. Returns True if logged in.
        """
        try:
            data = await self._request("GET", URL_LOGIN_STATUS, label="check_session")
            state = data.get("state", "") if isinstance(data, dict) else ""
            if state == "Logged":
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
        """
        Extend the Buff.market session lifetime without re-authentication.

        Calls ``POST /account/api/login/status/refresh``. Returns True on success.
        """
        try:
            await self._request("POST", URL_LOGIN_REFRESH, label="refresh_session")
            log.debug("Buff.market session refreshed.")
            self._session_valid = True
            return True
        except BuffAPIError as exc:
            log.warning("Session refresh failed: %s", exc)
            self._session_valid = False
            return False

    async def keepalive_loop(self, interval_seconds: float = 1800.0) -> None:
        """
        Background coroutine that keeps the Buff.market session alive.

        Every *interval_seconds* (default 30 min):
          - Calls ``refresh_session()`` to extend the session.
          - If the session has expired, re-authenticates via Steam OpenID
            using the Steam session stored during ``login_with_steam()``.
        """
        while True:
            await asyncio.sleep(interval_seconds)
            log.info("Buff.market session keepalive…")
            ok = await self.refresh_session()
            if not ok and self._steam_session is not None:
                log.warning("Session expired — re-logging in via Steam OpenID…")
                ok = await self.login_with_steam(self._steam_session)
                if not ok:
                    log.error(
                        "Buff.market re-login failed. The Steam session may also "
                        "have expired. Restart the bot to re-authenticate."
                    )

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    async def get_account_info(self) -> dict:
        """Return account info (uid, nickname, steam_id, balance)."""
        return await self._request("GET", URL_ACCOUNT, label="get_account_info")

    async def get_notifications(self, page_size: int = 20) -> list[dict]:
        """
        Fetch the latest Buff.market trade messages.

        Endpoint: GET /api/message/messages?type=trade

        Returns items where ``template_type == 127`` when an item is sold
        and the seller needs to send an offer.
        """
        try:
            data = await self._request(
                "GET",
                URL_MESSAGES,
                params={
                    "type": "trade",
                    "page_num": "1",
                    "page_size": str(page_size),
                },
                label="get_notifications",
            )
            items = data.get("items", []) if isinstance(data, dict) else []
            return items
        except BuffAPIError as exc:
            log.debug("Notifications poll failed: %s", exc)
            return []

    async def get_pending_sell_orders(self, page_size: int = 20) -> list[dict]:
        """
        Return sell orders where the seller must send a Steam offer.

        Uses /api/market/sell_order/history without a state filter (the
        ``state`` query param is not a valid filter on this endpoint).
        Filters client-side to TO_DELIVER + is_seller_asked_to_send_offer=true
        + has_sent_offer=false.

        Only scans the first page — TO_DELIVER orders appear at the top.
        """
        data = await self._request(
            "GET",
            URL_SELL_HISTORY,
            params={
                "game": self._game,
                "page_num": "1",
                "page_size": str(page_size),
            },
            label="get_pending_sell_orders",
        )
        items = data.get("items", []) if isinstance(data, dict) else (data or [])
        return [
            i for i in items
            if i.get("state") == "TO_DELIVER"
            and i.get("is_seller_asked_to_send_offer")
            and not i.get("has_sent_offer")
        ]

    async def get_steam_trades(self, page_size: int = 20) -> list[dict]:
        """
        Return Steam trades waiting to be sent by the seller.

        Calls /api/market/steam_trade without a state filter. Per APK
        decompilation, each item has ``url``, ``items_to_give``, and
        ``user_steamid`` needed to build and send a Steam trade offer.

        NOTE: Returns empty when seller_cookie_invalid=true on all orders
        (seller hasn't registered their Steam trade URL in buff.market).
        Use get_sell_order_bot_info() per order as a fallback.
        """
        all_trades: list[dict] = []
        page_num = 1
        while True:
            data = await self._request(
                "GET",
                URL_STEAM_TRADE,
                params={
                    "game": self._game,
                    "page_num": str(page_num),
                    "page_size": str(page_size),
                },
                label=f"get_steam_trades(page={page_num})",
            )
            if isinstance(data, dict):
                items = data.get("items", [])
            else:
                items = data or []
            all_trades.extend(items)
            total_page = data.get("total_page", 1) if isinstance(data, dict) else 1
            if page_num >= total_page:
                break
            page_num += 1
        return all_trades

    async def get_buyer_trade_info(self, order_id: str, item_id: str) -> dict | None:
        """
        Fetch the buyer's Steam trade URL for a specific TO_DELIVER P2P order.

        buff.market is a P2P platform — when a sale occurs the seller sends the
        item directly to the buyer.  This method tries three approaches to find
        the buyer's Steam trade URL and the list of assets to send:

          1. GET /api/market/steam_trade?item_id=<item_id>
          2. GET /api/market/steam_trade?order_id=<order_id>
          3. GET /api/market/sell_order/info?order_no=<order_id>
             (the ``trade_offer_url`` field in the order detail)

        Returns a dict with at least ``url`` (buyer's trade URL) on success,
        or None if all approaches fail.  All responses are logged at INFO.

        NOTE: If ``seller_cookie_invalid=true`` on the order, buff.market will
        not return the buyer's trade URL until the seller's Steam trade URL is
        registered.  Call ``update_seller_trade_url()`` at startup to fix this.
        """
        # Probe steam_trade with item_id and order_id params
        for label, params in [
            ("item_id",  {"game": self._game, "item_id":  item_id}),
            ("order_id", {"game": self._game, "order_id": order_id}),
        ]:
            try:
                data = await self._request(
                    "GET", URL_STEAM_TRADE,
                    params=params,
                    label=f"buyer_info/{label}",
                )
                log.info(
                    "steam_trade?%s=%s → type=%s keys=%s",
                    label, item_id if label == "item_id" else order_id,
                    type(data).__name__,
                    list(data.keys()) if isinstance(data, dict) else
                    (list(data[0].keys()) if isinstance(data, list) and data else "empty"),
                )
                if isinstance(data, dict) and (data.get("url") or data.get("user_steamid")):
                    return data
                if isinstance(data, list) and data and data[0].get("url"):
                    return data[0]
            except BuffAPIError as exc:
                log.info("steam_trade?%s → API error: %s", label, exc)

        # Fallback: try the order detail endpoint for trade_offer_url
        try:
            detail = await self._request(
                "GET", URL_SELL_ORDER_INFO,
                params={"order_no": order_id},
                label=f"sell_order/info({order_id})",
            )
            log.info(
                "sell_order/info → type=%s keys=%s trade_offer_url=%s",
                type(detail).__name__,
                list(detail.keys()) if isinstance(detail, dict) else "N/A",
                detail.get("trade_offer_url") if isinstance(detail, dict) else "N/A",
            )
            if isinstance(detail, dict) and detail.get("trade_offer_url"):
                return {"url": detail["trade_offer_url"], **detail}
        except BuffAPIError as exc:
            log.info("sell_order/info → API error: %s", exc)

        return None

    async def update_seller_trade_url(self, trade_url: str) -> bool:
        """
        Register/update the seller's Steam trade URL with buff.market.

        This fixes ``seller_cookie_invalid=true`` on TO_DELIVER orders.
        buff.market requires the seller's trade URL to be stored before it
        will release the buyer's trade URL via the steam_trade endpoint.

        Tries several likely endpoint patterns from the APK.
        """
        candidates = [
            ("POST", f"{_BASE}/account/api/user/steam_trade_url",
             {"steam_trade_url": trade_url}),
            ("POST", f"{_BASE}/account/api/user/update",
             {"steam_trade_url": trade_url}),
            ("POST", f"{_BASE}/api/market/user/steam_trade_url",
             {"game": self._game, "steam_trade_url": trade_url}),
        ]
        for method, url, payload in candidates:
            try:
                await self._request(method, url, data=payload,
                                    label="update_seller_trade_url")
                log.info("Seller trade URL registered via %s", url)
                return True
            except BuffAPIError as exc:
                log.info("update_seller_trade_url %s → %s", url, exc)
        log.warning(
            "Could not register seller trade URL with buff.market. "
            "seller_cookie_invalid orders will be skipped until this is fixed."
        )
        return False

    async def report_offer_sent(
        self,
        trade_id: str,
        steam_offer_id: str,
        partner_steam_id: str,
        token: str,
    ) -> bool:
        """
        Notify Buff.market that a Steam trade offer has been sent.

        POSTs to ``/api/market/steam_trade`` to link the offer ID to the
        internal trade record so Buff can track completion.
        """
        payload = {
            "tradeofferid": steam_offer_id,
            "server_id":    "1",
            "item_id":      trade_id,
            "partner":      partner_steam_id,
            "token":        token,
        }
        try:
            await self._request(
                "POST",
                URL_STEAM_TRADE,
                data=payload,
                label=f"report_offer_sent(trade={trade_id})",
            )
            return True
        except BuffAPIError as exc:
            log.warning("report_offer_sent(%s) failed: %s", trade_id, exc)
            return False

    async def get_sell_orders(self, page_size: int = 20) -> list[dict]:
        """Return current active sell orders on Buff.market."""
        all_orders: list[dict] = []
        page_num = 1
        while True:
            data = await self._request(
                "GET",
                URL_SELL_ORDER,
                params={
                    "game": self._game,
                    "page_num": str(page_num),
                    "page_size": str(page_size),
                },
                label=f"get_sell_orders(page={page_num})",
            )
            if isinstance(data, dict):
                items = data.get("items", [])
            else:
                items = data or []
            all_orders.extend(items)
            total_page = data.get("total_page", 1) if isinstance(data, dict) else 1
            if page_num >= total_page:
                break
            page_num += 1
        return all_orders


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def parse_trade_url(trade_url: str) -> tuple[str, str]:
    """
    Parse a Steam trade URL and return ``(partner_steam_id64, token)``.

    The ``partner`` param in a trade URL is a 32-bit account ID; we
    convert it to SteamID64 by adding the base offset.
    """
    from urllib.parse import parse_qs, urlparse
    _BASE_OFFSET = 76561197960265728
    qs = parse_qs(urlparse(trade_url).query)
    partner_account_id = int((qs.get("partner") or ["0"])[0])
    token = (qs.get("token") or [""])[0]
    steam_id64 = str(partner_account_id + _BASE_OFFSET)
    return steam_id64, token
