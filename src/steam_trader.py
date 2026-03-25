"""
Steam-side trade logic: confirm offers via Steam Guard.

Uses aiosteampy — fully async, native aiohttp, no thread-pool wrapping needed.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import aiohttp
from aiosteampy import SteamClient

log = logging.getLogger(__name__)

_KEEPALIVE_INTERVAL = 20 * 60  # 20 minutes


class SteamTrader:
    """
    High-level helper for Steam trade operations.

    Handles login, session keep-alive, and trade-offer confirmation
    via Steam Guard (shared/identity secrets).

    Usage::

        trader = SteamTrader.from_config(cfg, Path("cookies.json"))
        async with trader:
            confirmed = await trader.confirm_new_confirmations(before_ids)
    """

    def __init__(
        self,
        client: SteamClient,
        steam_id: int,
        cookie_path: Path,
    ) -> None:
        self._client = client
        self._steam_id = steam_id
        self._cookie_path = cookie_path
        self._keepalive_task: asyncio.Task | None = None

    @property
    def session(self) -> aiohttp.ClientSession:
        """The underlying aiohttp session, for reading live Steam cookies."""
        return self._client.session

    @classmethod
    def from_config(cls, cfg: dict, cookie_path: Path) -> "SteamTrader":
        """Build a SteamTrader from the parsed config dict."""
        steam_id = int(cfg["steam_id64"])
        proxy: str | None = None
        if cfg.get("client_proxy") and cfg.get("steam_use_proxy"):
            proxy = cfg["client_proxy"]

        client = SteamClient(
            steam_id=steam_id,
            username=cfg["steam_login"],
            password=cfg["steam_password"],
            shared_secret=cfg["shared_secret"],
            identity_secret=cfg["identity_secret"],
            api_key=cfg.get("steam_api_key") or None,
            proxy=proxy,
        )
        return cls(client=client, steam_id=steam_id, cookie_path=cookie_path)

    async def __aenter__(self) -> "SteamTrader":
        await self._login()
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._keepalive_task:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass
        await self._client.session.close()

    async def _login(self) -> None:
        await _retry(self._client.login, label="steam_login")
        log.info("Logged in to Steam as %s", self._steam_id)

    async def _keepalive_loop(self) -> None:
        while True:
            await asyncio.sleep(_KEEPALIVE_INTERVAL)
            try:
                alive = await self._client.is_session_alive()
                if alive:
                    log.debug("Keep-alive: Steam session OK")
                else:
                    log.warning("Keep-alive: session expired — re-logging in")
                    await _retry(self._client.login, label="keepalive_login")
                    log.info("Keep-alive: session restored")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.error("Keep-alive error: %s", exc)

    async def relogin(self) -> None:
        """Re-authenticate the Steam session (e.g. after session expiry)."""
        await _retry(self._client.login, label="steam_relogin")
        log.info("Steam session restored for %s", self._steam_id)

    async def get_pending_confirmation_ids(self) -> set[int]:
        """Return the set of creator_ids (trade offer IDs) for all pending confirmations."""
        try:
            confs = await _retry(
                lambda: self._client.get_confirmations(update_listings=False),
                label="get_confirmations",
            )
            return {c.creator_id for c in confs}
        except Exception as exc:
            log.error("get_pending_confirmation_ids error: %s", exc)
            return set()

    async def confirm_new_confirmations(self, before_ids: set[int]) -> int:
        """
        Confirm only the confirmations that appeared after *before_ids* was taken.

        Returns the number of confirmations that were allowed.
        """
        try:
            confs = await _retry(
                lambda: self._client.get_confirmations(update_listings=False),
                label="get_confirmations_after",
            )
            new_confs = [c for c in confs if c.creator_id not in before_ids]
            if not new_confs:
                log.info("No new confirmations found yet")
                return 0
            log.info("Confirming %d new trade offer confirmation(s)", len(new_confs))
            await _retry(
                lambda: self._client.allow_multiple_confirmations(new_confs),
                label="allow_multiple_confirmations",
            )
            return len(new_confs)
        except Exception as exc:
            log.error("confirm_new_confirmations error: %s", exc)
            return 0


async def _retry(fn, *, label: str = "", max_attempts: int = 6, base_delay: float = 3.0):
    """Retry an async callable on transient network errors with exponential backoff."""
    delay = base_delay
    for attempt in range(1, max_attempts + 2):
        try:
            return await fn()
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, TimeoutError) as exc:
            if attempt > max_attempts:
                log.error("[%s] Giving up after %d attempts: %s", label, attempt, exc)
                raise
            log.warning(
                "[%s] Transient error (attempt %d/%d): %s — retrying in %.1fs",
                label, attempt, max_attempts + 1, exc, delay,
            )
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60.0)
        except Exception:
            raise
