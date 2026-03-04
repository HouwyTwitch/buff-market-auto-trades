"""
Trade processing orchestration for Buff.market.

buff.market is a P2P marketplace — the seller must deliver items directly
to the buyer.  For CS2 the platform delegates offer-sending to its own
servers: the seller uploads their encrypted ``steamLoginSecure`` cookie and
buff.market sends the Steam trade offer on their behalf.

Delivery flow per cycle:
  1. Call ``GET /api/message/notification`` — check ``to_deliver_order.<game>``.
  2. If > 0, call ``GET /api/market/sell_order/to_deliver`` — list all orders.
  3. Encrypt the seller's ``steamLoginSecure`` cookie via ``build_seller_info()``.
  4. Call ``POST /api/market/manual_plus/seller_send_offer`` with all order IDs.
     buff.market's server decrypts, authenticates as the seller, and sends offers.

This module contains:
  - TradeProcessor: runs one delivery cycle.
  - NotificationPoller: async loop that drives TradeProcessor.
"""

from __future__ import annotations

import asyncio
import logging
import time

from .buff_client import BuffClient, build_seller_info
from .steam_trader import SteamTrader

log = logging.getLogger(__name__)


class TradeProcessor:
    """
    Executes one delivery cycle against buff.market.

    Args:
        buff:                 Authenticated BuffClient.
        my_steam_id:          The seller's SteamID64 (sent in the POST body).
        steam_trader:         SteamTrader used to confirm trade offers after
                              buff.market sends them on the seller's behalf.
        seller_info_override: If set, use this pre-built seller_info value
                              instead of encrypting via build_seller_info().
                              Useful for debugging when the encryption result
                              is suspect — paste a known-good value captured
                              from a working Android request.
    """

    _CONFIRM_DELAY         = 5.0   # seconds to wait after submit before first check
    _CONFIRM_POLL_INTERVAL = 20.0  # seconds between retries if confirmation not yet visible
    _CONFIRM_MAX_POLLS     = 15    # give up after ~5 minutes (15 × 20s)

    def __init__(
        self,
        buff: BuffClient,
        my_steam_id: int,
        steam_trader: SteamTrader,
        seller_info_override: str = "",
    ) -> None:
        self._buff                = buff
        self._my_id               = my_steam_id
        self._steam               = steam_trader
        self._seller_info_override = seller_info_override
        self._submitted_ids: set[str] = set()  # order IDs submitted this session
        self._bg_tasks: set[asyncio.Task] = set()  # keeps poller tasks alive until done

    async def _confirmation_poller(self, before_ids: set[int], order_ids: list[str]) -> None:
        """
        Background task: retry confirming the buff.market trade offer every
        ``_CONFIRM_POLL_INTERVAL`` seconds until confirmations appear or we time out.
        """
        for attempt in range(1, self._CONFIRM_MAX_POLLS + 1):
            await asyncio.sleep(self._CONFIRM_POLL_INTERVAL)
            log.info(
                "Confirmation poll %d/%d for order(s): %s",
                attempt, self._CONFIRM_MAX_POLLS, order_ids,
            )
            confirmed = await self._steam.confirm_new_confirmations(before_ids)
            if confirmed > 0:
                log.info("Confirmation(s) allowed for order(s): %s", order_ids)
                return
        log.error(
            "Confirmation timed out after %d polls (%.0fs) for order(s): %s",
            self._CONFIRM_MAX_POLLS,
            self._CONFIRM_MAX_POLLS * self._CONFIRM_POLL_INTERVAL,
            order_ids,
        )

    async def run_once(self) -> None:
        """
        Perform one full delivery cycle:

        1. Fetch all TO_DELIVER orders from ``sell_order/to_deliver``.
        2. Read the ``steamLoginSecure`` cookie from the stored Steam session.
        3. Encrypt it with the buff.market RSA-4096 public key (``build_seller_info``).
        4. POST all order IDs + encrypted credentials to
           ``manual_plus/seller_send_offer`` so buff.market can send offers.
        """
        log.info("=== Delivery cycle started ===")

        # 1. Fetch pending orders
        try:
            orders = await self._buff.get_pending_sell_orders()
        except Exception as exc:
            log.error("Failed to fetch pending sell orders: %s", exc)
            return

        if not orders:
            log.info("No TO_DELIVER orders found.")
            return

        current_ids = {str(o["id"]) for o in orders if o.get("id")}

        # Drop submitted IDs that have left TO_DELIVER (completed by buff.market)
        self._submitted_ids &= current_ids

        # Only process orders we haven't submitted yet this session
        new_order_ids = [oid for oid in current_ids if oid not in self._submitted_ids]
        if not new_order_ids:
            log.info(
                "All %d TO_DELIVER order(s) already submitted — "
                "awaiting Steam trade confirmation/acceptance.",
                len(current_ids),
            )
            return

        log.info("Found %d new TO_DELIVER order(s): %s", len(new_order_ids), new_order_ids)

        # 2. Build seller_info (encrypted Steam credentials)
        if self._seller_info_override:
            seller_info = self._seller_info_override
            log.info(
                "Using seller_info_override from config (%d chars) — "
                "skipping build_seller_info()",
                len(seller_info),
            )
        else:
            try:
                seller_info = build_seller_info(self._steam.session)
            except Exception as exc:
                log.error("Failed to build seller_info: %s", exc)
                return

        # 3. Snapshot current confirmations so we can identify the new one(s) after submit
        before_conf_ids = await self._steam.get_pending_confirmation_ids()

        # 4. Submit — buff.market sends the trade offers server-side
        steamid = str(self._my_id)
        log.info("Submitting seller_info for %d order(s)…", len(new_order_ids))
        ok = await self._buff.submit_send_offer(
            order_ids=new_order_ids,
            seller_info=seller_info,
            steamid=steamid,
        )

        if ok:
            self._submitted_ids.update(new_order_ids)
            log.info(
                "Offers sent by buff.market — waiting %.0fs for confirmation(s) to appear…",
                self._CONFIRM_DELAY,
            )
            await asyncio.sleep(self._CONFIRM_DELAY)
            confirmed = await self._steam.confirm_new_confirmations(before_conf_ids)
            if confirmed == 0:
                log.info(
                    "Confirmation not yet visible — polling every %.0fs (up to %d attempts)…",
                    self._CONFIRM_POLL_INTERVAL, self._CONFIRM_MAX_POLLS,
                )
                task = asyncio.create_task(
                    self._confirmation_poller(before_conf_ids, new_order_ids)
                )
                self._bg_tasks.add(task)
                task.add_done_callback(self._bg_tasks.discard)
            log.info(
                "=== Delivery cycle complete: %d order(s) submitted ===",
                len(new_order_ids),
            )
        else:
            log.warning(
                "=== Delivery cycle failed — will retry on next trigger ==="
            )


class NotificationPoller:
    """
    Async polling loop that drives TradeProcessor.

    Strategy:
      Every ``notif_interval`` seconds: call ``GET /api/message/notification``
      and check the ``to_deliver_order.<game>`` count (fast, lightweight).
      When count > 0, run a full delivery cycle.

      Every ``heartbeat_interval`` seconds (safety net): fetch the actual
      order list with ``GET /api/market/sell_order/to_deliver`` in case
      the notification count is stale.

      After each triggered cycle, wait ``post_run_delay`` seconds then run
      one more cycle to catch orders that arrived mid-processing.
    """

    def __init__(
        self,
        processor: TradeProcessor,
        buff: BuffClient,
        *,
        notif_interval: float = 15.0,
        heartbeat_interval: float = 60.0,
        post_run_delay: float = 5.0,
    ) -> None:
        self._proc               = processor
        self._buff               = buff
        self._notif_interval     = notif_interval
        self._heartbeat_interval = heartbeat_interval
        self._post_run_delay     = post_run_delay
        self._last_heartbeat: float = 0.0

    async def run(self) -> None:
        """Run forever. Use Ctrl+C or SIGTERM to stop."""
        log.info(
            "Notification poller started — "
            "notif_interval=%.0fs, heartbeat=%.0fs",
            self._notif_interval,
            self._heartbeat_interval,
        )

        # Initial run on startup to catch orders missed while offline
        await self._safe_run()

        while True:
            await asyncio.sleep(self._notif_interval)
            now = time.monotonic()
            triggered = False

            # ── Fast notification count check ────────────────────────────
            try:
                count = await self._buff.get_to_deliver_count()
                if count > 0:
                    log.info("Notification trigger: %d to-deliver order(s).", count)
                    triggered = True
                else:
                    log.debug("Notification: no pending orders (count=0).")
            except Exception as exc:
                log.debug("Notification poll error (will rely on heartbeat): %s", exc)

            # ── Heartbeat: cross-check with the full order list ──────────
            if not triggered and (now - self._last_heartbeat) >= self._heartbeat_interval:
                self._last_heartbeat = now
                try:
                    orders = await self._buff.get_pending_sell_orders()
                    if orders:
                        log.info("Heartbeat trigger: %d TO_DELIVER order(s).", len(orders))
                        triggered = True
                    else:
                        log.debug("Heartbeat: no pending orders.")
                except Exception as exc:
                    log.warning("Heartbeat poll failed: %s", exc)

            if triggered:
                await self._safe_run()
                await asyncio.sleep(self._post_run_delay)
                await self._safe_run()

    async def _safe_run(self) -> None:
        try:
            await self._proc.run_once()
        except Exception as exc:
            log.exception("Unexpected error in delivery cycle: %s", exc)
