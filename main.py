#!/usr/bin/env python3
"""
Buff.market Auto-Sale Processor
================================
Automatically processes Buff.market sell trades:
  1. Detects sold items via notification polling.
  2. Sends Steam trade offers to the Buff.market escrow bot.
  3. Confirms offers via Steam Guard (mobile authenticator).
  4. Reports offer IDs back to Buff so it can release funds.

Usage:
    python main.py [--config config.json] [--cookies cookies.json]
                   [--log-level DEBUG] [--log-file app.log] [--trace-http]

Requirements:
    pip install -r requirements.txt
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import logging.handlers
import os
import signal
import subprocess
import sys
from pathlib import Path

import aiohttp
from aiohttp_socks.connector import ProxyConnector

import src.config as cfg_module
from src.buff_client import AuthFatalError, BuffClient
from src.processor import NotificationPoller, TradeProcessor
from src.steam_trader import SteamTrader

_RESTART_DELAY = 60  # seconds to wait before restarting after auth failure


def _setup_logging(
    level: str = "INFO",
    log_file: str | None = None,
    trace_http: bool = False,
) -> None:
    fmt = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s"
    formatter = logging.Formatter(fmt)

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)

    if log_file:
        fh = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        fh.setFormatter(formatter)
        root.addHandler(fh)
        logging.getLogger(__name__).info("Logging to file: %s (10 MB × 5 rotation)", log_file)

    if trace_http:
        logging.getLogger("aiohttp").setLevel(logging.DEBUG)
        logging.getLogger("src.buff_client").setLevel(logging.DEBUG)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Buff.market auto-sale processor",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--config",      default="config.json",   help="Path to config JSON file")
    p.add_argument("--cookies",     default="cookies.json",  help="Path to Steam cookies file (created on first run)")
    p.add_argument("--log-level",   default="INFO",          help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    p.add_argument("--log-file",    default=None,            help="Optional rotating log file path")
    p.add_argument("--trace-http",  action="store_true",     help="Log full HTTP request/response bodies")
    return p.parse_args()


async def _main(args: argparse.Namespace) -> None:
    _setup_logging(
        level=args.log_level,
        log_file=args.log_file,
        trace_http=args.trace_http,
    )
    log = logging.getLogger(__name__)

    try:
        cfg = cfg_module.load(args.config)
    except cfg_module.ConfigError as exc:
        log.error("Configuration error: %s", exc)
        sys.exit(1)

    game = cfg.get("game", "csgo")
    ua = cfg.get(
        "user_agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/136.0.0.0 Safari/537.36",
    )

    # Build the aiohttp connector (optionally via SOCKS proxy)
    connector: aiohttp.BaseConnector
    if cfg.get("client_proxy") and not cfg.get("steam_use_proxy"):
        connector = ProxyConnector.from_url(cfg["client_proxy"])
        log.info("Using proxy for Buff HTTP client: %s", cfg["client_proxy"])
    else:
        connector = aiohttp.TCPConnector()

    cookie_path = Path(args.cookies)
    steam_trader = SteamTrader.from_config(cfg, cookie_path)

    async with aiohttp.ClientSession(connector=connector) as http_session:
        buff_client = BuffClient(
            game=game,
            http_session=http_session,
            session_cookie=cfg.get("buff_session", ""),
            user_agent=ua,
            trace_requests=args.trace_http,
        )

        async with steam_trader as steam:
            # --- Buff.market login ---
            # If a session cookie is present in config, verify it is still valid.
            # Otherwise (or if it has expired) perform a full Steam OpenID login.
            if cfg.get("buff_session"):
                logged_in = await buff_client.check_session()
                if not logged_in:
                    log.warning("Stored buff_session is invalid — re-logging in via Steam OpenID…")
                    logged_in = await buff_client.login_with_steam(steam.session)
            else:
                log.info("No buff_session in config — logging in via Steam OpenID…")
                logged_in = await buff_client.login_with_steam(steam.session)

            if not logged_in:
                log.error("Could not authenticate with Buff.market. Exiting.")
                sys.exit(1)

            try:
                account = await buff_client.get_account_info()
                nickname = account.get("nickname") or account.get("name") or "unknown"
                log.info("Buff.market logged in as: %s", nickname)
            except Exception as exc:
                log.error("Buff.market account check failed: %s", exc)
                sys.exit(1)

            seller_info_override = cfg.get("seller_info_override", "").strip()
            processor = TradeProcessor(
                buff=buff_client,
                my_steam_id=cfg["steam_id64"],
                steam_trader=steam,
                seller_info_override=seller_info_override,
            )

            poller = NotificationPoller(
                processor=processor,
                buff=buff_client,
                notif_interval=float(cfg.get("notif_interval_seconds", 15)),
                heartbeat_interval=float(cfg.get("heartbeat_interval_seconds", 60)),
                post_run_delay=float(cfg.get("post_run_delay_seconds", 5)),
            )

            # Graceful shutdown on SIGINT / SIGTERM
            loop = asyncio.get_running_loop()
            stop = asyncio.Event()

            def _signal_handler() -> None:
                log.info("Shutdown signal received — stopping after current cycle…")
                stop.set()

            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, _signal_handler)
                except NotImplementedError:
                    pass  # Windows

            # Session check — verifies session validity every 10 days by default.
            # Regular API activity (notification polling) keeps the session alive
            # implicitly; we only refresh/relogin if the check shows it has expired.
            # Auth errors during normal requests also trigger immediate reauth.
            keepalive_interval = float(cfg.get("session_keepalive_seconds", 864000))
            keepalive_task = asyncio.create_task(
                buff_client.keepalive_loop(keepalive_interval)
            )

            poller_task = asyncio.create_task(poller.run())
            stop_task = asyncio.create_task(stop.wait())

            done, pending = await asyncio.wait(
                {poller_task, stop_task, keepalive_task},
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

            # Check all completed tasks for AuthFatalError — trigger restart
            for task in done:
                if task is stop_task:
                    continue
                exc = task.exception()
                if isinstance(exc, AuthFatalError):
                    raise exc

            if poller_task in done and not stop.is_set():
                exc = poller_task.exception()
                if exc:
                    log.exception("Poller exited with error: %s", exc)
                    sys.exit(1)

    log.info("Buff.market auto-sale processor stopped.")


def _restart_script() -> None:
    """Replace the current process with a fresh invocation of the same script."""
    log = logging.getLogger(__name__)
    log.info(
        "Restarting script in %d seconds to re-authenticate from scratch…",
        _RESTART_DELAY,
    )
    import time
    time.sleep(_RESTART_DELAY)
    log.info("Restarting now: %s %s", sys.executable, " ".join(sys.argv))
    subprocess.Popen([sys.executable] + sys.argv)
    sys.exit(0)


def main() -> None:
    args = _parse_args()
    try:
        asyncio.run(_main(args))
    except AuthFatalError as exc:
        logging.getLogger(__name__).error("Fatal auth failure: %s", exc)
        _restart_script()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
