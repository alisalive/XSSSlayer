#!/usr/bin/env python3
"""Entry point wrapper for the xssslayer CLI command."""

import asyncio
import os
import signal
import sys

from xss_slayer import parse_args, run_scan, console, is_target_closed_error, request_shutdown


def _quiet_exception_handler(loop, context):
    """
    Suppress noisy 'exception was never retrieved' spam for Playwright's
    TargetClosedError — expected when the browser is torn down mid-operation
    on Ctrl+C. Everything else still goes to the default handler.
    """
    exc = context.get("exception")
    if exc is not None and is_target_closed_error(exc):
        return
    loop.default_exception_handler(context)


def _install_sigint_handler():
    """
    Replace the default SIGINT handler so Ctrl+C never raises
    KeyboardInterrupt into arbitrary running code (e.g. mid-write inside
    Playwright's own cleanup, which used to produce a second traceback).

    First Ctrl+C: sets a cooperative flag that run_scan() polls between
    batches, then returns normally — no exception is ever raised.
    Second Ctrl+C: the user is impatient / something is stuck, so force-exit
    immediately with no further cleanup.
    """
    pressed = False

    def handler(signum, frame):
        nonlocal pressed
        if pressed:
            os._exit(1)
        pressed = True
        console.print(
            "\n[bold red]Scan interrupted by user.[/] "
            "[dim]Finishing current batch and closing browser gracefully...[/]"
        )
        request_shutdown()

    signal.signal(signal.SIGINT, handler)


def main():
    args = parse_args()

    if args.jitter[0] > args.jitter[1]:
        args.jitter = [args.jitter[1], args.jitter[0]]

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.set_exception_handler(_quiet_exception_handler)

    _install_sigint_handler()

    try:
        loop.run_until_complete(run_scan(args))
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()

    sys.exit(0)


if __name__ == "__main__":
    main()
