#!/usr/bin/env python3
"""Entry point wrapper for the xssslayer CLI command."""

import asyncio
import sys

from xss_slayer import parse_args, run_scan, console, is_target_closed_error


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


def main():
    args = parse_args()

    if args.jitter[0] > args.jitter[1]:
        args.jitter = [args.jitter[1], args.jitter[0]]

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.set_exception_handler(_quiet_exception_handler)

    try:
        loop.run_until_complete(run_scan(args))
    except KeyboardInterrupt:
        console.print(
            "\n[bold red]Scan interrupted by user.[/] "
            "[dim]Closing browser gracefully...[/]"
        )
        pending = asyncio.all_tasks(loop)
        for t in pending:
            t.cancel()
        if pending:
            try:
                loop.run_until_complete(
                    asyncio.wait_for(
                        asyncio.gather(*pending, return_exceptions=True),
                        timeout=10,
                    )
                )
            except Exception:
                pass
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()

    sys.exit(0)


if __name__ == "__main__":
    main()
