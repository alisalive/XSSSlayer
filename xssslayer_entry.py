#!/usr/bin/env python3
"""Entry point wrapper for the xssslayer CLI command."""

import asyncio
import sys

from xss_slayer import parse_args, run_scan, console


def main():
    args = parse_args()

    if args.jitter[0] > args.jitter[1]:
        args.jitter = [args.jitter[1], args.jitter[0]]

    try:
        asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user.[/]")
        sys.exit(0)


if __name__ == "__main__":
    main()
