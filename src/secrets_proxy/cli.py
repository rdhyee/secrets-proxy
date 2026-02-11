"""CLI entry point for secrets-proxy."""

from __future__ import annotations

import argparse
import logging
import sys

from .config import load_config
from .launcher import run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secrets-proxy",
        description="Transparent proxy that injects secrets into sandboxed code's outbound HTTPS requests.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    subparsers = parser.add_subparsers(dest="command")

    # `secrets-proxy run` subcommand
    run_parser = subparsers.add_parser(
        "run", help="Run a command with secrets-proxy wrapping"
    )
    run_parser.add_argument(
        "--config",
        required=True,
        help="Path to secrets configuration JSON file",
    )
    run_parser.add_argument(
        "--allow-net",
        action="append",
        default=[],
        help="Additional hosts to allow (beyond those in secret configs). Can be repeated.",
    )
    run_parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Proxy listen port (default: 8080)",
    )
    run_parser.add_argument(
        "--ca-bundle",
        default=None,
        help="Custom path for the combined CA bundle",
    )
    run_parser.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        help="Command to run (after --)",
    )

    args = parser.parse_args(argv)

    # Set up logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [secrets-proxy] %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.command == "run":
        # Strip leading "--" from command if present
        cmd = args.cmd
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]

        if not cmd:
            print("Error: no command specified. Usage: secrets-proxy run --config secrets.json -- <command>", file=sys.stderr)
            return 1

        from .launcher import _check_config_permissions
        _check_config_permissions(args.config)

        config = load_config(args.config, allow_net=args.allow_net)
        config.proxy_port = args.port

        from pathlib import Path
        ca_path = Path(args.ca_bundle) if args.ca_bundle else None

        return run(config, cmd, ca_bundle_path=ca_path)

    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
