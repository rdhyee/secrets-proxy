"""Module CLI entry point for secrets-proxy."""

from __future__ import annotations

import argparse
import json
import logging
import shlex
import sys
from pathlib import Path

from .config import load_config, load_config_from_dict
from .launcher import _check_config_permissions, cleanup_nftables_chains, run


def _handle_init(args: argparse.Namespace) -> int:
    """Handle the 'init' subcommand.

    Loads config, generates placeholders, writes sandbox env file,
    prints the SECRETS_PROXY_CONFIG_JSON value to stdout.

    Config can be provided via --config-json (string), --config-file (path),
    or stdin (piped). Prefer stdin or --config-file over --config-json to
    avoid exposing secrets in process arguments visible to `ps`.
    """
    if args.config_json:
        raw = json.loads(args.config_json)
    elif args.config_file:
        with open(args.config_file) as f:
            raw = json.load(f)
    elif not sys.stdin.isatty():
        raw = json.load(sys.stdin)
    else:
        print("Error: --config-json, --config-file, or stdin required", file=sys.stderr)
        return 1

    config = load_config_from_dict(raw)

    # Write sandbox env file (export NAME=<shell-escaped placeholder>)
    if args.sandbox_env:
        with open(args.sandbox_env, "w") as f:
            for entry in config.secrets.values():
                f.write(f'export {entry.name}={shlex.quote(entry.placeholder)}\n')

    # Print config JSON to stdout for shell capture
    print(config.to_env_json())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secrets-proxy",
        description="Transparent proxy that injects secrets into sandboxed code's outbound HTTPS requests.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    subparsers = parser.add_subparsers(dest="command")

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

    init_parser = subparsers.add_parser(
        "init",
        help="Generate placeholders and config JSON for shell scripts",
    )
    init_parser.add_argument(
        "--config-json",
        default=None,
        help="Raw JSON config string",
    )
    init_parser.add_argument(
        "--config-file",
        default=None,
        help="Path to JSON config file",
    )
    init_parser.add_argument(
        "--sandbox-env",
        default=None,
        help="Path to write sandbox env file (export NAME=PLACEHOLDER)",
    )

    subparsers.add_parser(
        "cleanup", help="Clean up stale secrets-proxy nftables chains"
    )

    args = parser.parse_args(argv)

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [secrets-proxy] %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.command == "run":
        cmd = args.cmd
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]

        if not cmd:
            print("Error: no command specified. Usage: secrets-proxy run --config secrets.json -- <command>", file=sys.stderr)
            return 1

        _check_config_permissions(args.config)
        config = load_config(args.config, allow_net=args.allow_net)
        config.proxy_port = args.port

        ca_path = Path(args.ca_bundle) if args.ca_bundle else None
        return run(config, cmd, ca_bundle_path=ca_path)

    if args.command == "init":
        return _handle_init(args)

    if args.command == "cleanup":
        cleaned = cleanup_nftables_chains()
        if cleaned:
            print("Cleaned nftables chains:")
            for chain in cleaned:
                print(f"- {chain}")
        else:
            print("No secrets-proxy nftables chains found.")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
