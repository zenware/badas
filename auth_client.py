#!/usr/bin/env python3
"""
Small CLI client for poking at BadAS.

Examples:
    python auth_client.py login root password
    python auth_client.py user 2
    python auth_client.py search alice
    python auth_client.py me <token>
    python auth_client.py fetch http://127.0.0.1:5001/debug
    python auth_client.py ping '127.0.0.1; id'

This client does not know which behaviours are flaws. It simply makes the
service easy to explore.
"""

import argparse
import json
import os
import sys

import requests

DEFAULT_URL = os.environ.get("BADAS_URL", "http://127.0.0.1:5001")


def show(response):
    print(f"HTTP {response.status_code}")
    content_type = response.headers.get("Content-Type", "")
    if "application/json" in content_type:
        try:
            print(json.dumps(response.json(), indent=2))
            return
        except ValueError:
            pass
    print(response.text)


def main():
    parser = argparse.ArgumentParser(description="CLI client for the BadAS lab.")
    parser.add_argument("--url", default=DEFAULT_URL, help="base URL of the server")
    subparsers = parser.add_subparsers(dest="command", required=True)

    login = subparsers.add_parser("login", help="log in and print the JWT/session")
    login.add_argument("username")
    login.add_argument("password")

    user = subparsers.add_parser("user", help="fetch a user profile by id")
    user.add_argument("user_id")

    search = subparsers.add_parser("search", help="search usernames")
    search.add_argument("query")

    me = subparsers.add_parser("me", help="inspect a JWT")
    me.add_argument("token")

    fetch = subparsers.add_parser("fetch", help="ask the server to fetch a URL")
    fetch.add_argument("target")

    ping = subparsers.add_parser("ping", help="ask the server to ping a host")
    ping.add_argument("host")

    reset = subparsers.add_parser("reset", help="request a reset token")
    reset.add_argument("username")

    args = parser.parse_args()
    base = args.url.rstrip("/")

    try:
        if args.command == "login":
            response = requests.post(
                f"{base}/api/login",
                json={"username": args.username, "password": args.password},
                timeout=10,
            )
        elif args.command == "user":
            response = requests.get(f"{base}/api/users/{args.user_id}", timeout=10)
        elif args.command == "search":
            response = requests.get(
                f"{base}/api/users/search", params={"q": args.query}, timeout=10
            )
        elif args.command == "me":
            response = requests.get(
                f"{base}/api/me",
                headers={"Authorization": f"Bearer {args.token}"},
                timeout=10,
            )
        elif args.command == "fetch":
            response = requests.get(
                f"{base}/fetch", params={"url": args.target}, timeout=15
            )
        elif args.command == "ping":
            response = requests.get(
                f"{base}/ping", params={"host": args.host}, timeout=15
            )
        elif args.command == "reset":
            response = requests.post(
                f"{base}/reset/request",
                json={"username": args.username},
                timeout=10,
            )
        else:
            parser.error("unknown command")
            return 2
    except requests.RequestException as exc:
        print(f"request failed: {exc}")
        return 1

    show(response)
    return 0


if __name__ == "__main__":
    sys.exit(main())
