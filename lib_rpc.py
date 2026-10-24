#!/usr/bin/env python3
"""Minimal JSON-RPC client that mimics bitcoin-cli, for remote nodes by IP.

  python3 lib_rpc.py <method> [parameters...]

The connection comes from environment variables, never from the command line
(so the password never shows up in `ps`):
  BTC_RPC_URL     e.g. http://192.168.1.50:8332
  BTC_RPC_USER / BTC_RPC_PASS     or
  BTC_RPC_COOKIE  path to a .cookie file (user:password)

Same as bitcoin-cli: every parameter that is valid JSON is sent as JSON and
everything else as text; a null result prints nothing.
"""

import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def parse_param(p):
    # A txid could be all digits and get parsed as a number: keep it as text.
    if HEX64.match(p):
        return p
    try:
        return json.loads(p)
    except ValueError:
        return p


def credentials():
    cookie = os.environ.get("BTC_RPC_COOKIE")
    if cookie:
        with open(cookie) as f:
            user, _, password = f.read().strip().partition(":")
        return user, password
    return os.environ.get("BTC_RPC_USER", ""), os.environ.get("BTC_RPC_PASS", "")


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    url = os.environ.get("BTC_RPC_URL")
    if not url:
        print("Missing BTC_RPC_URL.", file=sys.stderr)
        sys.exit(2)

    method, params = sys.argv[1], [parse_param(p) for p in sys.argv[2:]]
    body = json.dumps({"jsonrpc": "1.0", "id": "bip110-tools",
                       "method": method, "params": params}).encode()
    user, password = credentials()
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json", "Authorization": f"Basic {token}"})

    try:
        with urllib.request.urlopen(req) as resp:
            reply = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("Error 401: wrong RPC user or password.", file=sys.stderr)
            sys.exit(1)
        try:
            reply = json.load(e)
        except ValueError:
            print(f"HTTP error {e.code} from the node.", file=sys.stderr)
            sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Could not connect to {url}: {e.reason}", file=sys.stderr)
        print("Check IP/port, rpcbind and rpcallowip in the node configuration.",
              file=sys.stderr)
        sys.exit(1)

    if reply.get("error"):
        err = reply["error"]
        print(f"error code: {err.get('code')}\nerror message:\n{err.get('message')}", file=sys.stderr)
        sys.exit(1)

    result = reply.get("result")
    if result is None:
        return
    if isinstance(result, str):
        print(result)
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
