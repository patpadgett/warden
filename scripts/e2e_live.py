#!/usr/bin/env python3
"""Live end-to-end smoke test for Warden.

Starts a real `warden serve` process (HTTP + HTTPS listeners), an HTTP and a
WebSocket upstream, then drives headless Chrome with a CDP virtual authenticator
through first-run setup, dashboard access, proxying, SSO, WebSockets, logout,
and passkey login.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import httpx
from websockets.sync.client import connect as ws_connect
from websockets.sync.server import serve as ws_serve

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from tests.conftest import UpstreamHandler, config_dict, write_config  # noqa: E402
from tests.test_tls import make_certificate  # noqa: E402
from tests.test_ws import _handler, _select_subprotocol  # noqa: E402

CHROME = os.environ.get("CHROME") or shutil.which("google-chrome") or shutil.which("chromium") or "/usr/bin/google-chrome"
SETUP_TOKEN = "LIVE-SETUP-CODE-2026"
ADMIN = "warden.home.lan"
HTTP_PORT = 18080
HTTPS_PORT = 18443
BASE = f"https://{ADMIN}:{HTTPS_PORT}"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def wait_port(port: int, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"port {port} did not open")


def wait_http(url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=0.5).read()
            return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(f"{url} did not answer")


class CDP:
    def __init__(self, url: str) -> None:
        self.ws = ws_connect(url, max_size=None, open_timeout=10)
        self.next_id = 0
        self.events: list[dict] = []

    def call(self, method: str, **params: object) -> dict:
        self.next_id += 1
        request_id = self.next_id
        self.ws.send(json.dumps({"id": request_id, "method": method, "params": params}))
        while True:
            message = json.loads(self.ws.recv(timeout=20))
            if message.get("id") == request_id:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message.get("result", {})
            self.events.append(message)

    def evaluate(self, expression: str, *, await_promise: bool = True) -> object:
        result = self.call(
            "Runtime.evaluate",
            expression=expression,
            returnByValue=True,
            awaitPromise=await_promise,
            userGesture=True,
        )
        if result.get("exceptionDetails"):
            details = result["exceptionDetails"]
            text = details.get("exception", {}).get("description") or details.get("text")
            raise RuntimeError(f"JS failed: {text}")
        return result.get("result", {}).get("value")

    def wait_js(self, expression: str, timeout: float = 25.0) -> object:
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            try:
                last = self.evaluate(expression)
            except Exception as exc:  # navigation can destroy the context
                last = f"error: {exc}"
            if last:
                return last
            time.sleep(0.15)
        raise RuntimeError(f"timed out waiting for JS: {expression} (last={last!r})")

    def navigate(self, url: str, expect: str) -> None:
        self.call("Page.navigate", url=url)
        needle = json.dumps(expect)
        self.wait_js(
            f"document.readyState === 'complete' && location.href.includes({needle})"
        )

    def drain_events(self) -> list[dict]:
        events, self.events = self.events, []
        return events

    def close(self) -> None:
        try:
            self.ws.close()
        except Exception:
            pass


def chrome_target(port: int) -> str:
    wait_http(f"http://127.0.0.1:{port}/json/version")
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=5) as response:
        targets = json.load(response)
    for target in targets:
        if target.get("type") == "page":
            return target["webSocketDebuggerUrl"]
    raise RuntimeError("no Chrome page target")


def http_get(client: httpx.Client, path: str, host: str, **kwargs: object) -> httpx.Response:
    headers = dict(kwargs.pop("headers", {}) or {})
    headers["host"] = host
    return client.get(path, headers=headers, **kwargs)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="warden-e2e-"))
    print(f"workdir {tmp}")
    http_upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    http_thread = threading.Thread(target=http_upstream.serve_forever, daemon=True)
    http_thread.start()
    ws_upstream = ws_serve(
        _handler,
        "127.0.0.1",
        0,
        subprotocols=["chat"],
        select_subprotocol=_select_subprotocol,
    )
    ws_thread = threading.Thread(target=ws_upstream.serve_forever, daemon=True)
    ws_thread.start()

    http_url = f"http://127.0.0.1:{http_upstream.server_port}"
    ws_url = f"http://127.0.0.1:{ws_upstream.socket.getsockname()[1]}"
    cert_dir = tmp / "certs"
    cert_dir.mkdir()
    cert_path, key_path = make_certificate(
        cert_dir,
        days=45,
        names=(
            ADMIN,
            "app.home.lan",
            "public.home.lan",
            "redirect.home.lan",
            "wschat.home.lan",
            "wsauth.home.lan",
        ),
    )
    acme_dir = tmp / "acme"
    acme_dir.mkdir()
    (acme_dir / "live-token").write_text("acme-proof\n", encoding="utf-8")
    renew_marker = tmp / "renew-marker"
    mesh_config = tmp / "wg0.conf"

    data = config_dict(
        tmp,
        routes=[
            {"host": "app.home.lan", "upstream": http_url, "name": "App", "auth": True},
            {"host": "public.home.lan", "upstream": http_url, "name": "Public", "auth": False},
            {"host": "redirect.home.lan", "upstream": http_url, "name": "Redirect", "auth": False},
            {"host": "wschat.home.lan", "upstream": ws_url, "name": "Chat", "auth": False},
            {"host": "wsauth.home.lan", "upstream": ws_url, "name": "Auth Chat", "auth": True},
        ],
        http_port=HTTP_PORT,
        https_port=HTTPS_PORT,
        admin_host=ADMIN,
        cookie_domain="home.lan",
        tls={
            "enabled": True,
            "certfile": str(cert_path),
            "keyfile": str(key_path),
            "acme_webroot": str(acme_dir),
            "renew_command": f"printf renewed > {renew_marker}",
            "renew_days_before": 60,
            "check_interval_hours": 1,
        },
        mesh={
            "enabled": True,
            "interface": "wg0",
            "address": "10.44.0.1/24",
            "listen_port": 51820,
            "endpoint": "vpn.home.lan:51820",
            "dns": "10.44.0.1",
            "client_allowed_ips": "10.44.0.0/24",
            "config_path": str(mesh_config),
        },
        log_level="info",
    )
    config_path = write_config(tmp, data)
    log_path = tmp / "warden.log"
    log_file = log_path.open("w", encoding="utf-8")
    env = os.environ.copy()
    env["WARDEN_CONFIG"] = str(config_path)
    env["WARDEN_SETUP_TOKEN"] = SETUP_TOKEN
    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "warden",
            "serve",
            "--host",
            "127.0.0.1",
        ],
        cwd=str(REPO),
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True,
    )
    chrome = None
    cdp = None
    checks: list[str] = []

    def check(name: str, condition: object, detail: object = "") -> None:
        if not condition:
            raise AssertionError(f"{name}: {detail}")
        checks.append(name)
        print(f"  ok  {name}")

    try:
        wait_port(HTTP_PORT)
        wait_port(HTTPS_PORT)
        time.sleep(0.6)
        client = httpx.Client(
            base_url=f"https://127.0.0.1:{HTTPS_PORT}",
            verify=False,
            follow_redirects=False,
            timeout=10,
            trust_env=False,
        )

        # ------------------------------------------------------------------
        print("unclaimed instance")
        response = http_get(client, "/", ADMIN, headers={"accept": "text/html"})
        check("unclaimed dashboard redirects to setup", response.status_code == 303, response.text)
        check(
            "setup redirect target",
            response.headers["location"] == "/_warden/setup",
            response.headers.get("location"),
        )
        response = http_get(client, "/_warden/api/status", ADMIN, headers={"accept": "application/json"})
        check("unclaimed API is 401", response.status_code == 401, response.status_code)
        check("unclaimed API advertises setup", response.json().get("setup_required") is True)
        response = http_get(client, "/_warden/setup", ADMIN, headers={"accept": "text/html"})
        check("setup page renders", response.status_code == 200, response.status_code)
        check("setup page has form", 'id="setup-form"' in response.text)
        response = http_get(client, "/_warden/health", ADMIN)
        check("health reports setup required", response.json()["setup_required"] is True)

        # ------------------------------------------------------------------
        print("TLS companion")
        plain = httpx.Client(base_url=f"http://127.0.0.1:{HTTP_PORT}", trust_env=False, timeout=10, follow_redirects=False)
        response = http_get(plain, "/service?q=1", ADMIN)
        check("http listener redirects", response.status_code == 308, response.status_code)
        check(
            "https redirect uses public port",
            response.headers["location"] == f"{BASE}/service?q=1",
            response.headers.get("location"),
        )
        response = plain.get("/.well-known/acme-challenge/live-token")
        check("ACME token served on http", response.status_code == 200, response.status_code)
        check("ACME token body", response.text.strip() == "acme-proof", response.text)
        response = http_get(client, "/.well-known/acme-challenge/live-token", ADMIN)
        check("ACME token served on https", response.status_code == 200, response.status_code)

        # ------------------------------------------------------------------
        print("chrome setup + virtual passkey")
        chrome_port = free_port()
        profile = tmp / "chrome-profile"
        hosts = "warden.home.lan,app.home.lan,public.home.lan,redirect.home.lan,wschat.home.lan,wsauth.home.lan"
        rules = ", ".join(f"MAP {host} 127.0.0.1" for host in hosts.split(","))
        chrome = subprocess.Popen(
            [
                CHROME,
                "--headless=new",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--no-proxy-server",
                "--ignore-certificate-errors",
                "--disable-background-networking",
                f"--remote-debugging-port={chrome_port}",
                f"--user-data-dir={profile}",
                f"--host-resolver-rules={rules}",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cdp = CDP(chrome_target(chrome_port))
        cdp.call("Page.enable")
        cdp.call("Runtime.enable")
        cdp.call("Network.enable")
        cdp.call("Log.enable")
        cdp.call("WebAuthn.enable", enableUI=False)
        authenticator = cdp.call(
            "WebAuthn.addVirtualAuthenticator",
            options={
                "protocol": "ctap2",
                "transport": "internal",
                "hasResidentKey": True,
                "hasUserVerification": True,
                "isUserVerified": True,
                "automaticPresenceSimulation": True,
            },
        )
        check("virtual authenticator added", bool(authenticator.get("authenticatorId")))

        cdp.navigate(f"{BASE}/_warden/setup", "/_warden/setup")
        check("browser sees secure context", cdp.evaluate("window.isSecureContext") is True)
        check("browser supports passkeys", cdp.evaluate("Boolean(window.PublicKeyCredential)") is True)
        cdp.evaluate("document.querySelector('#setup-username').value = 'pat'")
        cdp.evaluate("document.querySelector('#setup-display-name').value = 'Pat'")
        cdp.evaluate("document.querySelector('#setup-code').value = 'LIVESETUPCODE2026'")
        cdp.evaluate("document.querySelector('#setup-form').requestSubmit()")
        cdp.wait_js(
            "document.readyState === 'complete' && !location.pathname.startsWith('/_warden/setup')",
            timeout=40,
        )
        page = cdp.evaluate("document.body.dataset.page")
        check("setup lands on dashboard", page == "dashboard", page)
        check(
            "dashboard names the account",
            "pat" in (cdp.evaluate("document.body.textContent") or "").lower(),
        )

        cookies = cdp.call("Network.getCookies", urls=[f"{BASE}/"])["cookies"]
        session = next((item for item in cookies if item["name"] == "warden_session"), None)
        check("session cookie set", session is not None)
        check("session cookie is HttpOnly", session.get("httpOnly") is True, session)
        check("session cookie has parent domain", session.get("domain") == ".home.lan", session)
        token = session["value"]

        # ------------------------------------------------------------------
        print("authenticated dashboard + APIs")
        auth_headers = {"accept": "text/html", "cookie": f"warden_session={token}"}
        response = http_get(client, "/", ADMIN, headers=auth_headers)
        check("dashboard renders", response.status_code == 200, response.status_code)
        check("dashboard contains nav", "Access" in response.text and "Mesh" in response.text)
        check("security headers", response.headers.get("x-frame-options") == "DENY")
        check("admin responses are no-store", response.headers.get("cache-control") == "no-store")
        for path in ("/passkeys", "/activity", "/config", "/mesh"):
            response = http_get(client, path, ADMIN, headers=auth_headers)
            check(f"{path} renders", response.status_code == 200, response.status_code)
        response = http_get(
            client,
            "/_warden/api/status",
            ADMIN,
            headers={"accept": "application/json", "cookie": f"warden_session={token}"},
        )
        check("status API", response.status_code == 200, response.status_code)
        check("status API lists services", "services" in response.json(), response.text[:300])
        check("status API has totals", "totals" in response.json(), response.text[:300])
        check("health reports claimed", http_get(client, "/_warden/health", ADMIN).json()["setup_required"] is False)

        # ------------------------------------------------------------------
        print("admin mutation guards + mesh API")
        api_headers = {
            "accept": "application/json",
            "cookie": f"warden_session={token}",
            "host": ADMIN,
            "content-type": "application/json",
        }
        sparse_headers = {key: value for key, value in api_headers.items() if key != "content-type"}
        response = client.post(
            "/_warden/api/mesh/peers",
            headers=sparse_headers,
            json={"name": "blocked"},
        )
        check("admin mutation requires request header", response.status_code == 403, response.status_code)
        response = client.post(
            "/_warden/api/mesh/peers",
            headers={**api_headers, "x-warden-request": "1", "origin": "https://evil.example"},
            json={"name": "blocked"},
        )
        check("admin mutation blocks cross-origin", response.status_code == 403, response.status_code)

        mesh_headers = {**api_headers, "x-warden-request": "1"}
        response = client.post("/_warden/api/mesh/peers", headers=mesh_headers, json={"name": "laptop"})
        check("mesh peer created", response.status_code == 200, response.text[:300])
        peer_payload = response.json()
        peer = peer_payload["peer"]
        peer_config = peer_payload["config"]
        check("mesh peer address assigned", peer["address"] == "10.44.0.2", peer)
        check("mesh peer filename", peer_payload["filename"] == "warden-laptop.conf", peer_payload["filename"])
        check("peer config has interface", "[Interface]" in peer_config and "PrivateKey = " in peer_config)
        check("peer config has mesh address", "Address = 10.44.0.2/32" in peer_config, peer_config)
        check("peer config has hub endpoint", "Endpoint = vpn.home.lan:51820" in peer_config, peer_config)
        check("peer config has allowed ips", "AllowedIPs = 10.44.0.0/24" in peer_config, peer_config)
        check("peer config has keepalive", "PersistentKeepalive = 25" in peer_config, peer_config)
        check("peer config hides no keys", "<peer private key unavailable>" not in peer_config, peer_config)

        response = client.post("/_warden/api/mesh/peers", headers=mesh_headers, json={"name": "laptop"})
        check("duplicate mesh peer rejected", response.status_code == 400, response.status_code)

        response = client.get(
            f"/_warden/api/mesh/peers/{peer['id']}/config",
            headers={**api_headers, "x-warden-request": "1"},
        )
        check("mesh peer config downloads", response.status_code == 200, response.status_code)
        check(
            "download matches generated config",
            response.json()["config"] == peer_config,
            response.text[:200],
        )

        response = http_get(client, "/mesh", ADMIN, headers=auth_headers)
        check(
            "mesh page lists peer",
            response.status_code == 200 and f'data-peer-id="{peer["id"]}"' in response.text,
            response.text[:300],
        )
        check("mesh page shows peer address", "10.44.0.2" in response.text)
        check("mesh page shows hub key", 'id="hub-public-key"' in response.text)
        check("mesh page notes missing wg", "WireGuard is not readable" in response.text, response.text[:300])

        response = client.post(
            "/_warden/api/mesh/apply", headers={**mesh_headers, "content-type": "application/json"}, json={}
        )
        check("mesh apply fails cleanly without wg", response.status_code == 400, response.status_code)
        check("mesh apply error is actionable", "WireGuard" in response.json().get("detail", ""), response.text)
        check("mesh apply did not write config", not mesh_config.exists())

        response = client.delete(f"/_warden/api/mesh/peers/{peer['id']}", headers=mesh_headers)
        check("mesh peer removed", response.status_code == 200, response.status_code)
        response = client.delete(f"/_warden/api/mesh/peers/{peer['id']}", headers=mesh_headers)
        check("removed mesh peer is gone", response.status_code == 404, response.status_code)
        response = http_get(client, "/mesh", ADMIN, headers=auth_headers)
        check("mesh page drops removed peer", f'data-peer-id="{peer["id"]}"' not in response.text)

        # ------------------------------------------------------------------
        print("UI integrity")
        for path in ("/", "/passkeys", "/activity", "/config", "/mesh"):
            cdp.drain_events()
            cdp.call("Page.navigate", url=f"{BASE}{path}")
            cdp.wait_js(
                f"document.readyState === 'complete' && location.pathname === {json.dumps(path)}"
            )
            time.sleep(0.8)
            duplicates = cdp.evaluate(
                """
                (() => {
                  const ids = Array.from(document.querySelectorAll('[id]')).map((el) => el.id);
                  return ids.filter((id, index) => ids.indexOf(id) !== index);
                })()
                """
            )
            missing_labels = cdp.evaluate(
                """
                (() => {
                  const missing = [];
                  document.querySelectorAll('[aria-labelledby], [aria-describedby]').forEach((el) => {
                    for (const attr of ['aria-labelledby', 'aria-describedby']) {
                      (el.getAttribute(attr) || '').split(/\\s+/).filter(Boolean).forEach((id) => {
                        if (!document.getElementById(id)) missing.push(attr + ':' + id);
                      });
                    }
                  });
                  document.querySelectorAll('label[for]').forEach((label) => {
                    if (!document.getElementById(label.htmlFor)) missing.push('label:' + label.htmlFor);
                  });
                  return missing;
                })()
                """
            )
            events = cdp.drain_events()
            js_errors = []
            for event in events:
                if event.get("method") == "Runtime.exceptionThrown":
                    details = event["params"].get("exceptionDetails", {})
                    js_errors.append(
                        details.get("exception", {}).get("description") or details.get("text")
                    )
                elif event.get("method") == "Log.entryAdded":
                    entry = event["params"].get("entry", {})
                    if entry.get("level") == "error":
                        js_errors.append(entry.get("text"))
            check(f"{path} has no duplicate ids", not duplicates, duplicates)
            check(f"{path} has valid aria/label references", not missing_labels, missing_labels)
            check(f"{path} has no JS errors", not js_errors, js_errors)
            check(
                f"{path} booted shared JS",
                cdp.evaluate("Boolean(window.Warden && window.Warden.fetchJSON)") is True,
            )

        # ------------------------------------------------------------------
        print("proxy routing")
        no_cookie = {"accept": "text/html"}
        response = http_get(client, "/", "app.home.lan", headers=no_cookie)
        check("protected route redirects", response.status_code == 303, response.status_code)
        check(
            "protected redirect carries next",
            "/_warden/login?next=%2F" in response.headers.get("location", ""),
            response.headers.get("location"),
        )
        response = http_get(
            client, "/", "app.home.lan", headers={"accept": "application/json"}
        )
        check("protected API route is 401", response.status_code == 401, response.status_code)
        response = http_get(
            client,
            "/thing?x=1",
            "app.home.lan",
            headers={"accept": "text/html", "cookie": f"warden_session={token}"},
        )
        check("protected route proxies", response.status_code == 200, response.status_code)
        check("upstream gets username", "user=pat" in response.text, response.text)
        check("upstream gets https scheme", "xfp=https" in response.text, response.text)
        check("upstream gets path", "path=/thing?x=1" in response.text, response.text)
        check("warden cookie stripped", "cookie=None" in response.text, repr(response.text))

        spoof = {
            "accept": "text/html",
            "cookie": "warden_session=spoof; theme=dark",
            "x-warden-user": "evil",
            "x-warden-user-id": "999",
            "x-forwarded-for": "6.6.6.6",
        }
        response = http_get(client, "/", "public.home.lan", headers=spoof)
        check("public route proxies", response.status_code == 200, response.status_code)
        check("public route strips warden cookie", "cookie=theme=dark" in response.text, response.text)
        check("public route strips identity", "user=None" in response.text, response.text)
        check("public route replaces xff", "xff=127.0.0.1" in response.text, response.text)

        response = http_get(
            client,
            "/redirect",
            f"redirect.home.lan:{HTTPS_PORT}",
            headers={"accept": "text/html"},
        )
        check("upstream redirect preserved", response.status_code == 302, response.status_code)
        check(
            "upstream redirect rewritten",
            response.headers["location"] == f"https://redirect.home.lan:{HTTPS_PORT}/landing?x=1",
            response.headers.get("location"),
        )
        set_cookies = response.headers.get_list("set-cookie")
        check("spoofed warden cookie dropped", not any("warden_session" in item for item in set_cookies), set_cookies)

        response = http_get(client, "/headers", "app.home.lan", headers={"accept": "text/html", "cookie": f"warden_session={token}"})
        check("proxied request works on app host", response.status_code == 200, response.status_code)

        # ------------------------------------------------------------------
        print("browser SSO + websocket")
        cdp.navigate("https://app.home.lan:18443/", "app.home.lan")
        text = cdp.evaluate("document.body.textContent") or ""
        check("browser SSO sends cookie to route", "user=pat" in text, text)
        cdp.navigate("https://public.home.lan:18443/", "public.home.lan")
        text = cdp.evaluate("document.body.textContent") or ""
        check("browser public route has no identity", "user=None" in text, repr(text))

        result = cdp.evaluate(
            """
            new Promise((resolve, reject) => {
              const ws = new WebSocket('wss://wschat.home.lan:18443/echo', 'chat');
              const timer = setTimeout(() => reject(new Error('websocket timeout')), 10000);
              ws.onopen = () => ws.send('hello-live');
              ws.onmessage = (event) => {
                clearTimeout(timer);
                const protocol = ws.protocol;
                ws.close();
                resolve({data: event.data, protocol});
              };
              ws.onerror = () => { clearTimeout(timer); reject(new Error('websocket error')); };
            })
            """
        )
        check("public websocket echoes", result and result.get("data") == "hello-live", result)
        check("websocket subprotocol negotiated", result and result.get("protocol") == "chat", result)

        result = cdp.evaluate(
            """
            new Promise((resolve, reject) => {
              const ws = new WebSocket('wss://wsauth.home.lan:18443/echo');
              const timer = setTimeout(() => reject(new Error('websocket timeout')), 10000);
              ws.onopen = () => ws.send('authed');
              ws.onmessage = (event) => {
                clearTimeout(timer);
                ws.close();
                resolve(event.data);
              };
              ws.onerror = () => { clearTimeout(timer); reject(new Error('websocket error')); };
            })
            """
        )
        check("authenticated websocket works", result == "authed", result)

        cdp.call("Network.deleteCookies", name="warden_session", domain=".home.lan")
        result = cdp.evaluate(
            """
            new Promise((resolve) => {
              const ws = new WebSocket('wss://wsauth.home.lan:18443/echo');
              const timer = setTimeout(() => {
                ws.close();
                resolve({code: null, opened: true});
              }, 3000);
              ws.onopen = () => {};
              ws.onclose = (event) => {
                clearTimeout(timer);
                resolve({code: event.code, reason: event.reason});
              };
              ws.onerror = () => {};
            })
            """
        )
        check("anonymous authenticated websocket rejected", isinstance(result, dict) and result.get("code") == 4401, result)
        cdp.call(
            "Network.setCookie",
            name="warden_session",
            value=token,
            domain=".home.lan",
            path="/",
            secure=True,
            httpOnly=True,
            sameSite="Lax",
        )

        # ------------------------------------------------------------------
        print("logout + passkey login")
        old_token = token
        cdp.navigate(f"{BASE}/", ADMIN)
        cdp.evaluate("document.querySelector('#logout-button').click()")
        cdp.wait_js("location.pathname.includes('/_warden/login')", timeout=20)
        check("logout lands on login", cdp.evaluate("document.body.dataset.page") == "login")

        response = http_get(
            client,
            "/",
            ADMIN,
            headers={"accept": "text/html", "cookie": f"warden_session={old_token}"},
        )
        check("revoked cookie no longer works", response.status_code == 303, response.status_code)

        cdp.evaluate("document.querySelector('#passkey-login').click()")
        cdp.wait_js(
            "document.readyState === 'complete' && document.body.dataset.page === 'dashboard'",
            timeout=40,
        )
        check("passkey login lands on dashboard", cdp.evaluate("document.body.dataset.page") == "dashboard")
        cookies = cdp.call("Network.getCookies", urls=[f"{BASE}/"])["cookies"]
        new_session = next((item for item in cookies if item["name"] == "warden_session"), None)
        check("login issues a new session", new_session is not None and new_session["value"] != old_token)

        # ------------------------------------------------------------------
        print("access page session management")
        response = http_get(
            client,
            "/passkeys",
            ADMIN,
            headers={
                "accept": "text/html",
                "cookie": f"warden_session={new_session['value']}",
            },
        )
        check("access page lists sessions", response.status_code == 200, response.status_code)
        check("access page marks current session", "this device" in response.text, response.text[:300])

        # ------------------------------------------------------------------
        print("TLS renewal loop")
        deadline = time.time() + 35
        while not renew_marker.exists() and time.time() < deadline:
            time.sleep(0.5)
        check("renewal hook ran automatically", renew_marker.exists())
        check("renewal hook wrote expected output", renew_marker.read_text(encoding="utf-8").strip() == "renewed")
        response = http_get(
            client,
            "/",
            ADMIN,
            headers={
                "accept": "text/html",
                "cookie": f"warden_session={new_session['value']}",
            },
        )
        check(
            "dashboard reports renewal",
            "Last renewal" in response.text and "succeeded" in response.text,
            response.text[-1000:],
        )

        print(f"\n{len(checks)} live checks passed")
        print(f"server log: {log_path}")
        return 0
    except Exception:
        print("\nLIVE E2E FAILED", file=sys.stderr)
        if log_path.exists():
            print("\n--- warden log ---", file=sys.stderr)
            print(log_path.read_text(encoding="utf-8")[-12000:], file=sys.stderr)
        raise
    finally:
        if cdp is not None:
            cdp.close()
        if chrome is not None:
            chrome.terminate()
            try:
                chrome.wait(timeout=5)
            except subprocess.TimeoutExpired:
                chrome.kill()
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
        log_file.close()
        ws_upstream.shutdown()
        ws_thread.join(timeout=5)
        http_upstream.shutdown()
        http_upstream.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
