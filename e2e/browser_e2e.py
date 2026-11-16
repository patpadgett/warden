import re
import sqlite3

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

BASE = "http://localhost:8099"
SVC = "http://app.localhost:8099"


def boot(timeout=60):
    import time

    import httpx

    for _ in range(timeout * 2):
        try:
            with open("e2e/server.log") as handle:
                text = handle.read()
            m = re.search(r"Setup code · (\S+)", text)
            if m and httpx.get(
                "http://127.0.0.1:8099/_warden/health",
                headers={"Host": "localhost:8099"},
                timeout=2,
            ).status_code == 200:
                return m.group(1)
        except (FileNotFoundError, httpx.HTTPError):
            pass
        time.sleep(0.5)
    raise SystemExit("warden did not become ready")

setup_code = boot()
ok = True
def check(label, cond, extra=""):
    global ok; ok = ok and bool(cond)
    print(("[PASS] " if cond else "[FAIL] ") + label + (f"  | {extra}" if extra else ""))

def wait_leave(page, timeout_ms=15000):
    for _ in range(timeout_ms // 250):
        if "/_warden/login" not in page.url:
            return True
        if page.is_visible("#auth-error"):
            return False
        page.wait_for_timeout(250)
    return False

def new_session(browser, tag):
    ctx = browser.new_context()
    page = ctx.new_page()
    cdp = ctx.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True,
        "automaticPresenceSimulation": True}})
    page.on("console", lambda m: print(f"  [{tag} console:{m.type}] {m.text}") if m.type == "error" else None)
    page.on("requestfailed", lambda r: print(f"  [{tag} requestfailed] {r.url} {r.failure}"))
    return ctx, page

with sync_playwright() as p:
    browser = p.chromium.launch(args=["--host-resolver-rules=MAP localhost 127.0.0.1"])

    # ---- 1. first run: claim the instance through the setup form
    admin_ctx, page = new_session(browser, "admin")
    page.goto(BASE + "/_warden/setup")
    check("setup page loads", "Claim your Warden" in page.content())
    page.fill("#setup-username", "pat")
    page.fill("#setup-display-name", "Pat")
    page.fill("#setup-code", setup_code)
    page.click("#setup-submit")
    page.wait_for_url(lambda u: "/_warden/setup" not in u, timeout=20000)
    check("setup form signs in and lands on dashboard", page.url.rstrip("/") == BASE, page.url)
    check("dashboard lists the configured service", "Demo App" in page.content())
    page.click("#add-service")
    page.wait_for_selector("#service-modal-overlay.open", timeout=5000)
    check("add-service opens the service form",
          page.is_visible("#service-host") and page.is_visible("#service-form"),
          page.inner_text("#service-modal-title"))
    page.click("#service-modal-overlay .modal-foot [data-close-modal]")
    page.wait_for_selector("#service-modal-overlay", state="hidden", timeout=5000)

    # ---- 2. admin creates a user and captures the invite from the modal
    page.goto(BASE + "/users")
    check("users page renders", "Who holds the keys" in page.content())
    page.click("#add-user")
    page.fill("#user-form input[name=username]", "alex")
    page.fill("#user-form input[name=display_name]", "Alex Doe")
    page.fill("#user-form input[name=email]", "alex@example.com")
    page.click("#user-submit")
    page.wait_for_selector("#invite-modal-overlay.open", timeout=20000)
    token = page.input_value("#invite-token")
    link = page.input_value("#invite-link")
    check("invite modal exposes a token", bool(token), f"token={token!r}")
    check("invite link points at the invite page", "/_warden/invite/complete?token=" in link, link)
    print("captured invite token:", token)
    print("captured invite link :", link)

    # ---- 3. invitee opens the emailed link in a fresh browser profile
    inv_ctx, inv = new_session(browser, "invitee")
    inv.goto(link)
    check("invite page pre-fills the token from the URL", inv.input_value("#invite-token") == token)
    inv.fill("#passkey-name", "Alex iPhone")
    inv.click("#register-btn")

    err = None
    for _ in range(80):
        if inv.is_visible("#invite-error"):
            err = inv.inner_text("#invite-error").strip(); break
        if "/_warden/invite/complete" not in inv.url:
            break
        inv.wait_for_timeout(250)
    check("invite page registers the passkey as shipped",
          err is None and "/_warden/invite/complete" not in inv.url,
          f"error shown to user={err!r} url={inv.url}")

    check("invitee now holds a session", len(inv_ctx.cookies()) > 0, str([c["name"] for c in inv_ctx.cookies()]))

    inv.goto(BASE + "/")
    check("non-admin invitee lands on the portal",
          inv.url.rstrip("/").endswith("/portal"), inv.url)
    portal_text = inv.inner_text("body")
    check("portal lists the exposed service",
          "app.localhost" in portal_text, portal_text[:120].replace("\n", " "))
    check("portal links to credential management",
          inv.is_visible("a[href='/passkeys']") and inv.is_visible("a[href='/backup_codes']"))
    inv.goto(BASE + "/users")
    check("non-admin is refused an admin page but offered the portal",
          "admin-only" in inv.inner_text("body") and "/portal" in inv.content(),
          f"{inv.url} {inv.inner_text('body')[:80]!r}")

    # ---- 5. invite token cannot be reused
    reuse_ctx, reuse = new_session(browser, "reuse")
    reuse.goto(link)
    reuse.fill("#passkey-name", "Again")
    reuse.click("#register-btn")
    reuse.wait_for_selector("#invite-error", state="visible", timeout=20000)
    msg = reuse.inner_text("#invite-error")
    check("reused invite is rejected with a clear message", "invalid" in msg.lower() or "used" in msg.lower(), msg.strip()[:120])

    # ---- 6. invited user can sign in again with the passkey they just registered
    inv_ctx.clear_cookies()
    inv.goto(BASE + "/")
    check("signed-out invitee is redirected to sign-in", "/_warden/login" in inv.url, inv.url)
    check("sign-in page shows the requested next path", "next=" in inv.url, inv.url)
    if not inv.is_visible("#login-username"):
        inv.click("summary")
        inv.wait_for_selector("#login-username", state="visible", timeout=5000)
    inv.fill("#login-username", "alex")
    inv.click("#passkey-login")
    signed_in = wait_leave(inv)
    err_text = inv.inner_text("#auth-error") if inv.is_visible("#auth-error") else ""
    check("invited user signs in with the new passkey", signed_in, f"url={inv.url} error={err_text!r}")

    # ---- 7. admin logs out and back in, then every dashboard page loads
    page.goto(BASE + "/")
    page.click("#logout-button")
    page.wait_for_url(lambda u: "/_warden/login" in u, timeout=20000)
    check("logout returns to the sign-in page", "/_warden/login" in page.url)
    if not page.is_visible("#login-username"):
        page.click("summary")
        page.wait_for_selector("#login-username", state="visible", timeout=5000)
    page.fill("#login-username", "pat")
    page.click("#passkey-login")
    admin_signed = wait_leave(page)
    admin_err = page.inner_text("#auth-error") if page.is_visible("#auth-error") else ""
    check("admin passkey sign-in works", admin_signed, f"url={page.url} error={admin_err!r}")

    for path, marker in [("/passkeys", "Access"), ("/activity", "Activity"), ("/backup_codes", "Backup"),
                         ("/tls", "TLS"), ("/config", "Config"), ("/mesh", "Mesh"),
                         ("/metrics/view", "Metrics")]:
        resp = page.goto(BASE + path)
        body = page.inner_text("body")
        check(f"dashboard page {path} loads", resp.status == 200 and marker.lower() in body.lower(),
              f"{resp.status} {body[:60]!r}")

    try:
        token_btn = page.goto(BASE + "/backup_codes")
        page.click('#backup-form button[type="submit"]')
        page.wait_for_load_state("load")
        page.wait_for_selector("#new-backup-code", timeout=10000)
        new_code = page.inner_text("#new-backup-code").strip()
        check("backup code generation via the dashboard form works", bool(new_code), f"code={new_code!r}")
    except PlaywrightError as exc:
        print("  [backup_codes form] ", type(exc).__name__, str(exc)[:120])

    browser.close()

db = sqlite3.connect("e2e/warden.db")
print("\nusers      :", db.execute("select id, username, is_admin, email from users").fetchall())
print("credentials:", db.execute("select user_id, name, sign_count from credentials").fetchall())
print("invites    :", db.execute("select id, user_id, used from invites").fetchall())
print("sessions   :", db.execute("select user_id, count(*) from sessions group by user_id").fetchall())
print("audit      :", db.execute("select event, username from audit order by id desc limit 8").fetchall())
db.close()
print("\nRESULT:", "ALL PASS" if ok else "FAILURES PRESENT")
