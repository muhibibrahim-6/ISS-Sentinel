import io
import os
import re
import sys
import json
import time
import hashlib
import hmac
import base64
import asyncio
import secrets
import sqlite3
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, date, timedelta, timezone
from decimal import Decimal
from functools import wraps

import discord
from discord import app_commands
from discord.ext import commands
from typing import Literal
from flask import (Flask, Response, send_from_directory, render_template_string, request, redirect,
                   url_for, session, abort, g, flash)
from markupsafe import escape
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_OK = True
except ImportError:  # site still starts; only certificates are disabled
    Image = ImageDraw = ImageFont = None
    PIL_OK = False
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

try:
    sys.stdout.reconfigure(line_buffering=True)  # show logs on Render immediately
except Exception:
    pass

# ------------------------------------------------------------------
# Config (all secrets come from environment variables)
# ------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config.update(
    MAX_CONTENT_LENGTH=6 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)

DB_FILE = os.environ.get("DB_FILE", "iss.db")
OWNER_EMAIL = os.environ["OWNER_EMAIL"]
OWNER_USERNAME = os.environ.get("OWNER_USERNAME", "owner")
OWNER_PASSWORD = os.environ["OWNER_PASSWORD"]
BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN")

limiter = Limiter(get_remote_address, app=app,
                  default_limits=["200 per hour"], storage_uri="memory://")


# ------------------------------------------------------------------
# Database (sqlite, created automatically)
# ------------------------------------------------------------------
def connect():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=8000")
    return conn


def get_db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = connect()
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS admins(
        email TEXT PRIMARY KEY, username TEXT, password_hash TEXT);
    CREATE TABLE IF NOT EXISTS licenses(
        key TEXT PRIMARY KEY, name TEXT, org TEXT, expiry TEXT,
        max_devices INTEGER, plan TEXT, client_user TEXT,
        client_pwd_hash TEXT, created TEXT);
    CREATE TABLE IF NOT EXISTS tickets(
        id INTEGER PRIMARY KEY AUTOINCREMENT, license_key TEXT,
        subject TEXT, status TEXT DEFAULT 'open', created TEXT);
    CREATE TABLE IF NOT EXISTS devices(
        id INTEGER PRIMARY KEY AUTOINCREMENT, license_key TEXT, device_id TEXT,
        name TEXT, first_seen TEXT, last_seen TEXT, UNIQUE(license_key, device_id));
    CREATE TABLE IF NOT EXISTS threats(hash TEXT PRIMARY KEY, name TEXT, added TEXT);
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, name TEXT, password_hash TEXT, created TEXT);
    CREATE TABLE IF NOT EXISTS agents(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, email TEXT UNIQUE, password_hash TEXT, created TEXT);
    CREATE TABLE IF NOT EXISTS certificates(id INTEGER PRIMARY KEY AUTOINCREMENT, cert_id TEXT UNIQUE, name TEXT, email TEXT, org TEXT,
        country TEXT, phone TEXT, discord TEXT, role TEXT, valid_from TEXT, valid_to TEXT, status TEXT DEFAULT 'valid',
        pixel_hash TEXT, png BLOB, verified_count INTEGER DEFAULT 0, created TEXT);
    CREATE TABLE IF NOT EXISTS commands(id INTEGER PRIMARY KEY AUTOINCREMENT, license_key TEXT, type TEXT, created TEXT);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, license_key TEXT, device_id TEXT, command_id INTEGER, type TEXT, detail TEXT, created TEXT);
    CREATE TABLE IF NOT EXISTS id_keys(id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE, agent_id INTEGER, cert_pk INTEGER,
        snapshot TEXT, created_ts INTEGER, expires_ts INTEGER, used_ts INTEGER);
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY, plan TEXT, cycle TEXT, usd TEXT, bdt TEXT, provider TEXT,
        status TEXT DEFAULT 'pending', provider_ref TEXT, trx TEXT, name TEXT, email TEXT, org TEXT,
        client_user TEXT, pwd_hash TEXT, license_key TEXT, created TEXT, paid TEXT);
    CREATE UNIQUE INDEX IF NOT EXISTS orders_trx ON orders(trx);
    CREATE TABLE IF NOT EXISTS ticket_messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER,
        sender TEXT, body TEXT, created TEXT);
    """)
    try:
        conn.execute("ALTER TABLE licenses ADD COLUMN must_change INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE licenses ADD COLUMN created_by TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE devices ADD COLUMN is_admin INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    if not conn.execute("SELECT 1 FROM admins WHERE email=?", (OWNER_EMAIL,)).fetchone():
        conn.execute("INSERT INTO admins VALUES(?,?,?)",
                     (OWNER_EMAIL, OWNER_USERNAME, generate_password_hash(OWNER_PASSWORD)))
    conn.commit()
    conn.close()


def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M")


# ------------------------------------------------------------------
# Discord alerts (the bot posts to the chosen channel, no webhook needed)
# ------------------------------------------------------------------
def send_discord_alert(text):
    try:
        if not bot.is_ready():
            return
        conn = connect()
        row = conn.execute("SELECT value FROM settings WHERE key='alert_channel'").fetchone()
        conn.close()
        if not row:
            return

        async def _send():
            ch = bot.get_channel(int(row["value"]))
            if ch:
                await ch.send(text)
        asyncio.run_coroutine_threadsafe(_send(), bot.loop)
    except Exception as e:
        print(f"Alert error: {e}")


# ------------------------------------------------------------------
# CSRF + Auth helpers
# ------------------------------------------------------------------
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf"] = csrf_token


CSRF_EXEMPT = ("/scan", "/api/activate", "/api/agent/poll", "/api/agent/event", "/api/agent/threats", "/webhooks/paddle")


@app.before_request
def check_csrf():
    if request.method == "POST" and request.path not in CSRF_EXEMPT:
        sent = request.form.get("csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid CSRF token")


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return f(*a, **kw)
    return wrapper


def current_agent():
    aid = session.get("agent_id")
    if not aid:
        return None
    return get_db().execute("SELECT * FROM agents WHERE id=?", (aid,)).fetchone()


def staff_required(f):
    """Owner/admins get the full panel. Agents get a limited panel."""
    @wraps(f)
    def wrapper(*a, **kw):
        if session.get("is_admin"):
            g.staff = None
            return f(*a, **kw)
        ag = current_agent()
        if not ag:
            session.pop("agent_id", None)
            return redirect(url_for("login"))
        g.staff = ag
        return f(*a, **kw)
    return wrapper


def client_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        key = session.get("client_license")
        if not key:
            return redirect(url_for("client_login"))
        lic = get_db().execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
        if not lic:
            session.pop("client_license", None)
            return redirect(url_for("client_login"))
        g.lic = lic
        if lic["must_change"] and request.endpoint not in ("client_account", "client_logout"):
            flash("For your security, please change the default username and password first.")
            return redirect(url_for("client_account"))
        return f(*a, **kw)
    return wrapper


# ------------------------------------------------------------------
# Plans (devices: 0 = Unlimited)
# ------------------------------------------------------------------
PLANS = {
    "1-Day Plan": {"devices": 2, "monthly": "$0.01", "yearly": "-", "days": 1, "bdt": "1",
                   "for": "Try ISS for one day.",
                   "features": ["Full protection for one day", "Real-time cloud threat scanning and instant alerts", "Up to 2 devices"]},
    "Basic Plan": {"devices": 2, "monthly": "$4.99", "yearly": "$49.99", "for": "Individuals, freelancers and home offices.",
                   "features": ["Real-time cloud threat scanning and instant alerts", "Automated license management", "Secure server protection"]},
    "Standard Plan": {"devices": 5, "monthly": "$11.99", "yearly": "$119.99", "for": "Small teams and startups.",
                      "features": ["Everything in Basic", "Centralized organization monitoring", "Expiration tracking and renewal alerts"]},
    "Pro Plan": {"devices": 10, "monthly": "$21.99", "yearly": "$219.99", "for": "Growing businesses and offices.",
                 "features": ["Everything in Standard", "Priority cloud server response", "Dedicated threat definitions and instant blocking"]},
    "Enterprise Plan": {"devices": 0, "monthly": "$50.00", "yearly": "$510.00", "for": "Large organizations with many devices.",
                        "features": ["Everything in Pro", "Unlimited devices", "Custom requirements and dedicated support"]},
}


def plans_html():
    cards = ""
    for name, p in PLANS.items():
        dev = "Unlimited devices" if p["devices"] == 0 else "Up to %d devices" % p["devices"]
        li = "".join("<li>%s</li>" % x for x in p["features"])
        if p.get("days"):
            price = ('<div class="price">%s<small> / day</small></div>'
                     '<div style="color:var(--mute);font-size:.8rem">&#2547;%s Bangladeshi Taka</div>' % (p["monthly"], p["bdt"]))
        else:
            price = ('<div class="price">%s<small> / month</small></div>'
                     '<div style="color:var(--mute);font-size:.8rem">%s / year (save about 15%%)</div>' % (p["monthly"], p["yearly"]))
        cards += ('<div class="plan"><h3>%s</h3><div class="dev">%s</div>%s'
                  '<p style="color:var(--mute);font-size:.82rem;margin:10px 0 0">%s</p><ul>%s</ul>'
                  '<a class="btn" href="/checkout?plan=%s" style="display:block;text-align:center;margin-top:18px">Buy now</a></div>'
                  % (name, dev, price, p["for"], li, urllib.parse.quote(name)))
    return ('<section id="plans"><h2>Plans and pricing.</h2><p class="sub">Every plan includes the ISS cloud portal and agent. '
            'Press Buy now under a plan and pay by card or with USDT.</p><div class="plans">' + cards + '</div>'
            '<p class="sub" style="margin-top:26px">Before you buy, read <a href="/safe-buying" style="color:var(--cy)">how to buy safely</a> '
            'and always <a href="/verify" style="color:var(--cy)">verify the seller</a>.</p></section>')


def safe_html():
    return ('<ol class="guide">'
            '<li>Join our official <a href="https://discord.gg/mxRgm2R3ud" target="_blank" rel="noopener noreferrer">Discord server</a>, '
            'open the <b>ISS Cyber Defence Suite</b> category and click <b>Buy Now</b>.</li>'
            '<li>Before paying, ask the seller for their <b>Trade Certificate</b> image.</li>'
            '<li><b>Step 1, FSA:</b> open <a href="/verify">Verify Seller</a> and upload the certificate image. You must see a green tick.</li>'
            '<li><b>Step 2, SSA:</b> ask the seller to log in and create an <b>identification key</b> right now. Enter the key yourself on the same page. '
            'It works once and expires in 15 minutes.</li>'
            '<li>Check that the name and Discord account shown match the person you are chatting with. <mark>If anything differs, do not buy.</mark></li>'
            '<li>Buy only when both steps pass.</li></ol>'
            '<div class="warn"><mark>Do not buy any other way.</mark> Anyone who cannot pass both steps '
            'is <mark>not part of our team</mark>, and you may be scammed.</div>'
            '<h3>Our promise</h3><p class="m">ISS never creates, spreads or tolerates malware to drive sales. '
            'We only use the harmless, industry-standard EICAR test file to let you check that your protection works. '
            'Our business grows by protecting customers, never by endangering them.</p>')


@app.route("/safe-buying")
def safe_buying():
    return page("How to buy safely", '<div class="top"><h2>How to buy safely</h2><a class="btn btn2" href="/">&larr; Home</a></div><div class="card">' + safe_html() + '</div>')


# ------------------------------------------------------------------
# Legal pages: Terms of Service, Privacy Policy, Refund Policy
# ------------------------------------------------------------------
LEGAL_UPDATED = "24 October 2026"
DISCORD_LINK = '<a href="https://discord.gg/mxRgm2R3ud" target="_blank" rel="noopener noreferrer">our Discord server</a>'


def legal_page(title, intro, sections):
    body = ('<div class="top"><h2>' + title + '</h2><a class="btn btn2" href="/">&larr; Home</a></div>'
            '<div class="card" style="line-height:1.7"><p class="m">Last updated: ' + LEGAL_UPDATED + '</p><p>' + intro + '</p>')
    for head, html in sections:
        body += '<h3 style="margin:22px 0 6px">' + head + '</h3>' + html
    return page(title, body + '</div>')


@app.route("/terms")
def terms():
    return legal_page("Terms of Service",
        "These terms apply when you use the website, the Client Portal and the ISS Cloud Security Agent provided by "
        "International System Security (&ldquo;ISS&rdquo;, &ldquo;we&rdquo;). By buying a plan or using the service you agree to them.", [
        ("1. The service", "<p>ISS sells licenses for cyber security software: an agent that runs on your computer, and a cloud portal where you manage "
         "devices, see reports and contact support. Plans, prices and the number of devices are shown on the website.</p>"),
        ("2. Licenses and plans", "<ul><li>A paid plan gives you a personal, non-exclusive, non-transferable right to use the software on the number of devices in your plan until the expiry date shown in your portal.</li>"
         "<li>Plans are one-time purchases for a fixed period (1 day, 1 month or 1 year). Nothing renews automatically, and we never charge you again unless you buy again.</li>"
         "<li>The first device you add to a license becomes its admin device. Only an admin device can change the portal username and password, remove devices or give admin rights.</li></ul>"),
        ("3. Your account", "<p>Keep your license key, username and password private. You are responsible for what happens under your license. "
         "Tell us on " + DISCORD_LINK + " if you think someone else has access.</p>"),
        ("4. Acceptable use", "<p>You agree not to: use the software for anything illegal; share, resell or rent your license; "
         "try to break, overload or get around the service or its device limits; or copy or reverse engineer the software, except where the law allows it.</p>"),
        ("5. Prices and payment", "<ul><li>Prices are shown in US dollars.</li>"
         "<li><b>Card payments</b> are processed by Paddle, our payment partner and merchant of record. Paddle sells the license to you, adds any taxes that apply at checkout, and its own terms apply to the payment.</li>"
         "<li><b>USDT payments</b> are made on the BNB Smart Chain (BEP-20) network to the wallet address shown on your order. Blockchain payments cannot be reversed. Send the exact amount shown, on the correct network. We cannot recover funds sent on another network or to another address.</li>"
         "<li>Your license is created automatically once the payment is confirmed.</li></ul>"),
        ("6. Refunds", "<p>See the <a href=\"/refund\">Refund Policy</a>.</p>"),
        ("7. No guarantee against all threats", "<p>No security software can detect every threat. The software is provided &ldquo;as is&rdquo;, without a promise that it will find or stop all malware, "
         "or that it will always run without errors or interruptions. Keep backups of your important files.</p>"),
        ("8. Limit of liability", "<p>To the extent the law allows, ISS is not liable for indirect or consequential losses such as lost data, profit or business. "
         "Our total liability for any claim is limited to the amount you paid for the plan in the 12 months before the claim. Nothing here limits rights you have by law that cannot be limited.</p>"),
        ("9. Suspension and ending", "<p>You can stop using the service at any time. We may suspend or end a license if these terms are broken or if the license was obtained by fraud or a reversed payment.</p>"),
        ("10. Changes", "<p>We may update these terms. The date at the top shows the latest version. Using the service after a change means you accept it.</p>"),
        ("11. Governing law", "<p>These terms are governed by the laws of Bangladesh.</p>"),
        ("12. Contact", "<p>Questions? Reach us on " + DISCORD_LINK + " or open a support ticket in your Client Portal.</p>")])


@app.route("/privacy")
def privacy():
    return legal_page("Privacy Policy",
        "This policy explains what information International System Security (&ldquo;ISS&rdquo;) collects, why, and what we do with it.", [
        ("1. What we collect", "<ul><li><b>Purchase and account details:</b> your name, email address, organization, portal username, a license key, your plan and its expiry date. Your password is stored only as a one-way hash, never as plain text.</li>"
         "<li><b>Device details:</b> the name and an anonymous ID of each device you add, and when it was last seen.</li>"
         "<li><b>Security events from the agent:</b> when the agent blocks something, we receive the threat name, the file name (not the file itself) and the time. Test results are reported the same way.</li>"
         "<li><b>Support tickets:</b> what you write to us.</li>"
         "<li><b>Orders:</b> order number, plan, amount, and the payment reference (the Paddle transaction ID, or the USDT transaction hash).</li>"
         "<li><b>Technical data:</b> your IP address in server logs and for abuse protection, and a session cookie that keeps you logged in.</li>"
         "<li>If you sign in with Google, we receive your name and verified email address from Google.</li></ul>"),
        ("2. Payment information", "<p>Card details are entered on Paddle&rsquo;s secure checkout and handled by Paddle. We never see or store your card number. "
         "USDT payments are public blockchain transactions.</p>"),
        ("3. How we use it", "<p>To create and run your license, show your devices and reports, give support, process orders, keep the service secure, prevent fraud and misuse, and meet legal and accounting duties. We do not sell your information and we do not use it for advertising.</p>"),
        ("4. Who we share it with", "<ul><li><b>Paddle</b>, to take card payments.</li><li><b>Our hosting provider</b>, which runs the servers.</li>"
         "<li><b>Discord</b>, where we receive internal notices about new orders, licenses and support activity.</li><li><b>Google</b>, only if you choose Google sign-in.</li>"
         "<li>Authorities, if the law requires it.</li></ul>"),
        ("5. Cookies", "<p>We use only the cookies needed to keep you signed in and to protect forms. We do not use advertising or tracking cookies.</p>"),
        ("6. How long we keep it", "<p>For as long as your license or account exists and as long as needed for support, accounting and legal reasons. Security events are kept for your reports.</p>"),
        ("7. Your choices", "<p>You can ask us to show, correct or delete your information, or close your account, on " + DISCORD_LINK + " or through a support ticket. Deleting your information ends your license. We may keep order records that the law requires us to keep.</p>"),
        ("8. Security", "<p>We use HTTPS, hashed passwords and access controls. No system is perfectly secure, so please use a strong password and keep your license key private.</p>"),
        ("9. Children", "<p>The service is not meant for children.</p>"),
        ("10. Changes and contact", "<p>We may update this policy and will change the date above when we do. Questions? Reach us on " + DISCORD_LINK + ".</p>")])


@app.route("/refund")
def refund():
    return legal_page("Refund Policy",
        "ISS licenses are digital and delivered right after payment. This is how refunds work.", [
        ("1. Monthly and yearly plans", "<p>If the software does not work for you, ask for a refund within <b>14 days</b> of the purchase. Send the request with your order number on " + DISCORD_LINK + " or in a support ticket. "
         "We will first try to fix the problem. If we cannot, you get your money back.</p>"),
        ("2. 1-Day Plan", "<p>The 1-Day Plan is a short trial that starts working immediately and is <b>not refundable</b>.</p>"),
        ("3. When we may refuse", "<p>Refunds are not given after 14 days, or for a license that was shared, resold or misused, or that was stopped for breaking the Terms of Service.</p>"),
        ("4. Duplicate or mistaken payments", "<p>If you were charged twice or paid the wrong amount for an order, tell us with the order number and we will correct it or refund the difference.</p>"),
        ("5. How the money comes back", "<ul><li><b>Card payments:</b> refunded to the original card through Paddle. It can take several business days to appear on your statement.</li>"
         "<li><b>USDT payments:</b> refunded in USDT to the wallet address you tell us, on the BNB Smart Chain network. Network fees are deducted from the refund.</li></ul>"),
        ("6. After a refund", "<p>The license is deactivated when a refund is approved.</p>"),
        ("7. Contact", "<p>To ask for a refund, reach us on " + DISCORD_LINK + " or open a support ticket in your Client Portal.</p>")])


def plan_devices(plan):
    return PLANS.get(plan, {}).get("devices", 2)


def device_limit(lic):
    try:
        return int(lic["max_devices"] or 0)
    except (TypeError, ValueError):
        return 0


def limit_text(n):
    return "Unlimited" if n == 0 else str(n)


# ------------------------------------------------------------------
# Layout
# ------------------------------------------------------------------
LAYOUT = """
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }}</title>
<style>
 body{font-family:'Segoe UI',sans-serif;background:#060913;color:#fff;margin:0;padding:24px}
 .card{background:#111827;border:1px solid #1e293b;border-radius:8px;padding:20px;margin:16px 0}
 input,select,textarea{width:100%;padding:9px;margin:5px 0;background:#060913;border:1px solid #334155;color:#fff;border-radius:6px;box-sizing:border-box}
 button,.btn{background:#0ea5e9;color:#fff;padding:10px 18px;border:none;border-radius:6px;font-weight:bold;cursor:pointer;text-decoration:none;display:inline-block}
 .btn2{background:#1e293b;color:#38bdf8}
 a{color:#38bdf8} table{width:100%;border-collapse:collapse}
 td,th{padding:8px;border-bottom:1px solid #1e293b;text-align:left;font-size:14px}
 .ok{color:#34d399}.err{color:#fca5a5}.wrap{max-width:900px;margin:auto}
 .me{background:#0c4a6e;padding:8px;border-radius:6px;margin:6px 0}
 .them{background:#1e293b;padding:8px;border-radius:6px;margin:6px 0}
</style></head>
<body><div class="wrap">{{ body|safe }}</div></body></html>
"""


PORTAL_LAYOUT = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} | ISS</title>
{% if manifest %}<link rel="manifest" href="{{ manifest }}"><meta name="theme-color" content="#07090c"><link rel="icon" type="image/png" href="/pwa-icon-192.png">{% endif %}
<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#07090c;--panel:#0c1117;--line:#1d2a35;--txt:#dce6ee;--mute:#7f93a3;--cy:#00d9ff;--am:#ffb224;--ok:#5dffb4}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:400 15px/1.6 'JetBrains Mono',monospace;padding:22px;background-image:linear-gradient(rgba(0,217,255,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(0,217,255,.04) 1px,transparent 1px);background-size:56px 56px}
.wrap{max-width:940px;margin:auto}
h1,h2,h3{font-family:'Chakra Petch',sans-serif;margin:0 0 8px}
a{color:var(--cy)}
.card{position:relative;background:var(--panel);border:1px solid var(--line);padding:22px;margin:16px 0}
.card:before{content:"";position:absolute;top:-1px;left:-1px;width:16px;height:16px;border:2px solid var(--cy);border-right:0;border-bottom:0}
input,select,textarea{width:100%;padding:11px;margin:5px 0;background:#05080b;border:1px solid var(--line);color:var(--txt);font:inherit}
button,.btn{background:var(--cy);color:#001014;padding:11px 20px;border:0;font:700 .9rem 'Chakra Petch',sans-serif;cursor:pointer;text-decoration:none;display:inline-block}
.btn2{background:transparent;color:var(--txt);border:1px solid var(--mute)}
table{width:100%;border-collapse:collapse}td,th{padding:9px 6px;border-bottom:1px solid var(--line);text-align:left;font-size:13px}
th{color:var(--mute);font-weight:400}
.ok{color:var(--ok)}.err{color:#ff8a8a}.m{color:var(--mute);font-size:.85rem}
.me{background:#0a2a35;padding:8px;margin:6px 0}.them{background:#141c24;padding:8px;margin:6px 0}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}
.status{display:inline-flex;align-items:center;gap:10px;padding:6px 14px;border:1px solid var(--ok);color:var(--ok);font-weight:700}
.dot{width:10px;height:10px;background:var(--ok);border-radius:50%;box-shadow:0 0 12px var(--ok);animation:p 1.6s infinite}
@keyframes p{50%{opacity:.35}}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.big{font:700 2.6rem 'Chakra Petch',sans-serif}.big small{font-size:1rem;color:var(--mute)}
.meter{height:8px;background:var(--line);margin:10px 0}.meter i{display:block;height:100%;background:var(--cy)}
tr.cur td{color:var(--am)}
code{color:var(--am)}
.warn{border:1px solid var(--am);background:rgba(255,178,36,.08);padding:18px 22px;margin:22px 0}mark{background:rgba(255,178,36,.25);color:#fff;padding:0 4px}ol.guide li{margin:12px 0}
button.status{background:transparent;cursor:pointer;font:700 1rem 'JetBrains Mono',monospace;color:var(--ok)}.res{text-align:center;padding:34px}.res .mark{font-size:5rem;line-height:1}.res.okc .mark{color:var(--ok)}.res.bad .mark{color:#ff5d5d}.pill{display:inline-block;padding:2px 10px;border:1px solid var(--line);font-size:.75rem}.pill.g{color:var(--ok);border-color:var(--ok)}.pill.r{color:#ff8a8a;border-color:#ff8a8a}
.dshell{display:flex;gap:24px;align-items:flex-start}.dside{flex:none;width:210px;background:var(--panel);border:1px solid var(--line);display:flex;flex-direction:column;padding:14px 0;position:sticky;top:16px}.dside a,.dside button.dl{padding:11px 18px;color:var(--txt);text-decoration:none;font-size:.88rem;border:0;background:none;text-align:left;width:100%;cursor:pointer;font-family:inherit;display:block}.dside a.cur{color:var(--cy);background:rgba(0,217,255,.08);border-left:3px solid var(--cy);padding-left:15px}.dside a:hover{color:var(--cy)}.dside form{margin-top:4px;border-top:1px solid var(--line);padding-top:8px}.dside button.dl{color:#ff8a8a}.dside button.dl:hover{color:#fff}.dmain{flex:1;min-width:0}.dtop{display:none}.dback{display:none}.menu-btn{width:40px;height:40px;background:transparent;border:1px solid var(--line);display:flex;flex-direction:column;justify-content:center;gap:5px;padding:0 10px;cursor:pointer;flex:none}.menu-btn span{display:block;height:2px;background:var(--txt)}@media(max-width:760px){.dshell{display:block}.dside{display:none;width:84vw;max-width:290px;position:fixed;top:0;left:0;bottom:0;z-index:10;overflow-y:auto;border-right:1px solid var(--line)}.dside.open{display:flex}.dback{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:9}.dback.open{display:block}.dtop{display:flex;align-items:center;gap:12px;margin-bottom:16px}.dtitle{font:700 1.05rem 'Chakra Petch',sans-serif}}
@media(max-width:700px){.g2{grid-template-columns:1fr}}
.scan6{display:grid;gap:8px;margin:16px 0}.s6{display:flex;align-items:center;gap:12px;padding:10px 12px;border:1px solid var(--line);background:#05080b;font-size:.88rem;color:var(--mute)}.s6 i{width:16px;height:16px;border:2px solid var(--line);border-radius:50%;flex:none}.s6.go{color:var(--txt);border-color:var(--cy)}.s6.go i{border-color:var(--cy);border-top-color:transparent;animation:spin6 .7s linear infinite}.s6.done{color:var(--ok)}.s6.done i{border-color:var(--ok);background:var(--ok)}@keyframes spin6{to{transform:rotate(360deg)}}.bars{display:flex;align-items:flex-end;gap:3px;height:56px;margin-top:8px}.bar{flex:1;background:var(--cy);opacity:.75;height:var(--h);min-height:3px}
</style></head><body><div class="wrap">{% for m in get_flashed_messages() %}<div class="card ok" style="padding:12px 18px">{{ m }}</div>{% endfor %}{{ body|safe }}</div></body></html>"""


def dash_shell(title, nav, active, logout_action, body_html, site_home="/"):
    """A real sidebar dashboard shell: a hamburger on mobile, an always-visible
    sidebar on wider screens, shared by the admin portal, the client portal and
    the agent dashboard, so every page shows ONE section at a time instead of
    everything stacked on a single long page."""
    items = "".join(
        f'<a class="{"cur" if n["key"] == active else ""}" href="{n["href"]}">{n["label"]}</a>'
        for n in nav)
    return f'''
    <div class="dshell">
      <div class="dback" id="dBack"></div>
      <nav class="dside" id="dSide">
        <div style="padding:0 22px 14px;font:700 1rem 'Chakra Petch',sans-serif;color:var(--cy)">ISS {escape(title)}</div>
        {items}
        <a href="{escape(site_home)}">&larr; Back to site</a>
        <form method="POST" action="{escape(logout_action)}">
          <input type="hidden" name="csrf" value="{csrf_token()}"><button class="dl">Logout</button></form>
      </nav>
      <div style="flex:1;min-width:0">
        <div class="dtop"><button class="menu-btn" id="dMenuBtn" aria-label="Open menu"><span></span><span></span><span></span></button>
          <span class="dtitle">{escape(title)}</span></div>
        <main class="dmain">{body_html}</main>
      </div>
    </div>
    <script>(function(){{var b=document.getElementById('dMenuBtn'),s=document.getElementById('dSide'),k=document.getElementById('dBack');
    if(!b)return;function t(o){{s.classList.toggle('open',o);k.classList.toggle('open',o)}}
    b.addEventListener('click',function(){{t(!s.classList.contains('open'))}});k.addEventListener('click',function(){{t(false)}})}})();</script>
    '''


def page(title, body_tpl, shell=None, **ctx):
    body = render_template_string(body_tpl, **ctx)
    if shell:
        body = dash_shell(title, shell["nav"], shell["active"], shell.get("logout", "/logout"), body,
                          shell.get("home", "/"))
    layout = PORTAL_LAYOUT
    return render_template_string(layout, title=title, body=body, manifest=(shell or {}).get("manifest"))


# ------------------------------------------------------------------
# Home
# ------------------------------------------------------------------
BUILD = "v10b-dashboards-2026-10-18"

LANDING_HTML = r'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>International System Security (ISS) | Cyber Security Services</title>
<meta name="description" content="International System Security: cyber security services and a client platform for licenses, access and support.">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root{box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px);--bg:#07090c;--panel:#0c1117;--line:#1d2a35;--txt:#dce6ee;--mute:#7f93a3;--cy:#00d9ff;--am:#ffb224}
*{box-sizing:border-box;margin:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--txt);font:400 16px/1.65 'JetBrains Mono',ui-monospace,monospace;overflow-x:hidden}
body:before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(255,255,255,.025) 0 1px,transparent 1px 3px),linear-gradient(rgba(0,217,255,.05) 1px,transparent 1px) 0 0/64px 64px,linear-gradient(90deg,rgba(0,217,255,.05) 1px,transparent 1px) 0 0/64px 64px,radial-gradient(80% 60% at 70% 0%,rgba(0,217,255,.09),transparent 70%)}
a{color:inherit;text-decoration:none}
:focus-visible{outline:2px solid var(--am);outline-offset:3px}
.wrap{max-width:1280px;margin:auto;padding:0 26px}
h1,h2,h3{font-family:'Chakra Petch',sans-serif;font-weight:700;line-height:1.05;letter-spacing:.01em}
nav{position:sticky;top:env(safe-area-inset-top,0px);z-index:5;background:rgba(7,9,12,.88);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
nav .wrap{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px 14px;padding:12px 0}.brand{flex:none}.quicknav{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-left:auto;order:2}.qbtn{padding:8px 14px;border:1px solid var(--line);color:var(--txt);font:600 .78rem 'Chakra Petch',sans-serif;background:transparent;white-space:nowrap;cursor:pointer;text-decoration:none;display:inline-block}.qbtn:hover{border-color:var(--cy);color:var(--cy)}.qbtn.solid{background:var(--cy);color:#001014;border-color:var(--cy)}.qbtn.solid:hover{background:#fff;color:#001014}.qform{margin:0;display:inline-block}.menu-btn{order:3;flex:none}@media(max-width:560px){.quicknav{order:3;flex-basis:100%;justify-content:flex-start}.menu-btn{order:2}}
.brand{display:flex;align-items:center;gap:12px;font:700 1.15rem 'Chakra Petch'}
.brand svg{width:30px;height:30px}
.links{display:flex;gap:26px;align-items:center;font-size:.85rem;color:var(--mute)}
.links a:hover{color:var(--cy)}
.btn{display:inline-block;padding:13px 26px;font:700 .95rem 'Chakra Petch';letter-spacing:.04em;background:var(--cy);color:#001014;clip-path:polygon(0 0,calc(100% - 12px) 0,100% 12px,100% 100%,12px 100%,0 calc(100% - 12px));transition:background .15s,transform .15s}
.btn:hover{background:#fff;transform:translateY(-2px)}
.btn.line{background:transparent;color:var(--txt);border:1px solid var(--mute);clip-path:none}
.btn.line:hover{border-color:var(--cy);color:var(--cy);background:transparent}
.hero{display:grid;grid-template-columns:1.05fr .95fr;gap:56px;align-items:center;padding:96px 0 110px}
.hero h1{font-size:clamp(2.9rem,7vw,5.6rem)}
.hero h1 em{display:block;font-style:normal;color:var(--cy);text-shadow:0 0 28px rgba(0,217,255,.45)}
.hero p{color:var(--mute);max-width:36rem;margin:26px 0 38px;font-size:1.08rem}
.cta{display:flex;gap:14px;flex-wrap:wrap}
.hud{position:relative;background:var(--panel);border:1px solid var(--line);padding:0}
.hud:before,.hud:after,.card:before,.card:after{content:"";position:absolute;width:18px;height:18px;border:2px solid var(--cy);pointer-events:none}
.hud:before,.card:before{top:-1px;left:-1px;border-right:0;border-bottom:0}
.hud:after,.card:after{bottom:-1px;right:-1px;border-left:0;border-top:0}
.bar{display:flex;justify-content:space-between;padding:10px 16px;border-bottom:1px solid var(--line);font-size:.75rem;color:var(--mute)}
.bar b{color:var(--am);font-weight:500}
#log{padding:20px 18px;min-height:216px;font-size:.84rem;color:#a8f3ff;white-space:pre-wrap}
#log .ok{color:#5dffb4}
.cur{display:inline-block;width:9px;height:1em;background:var(--cy);vertical-align:-2px;animation:bl 1s steps(1) infinite}
@keyframes bl{50%{opacity:0}}
.read{display:grid;grid-template-columns:repeat(3,1fr);border-top:1px solid var(--line)}
.read div{padding:14px 16px;border-right:1px solid var(--line);font-size:.72rem;color:var(--mute)}
.read div:last-child{border:0}.read strong{display:block;color:var(--txt);font-size:.95rem;margin-top:2px}
section{padding:104px 0}
h2{font-size:clamp(2.1rem,4.4vw,3.4rem);max-width:36rem}
.sub{color:var(--mute);max-width:38rem;margin:16px 0 48px;font-size:1.02rem}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.card{position:relative;background:var(--panel);border:1px solid var(--line);padding:26px;transition:border-color .2s}
.card:hover{border-color:rgba(0,217,255,.5)}
.card code{display:inline-block;color:var(--am);font-size:.8rem;margin-bottom:12px}
.card h3{font-size:1.35rem;margin-bottom:8px}.card p{color:var(--mute);font-size:.88rem}
.seq{display:grid;grid-template-columns:repeat(3,1fr);gap:0;border:1px solid var(--line);background:var(--panel)}
.seq div{padding:30px;border-right:1px solid var(--line)}.seq div:last-child{border:0}
.seq b{color:var(--cy);font:700 .8rem 'JetBrains Mono'}
.seq h3{font-size:1.3rem;margin:8px 0}.seq p{color:var(--mute);font-size:.88rem}
.band{position:relative;border:1px solid var(--cy);padding:56px 30px;text-align:center;background:linear-gradient(180deg,rgba(0,217,255,.1),transparent)}
.band h2{margin:0 auto 12px;max-width:none}.band p{color:var(--mute);margin-bottom:28px;font-size:.92rem}
.soc{border:1px solid var(--line);max-width:680px;background:var(--panel)}
.s{display:flex;align-items:center;gap:16px;padding:18px 22px;border-bottom:1px solid var(--line);transition:background .15s,padding .15s}
.s:last-child{border:0}.s:hover{background:rgba(0,217,255,.07);padding-left:30px}
.s span{color:var(--mute);width:96px;font-size:.82rem}.s strong{font-weight:500}
.s em{margin-left:auto;font-style:normal;color:var(--cy);font-size:.8rem}
footer{border-top:1px solid var(--line);padding:28px 0;color:var(--mute);font-size:.78rem}
footer .wrap{display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px}
.term{border:1px solid var(--line);background:#05080b;max-width:820px;margin:0 auto;box-shadow:0 0 60px rgba(0,217,255,.08)}.tbar{display:flex;gap:7px;align-items:center;padding:10px 14px;border-bottom:1px solid var(--line);font-size:.72rem;color:var(--mute)}.tbar i{width:9px;height:9px;background:var(--line);display:block}.tbar i:first-child{background:var(--am)}.tbar span{margin-left:10px}#tout{padding:20px 18px;min-height:310px;font:400 .82rem/1.75 'JetBrains Mono',monospace;color:#a8f3ff;white-space:pre-wrap;overflow-x:auto}#tout .p{color:var(--am)}#tout .g{color:#5dffb4}#tout .m{color:var(--mute)}.brand img{height:38px;width:auto}.brand span{font-size:1rem}.lock{display:flex;align-items:center;gap:16px;margin-bottom:34px}.lock img{height:92px;width:auto;filter:drop-shadow(0 0 20px rgba(124,92,255,.55))}.lock b{display:block;font:700 1.05rem 'Chakra Petch';letter-spacing:.03em}.lock span{display:block;color:var(--am);font-size:.76rem;margin-top:2px}.seq4{grid-template-columns:repeat(4,1fr)}.seq4 div{padding:24px}
@media(max-width:860px){.brand span{display:none}.seq4{grid-template-columns:1fr}.hero{grid-template-columns:1fr;padding-top:40px}.grid,.seq{grid-template-columns:1fr}.seq div{border-right:0;border-bottom:1px solid var(--line)}.links a:not(.btn){display:none}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
.plans{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px}.plan{background:var(--panel);border:1px solid var(--line);padding:26px 22px}.plan h3{font-size:1.3rem}.plan .price{font:700 2rem 'Chakra Petch',sans-serif;color:var(--cy);margin-top:10px}.plan .price small{font-size:.8rem;color:var(--mute)}.plan ul{list-style:none;padding:0;margin:16px 0 0;font-size:.82rem;color:var(--mute)}.plan li{padding:7px 0;border-top:1px solid var(--line)}.plan .dev{color:var(--am);font-size:.85rem}.warn{border:1px solid var(--am);background:rgba(255,178,36,.08);padding:18px 22px;margin:22px 0;font-size:.92rem}.warn mark,.guide mark{background:rgba(255,178,36,.25);color:#fff;padding:0 4px}.guide{max-width:760px;font-size:.92rem;color:var(--mute)}.guide li{margin:10px 0}.links form{display:inline;margin:0}@media(max-width:1000px){.plans{grid-template-columns:1fr 1fr}}@media(max-width:600px){.plans{grid-template-columns:1fr}}
.menu-btn{width:44px;height:44px;background:transparent;border:1px solid var(--line);display:flex;flex-direction:column;justify-content:center;gap:6px;padding:0 11px;cursor:pointer}.menu-btn span{display:block;height:2px;background:var(--txt);transition:transform .2s,opacity .2s}.menu-btn.open span:nth-child(1){transform:translateY(8px) rotate(45deg)}.menu-btn.open span:nth-child(2){opacity:0}.menu-btn.open span:nth-child(3){transform:translateY(-8px) rotate(-45deg)}.drawer{position:absolute;right:0;top:100%;width:min(320px,100vw);background:rgba(7,9,12,.98);border:1px solid var(--line);border-top:0;display:none;flex-direction:column;padding:10px 0;max-height:calc(100vh - 66px);overflow:auto}.drawer.open{display:flex}.drawer a,.drawer button.dl{padding:14px 22px;color:var(--txt);font-size:.95rem;border:0;background:none;text-align:left;font-family:inherit;cursor:pointer;width:100%;display:block}.drawer a:hover,.drawer button.dl:hover{background:rgba(0,217,255,.07);color:var(--cy)}.drawer form{margin:0}.dsep{height:1px;background:var(--line);margin:8px 0}.scan6{display:grid;gap:8px;margin:16px 0}.s6{display:flex;align-items:center;gap:12px;padding:10px 12px;border:1px solid var(--line);background:#05080b;font-size:.88rem;color:var(--mute)}.s6 i{width:16px;height:16px;border:2px solid var(--line);border-radius:50%;flex:none}.s6.go{color:var(--txt);border-color:var(--cy)}.s6.go i{border-color:var(--cy);border-top-color:transparent;animation:spin6 .7s linear infinite}.s6.done{color:var(--ok)}.s6.done i{border-color:var(--ok);background:var(--ok)}@keyframes spin6{to{transform:rotate(360deg)}}.bars{display:flex;align-items:flex-end;gap:3px;height:56px;margin-top:8px}.bar{flex:1;background:var(--cy);opacity:.75;height:var(--h);min-height:3px}
</style></head><body>
<nav><div class="wrap"><a class="brand" href="#"><img src="/shield.webp" alt="ISS logo"><span>International System Security</span></a>
<div class="quicknav"><a class="qbtn" href="/client-login">Client Portal</a>__AUTHNAV__</div>
<button class="menu-btn" id="menuBtn" aria-label="Open menu" aria-expanded="false" aria-controls="drawer"><span></span><span></span><span></span></button></div>
<div class="drawer" id="drawer"><a href="/">Home</a><a href="#services">Services</a><a href="#plans">Plans &amp; pricing</a><a href="/verify">Verify Seller</a><a href="/safe-buying">How to buy safely</a><a href="#connect">Contact</a><a href="/terms">Terms of Service</a><a href="/privacy">Privacy Policy</a><a href="/refund">Refund Policy</a></div></nav>
<script>(function(){var b=document.getElementById('menuBtn'),d=document.getElementById('drawer');function t(o){d.classList.toggle('open',o);b.classList.toggle('open',o);b.setAttribute('aria-expanded',o)}b.addEventListener('click',function(){t(!d.classList.contains('open'))});d.addEventListener('click',function(e){if(e.target.closest('a'))t(false)});document.addEventListener('keydown',function(e){if(e.key==='Escape')t(false)});document.addEventListener('click',function(e){if(!e.target.closest('nav'))t(false)})})();</script>

<main class="wrap">
<header class="hero">
<div>
<div class="lock"><img src="/logo.webp" alt="ISS shield logo"><div><b>International System Security</b><span>New window of world wide web</span></div></div>
<h1>Security operations,<em>under control.</em></h1>
<p>International System Security (ISS) delivers cyber security services and a client platform that keeps licenses, access and support in one place.</p>
<div class="cta"><a class="btn" href="/client-login">Open Client Portal</a><a class="btn line" href="https://discord.gg/mxRgm2R3ud" target="_blank" rel="noopener noreferrer">Join Discord</a></div>
</div>
<div class="hud" aria-label="System console">
<div class="bar"><span>iss-core / console</span><b>live</b></div>
<div id="log"></div>
<div class="read"><div>plan tiers<strong>3</strong></div><div>passwords<strong>hashed</strong></div><div>sign-in<strong>rate limited</strong></div></div>
</div>
</header>

<section id="services"><h2>Cyber security services.</h2><p class="sub">Protection for organizations that cannot afford downtime or data loss.</p>
<div class="grid">
<div class="card"><code>scan.vuln</code><h3>Vulnerability assessment</h3><p>Find weak points in systems and applications before attackers do.</p></div>
<div class="card"><code>test.pentest</code><h3>Penetration testing</h3><p>Controlled attack simulations that show what is really exposed.</p></div>
<div class="card"><code>net.guard</code><h3>Network security</h3><p>Secure configuration and monitoring of your network perimeter.</p></div>
<div class="card"><code>endpoint.av</code><h3>Endpoint protection</h3><p>Cloud-managed antivirus agents on the devices your team uses.</p></div>
<div class="card"><code>ir.respond</code><h3>Incident response</h3><p>Fast containment and recovery when something goes wrong.</p></div>
<div class="card"><code>advise.sec</code><h3>Security consulting</h3><p>Clear, practical advice on policy, risk and next steps.</p></div>
</div></section>

<section id="platform"><h2>The ISS client platform.</h2><p class="sub">Every client gets one place to manage protection and reach our team.</p>
<div class="seq seq4">
<div><b>/newlicense</b><h3>License registry</h3><p>Keys with plan and expiry date.</p></div>
<div><b>/client-login</b><h3>Client portal</h3><p>A private dashboard per client.</p></div>
<div><b>/tickets</b><h3>Support desk</h3><p>Ticket threads with our team.</p></div>
<div><b>/report</b><h3>Discord control</h3><p>Reports and alerts in your server.</p></div>
</div></section>

<section id="deploy"><h2>Deployment sequence</h2><p class="sub">From request to protected in three steps.</p>
<div class="seq">
<div><b>step 1</b><h3>Request a key</h3><p>Contact the team on Discord and receive your license, username and password.</p></div>
<div><b>step 2</b><h3>Authenticate</h3><p>Open the Client Portal and sign in with your license key.</p></div>
<div><b>step 3</b><h3>Operate</h3><p>Check your status and open a ticket whenever you need support.</p></div>
</div></section>

__PLANS__

<section><div class="band card"><h2>Need a license?</h2><p>Tell us about your organization on Discord and we will set you up.</p><a class="btn" href="https://discord.gg/mxRgm2R3ud" target="_blank" rel="noopener noreferrer">Join Discord</a></div></section>

<section id="connect"><h2>Contact Muhib.</h2><p class="sub">Pick a channel. Messages and follows are welcome.</p>
<div class="soc">
<a class="s" href="https://instagram.com/mrshadow6000" target="_blank" rel="noopener noreferrer"><span>instagram</span><strong>mrshadow6000</strong><em>follow</em></a>
<a class="s" href="https://discord.gg/mxRgm2R3ud" target="_blank" rel="noopener noreferrer"><span>discord</span><strong>ISS community</strong><em>join</em></a>
<a class="s" href="https://www.linkedin.com/search/results/people/?keywords=Muhib%20Ibrahim" target="_blank" rel="noopener noreferrer"><span>linkedin</span><strong>Muhib Ibrahim</strong><em>connect</em></a>
<a class="s" href="https://github.com/muhibibrahim-6" target="_blank" rel="noopener noreferrer"><span>github</span><strong>muhibibrahim-6</strong><em>follow</em></a>
<a class="s" href="https://medium.com/@Muhibibrahim" target="_blank" rel="noopener noreferrer"><span>medium</span><strong>@Muhibibrahim</strong><em>read</em></a>
</div></section>
<section id="terminal"><h2>Watch it work.</h2><p class="sub">A simulated session of the ISS toolkit, running on a loop.</p>
<div class="term"><div class="tbar"><i></i><i></i><i></i><span>iss@secure: ~ (simulated demo)</span></div><pre id="tout" aria-label="Simulated terminal session"></pre></div></section>
</main>
<footer><div class="wrap"><span>© 2026 International System Security · build __BUILD__</span><span><a href="/client-login">client login</a> / <a href="/admin">admin</a></span></div></footer>
<script>
(function(){
var L=['> boot iss-core','> load license.registry ..... [ok]','> load client.portal ....... [ok]','> load support.desk ........ [ok]','> link discord.control ..... [ok]','> status: ready'];
var el=document.getElementById('log'),cur='<span class="cur"></span>';
function paint(t){el.innerHTML=t.replace(/\[ok\]/g,'<span class="ok">[ok]</span>')+cur}
if(window.matchMedia('(prefers-reduced-motion:reduce)').matches){paint(L.join('\n'));return}
var i=0,j=0,out='';
(function tick(){if(i>=L.length){paint(out);return}
var line=L[i];out+=line.charAt(j++);paint(out);
if(j>=line.length){out+='\n';i++;j=0;setTimeout(tick,260)}else setTimeout(tick,22)})();
})();
</script>
<script>
(function(){
var el=document.getElementById('tout');if(!el)return;
var P='<span class="p">iss@secure:~$</span> ';
var S=[['c','iss scan --target client-network'],['o','<span class="m">resolving hosts</span> ........ <span class="g">done</span>'],['o','<span class="m">checking open ports</span> ... <span class="g">done</span>'],['b','scanning files'],['o','<span class="m">verifying license</span> ..... <span class="g">valid</span>'],['o','<span class="g">scan complete: no threats found in this demo</span>'],['c','iss status'],['o','protection ........ <span class="g">active</span>'],['o','plan ............. pro'],['c','iss support --new "need help"'],['o','<span class="g">ticket created. our team will reply in the thread.</span>']];
var html='';
function esc(t){return t.replace(/&/g,'&amp;').replace(/</g,'&lt;')}
function draw(x){el.innerHTML=html+(x||'')+'<span class="cur"></span>'}
function sleep(n){return new Promise(function(r){setTimeout(r,n)})}
function bar(l,p){return '<span class="m">'+l+'</span> ['+'█'.repeat(p)+'░'.repeat(10-p)+'] '+(p*10)+'%'}
if(window.matchMedia('(prefers-reduced-motion:reduce)').matches){S.forEach(function(s){html+=(s[0]=='c'?P+esc(s[1]):s[0]=='b'?bar(s[1],10):s[1])+'\n'});draw();return}
async function run(){
while(true){html='';draw();
for(var i=0;i<S.length;i++){var s=S[i];
if(s[0]=='c'){html+=P;for(var k=1;k<=s[1].length;k++){draw(esc(s[1].slice(0,k)));await sleep(40)}html+=esc(s[1])+'\n';draw();await sleep(380)}
else if(s[0]=='o'){html+=s[1]+'\n';draw();await sleep(430)}
else{for(var p=0;p<=10;p++){draw(bar(s[1],p));await sleep(130)}html+=bar(s[1],10)+'\n';draw();await sleep(300)}}
await sleep(3800)}}
var started=false;function go(){if(!started){started=true;run()}}
if('IntersectionObserver' in window){new IntersectionObserver(function(e){if(e[0].isIntersecting)go()},{threshold:.25}).observe(el)}else go();
})();
</script>
</body></html>
'''


@app.route("/")
def home():
    resp = Response(LANDING_HTML.replace("__BUILD__", BUILD).replace("__AUTHNAV__", auth_nav()).replace("__PLANS__", plans_html()), mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ------------------------------------------------------------------
# Logo images (embedded in the code, no separate files needed)
# ------------------------------------------------------------------
LOGO_B64 = """
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
Ej7MXY//oC44AAAAAAA=
"""

SHIELD_B64 = """
UklGRj4hAABXRUJQVlA4WAoAAAAQAAAAbgAAbQAAQUxQSHcRAAAB/yckSPD/eGtEpO4TjNpGkpRU96+GP+E9IUT0fwL40RfHI7fa
pj710qKgiblWzpFgk1VWqZoAgUk1KQoKynIH2u7uZYbWCzAzgLq7vlHkHtZo21r2tFrnPG9C8CDFS3Hqcuvu7u7tdeO6u7u7u3vd
3b1F672FeosGAgn53ufsH+/7fUjo/4iYAPqjuYLXUQfcXjfc8bceDsleFyzBATeq7wfjINkWzxLM/EWfsrTk3UMgbdkswejPL5NK
RSktOL8dkm2xPMGwDy2WypCkXEp3nQYk2yJ5glEffFYqQ1KEpJyl209tg8K2NOYhtv7cEimHpCilMiTlkB55x0jwtAUxV8Dub39Z
KkNSlNKS5VIZknKWHv/yNkDyLYJ5yjD4hHOPL1RmSVFKK742auYvu6UyJOVS6vrdkQk8ufUzLwD2PfmM6ZBDkkqp73czALb/ZY/U
CEm5lDTv07sAVni/seQAO3zo9H0cRUKKUlr/t30gmTvs9ts1UpklRUPSuuveOgkgJdvczFNyoNj1I9euF2RzIJdS398PAHcAT7DL
D5dLuQwpcilpxX/fM9sAT8k2EzNPieq4077+cK+kLDeQkJb+8g3giabuMPnT8yU1QlKUWdK6B750VCeAF262ScxTkaideMSnbnhe
kspSAkIJnvrcNmCJlt1h6Dk39UhRhqQosyQ987+37d5J1YvkthHMUVA7auIOe+80DCDCzYBcZqn36tMHQ3I22Apgz++8JCmXISly
JAMef/Te+x5bWQKYGYRaUQDDxk7eccrMfUYAhDAHJJmkR7+5K5CcjWrJofPcf62R1MghIQlzoGfeg08+8eySvqB107iTx0ybNnXo
MAdQ4MkABQl4+hfHDAOSsfGTA1Pece0qSbmRDCDCneqqlS8tfOLlpXf3NPM48Hxqs8zNHAjhBo3F194wCkhubFpLBmw756YVEkS4
A0hBwVSq+9yXch10ZJlhGCAhPBksvf++mx7sg7bCMLdNA+bJgSlv/PWh0wEFhhkIIXIxFPOKgCHIAElyNwyWPDP35gdfBTzYjD0Z
MHS7Qw+cNZNqw8zMgeTDKGk+oq523cpn5s1/NFNNIqZs9/nTYee/HoZvOsAKD2DUzJ322GPceKPFwYyYFO3dvhQYVZG9suC5xU8/
0001JUngsc+pv3ub+36XHLWZAGYeATB2+5ljZ86e1QmIDg79b3fHJaO/DbQBiK/8lI3f/u7dsM2l6ob06i2An3RJOODkFY+3v7hH
n4FVjKUc3BFZGZeEgTySH7rfuX890K44Hd+cas1NVi6jdiCynlzmUiIBMtbxraklCEMYBp6dV15Ypx9h9ENlSKS6NgYPWGYrB6R2
KKiql33MTAYy85RMIke7jzxnbP+oLyuGc8tRS7Rm9qKVnyfVlN1M8MgSoFjXK2rd9julo99BO4ccHalY6xf+l6hRr/9sm5IgJDXy
FU8Va7rXPjbpv1c09HZS/8l1bbz2VK9Zkf83n6ZFfLQ9ECXy3jO2f9twz+t7B8ye9bZfzsD7j9UlbqbesDp4khYH/O+Z90ExdBX9
PdXBkMHJC2zsUKImSrZr6+hdnXLIe199410Lf9H9/q1Ot+Rm/UnN5ry5UTjafzK5xrHLZl46ataynBvTHz9w6dEfGdgxdnTCaWpm
NSZJG8XNBBghtRAV0c240Q2QLnmsiXXoxx3X/+2xNyf1XDCJ9Owc2H3Q89SbWabVhG+AuYVoMaEmVjHW0lQiaryDH3Ny39efBb4F
GfCXqbcEFNMmj+lM0dO14qVn+8C9lQQwZfqoYW30rVr73NN9YKkmVaDRrL2gUZOG0B6X7UaKkz/Q054ix5CvX5XKisPQg07ac5uR
1K94fuE1E8G8zox0wEn7Tx9L/epnn73hemUS0NHsjD3Wu6S7v0wfYOFbkbPJ0PSDqR8jATjt712wIxBR4w4s/92+1DucdauAiBpL
QN+/jyMDI1ClhzkHrncZP72eLgygE5AJ1uVwQNZDNTHjbimEG/UKTOr75+5m4Iz9lxSBOfUKzM+46vojMDoBRDdNf38TKytiEIAA
S0284uz1vMrsbGg0Qm8lYWw9T7kUG6qcjzweZ0zFWN/EUxtdmBDDK9WgaQCuaf+bVCYHCNW5gXLcWZgZw/5OY4ABKDAEbkDOT3dS
8IOK082I8eOnHDaJHHTJADqbtViBb0wsC6o50bR0U9apJDx/jMYgqrlw6ktzy/oQKfF7QNZYyUPSMys+YIjlDartqM5b8jj4jCio
Ta889PRqG77N5NkDoU+3upkz6aRopzatfPDRVzVyyuTZndDQ4uFmzi1Uexv84plFPz9+DwNWrAeMgchqolkC42wTVdnXfrWE6oBt
9zvnIOXDSCROI6wS/rM/Ur/tXmccPkjvIxnMA8SadQwcNZiqWFOBThO1uZlDTrtSm9PPP00CTBk4+parMEgcLiq57X83kWoysOtH
5g4xMwY+hiFeXYHBef/5zyVF4WtXKYS26qBezQKjczRWSfwmWUnVnFDbCAOcMQjA+aOn3hozUzAKcCa9SLVrHcCup5x+VtmI3tWW
LNmYIRsDikStbHBuN1WqiaoZTtPOFYVUqbowSLxhHYZYzbi9t+4E+Omvd8r3vfLisldeXDnYvaZFAd1rUQ2fPXUtbpIqmAE4jbaa
8Pf//XncJFXAgIIzlA1Yzdjfff+uhw6aMuDJo5ZfRLsc5Uy9mgUyLt8hJwDZvd+5fg1YCommiV/tmxOAbNGXrusCipCoL5jTaLTR
aJvLxONiyqhFC//4w+nXnbQqIQDve1WtGbg+f1jUEM7im66f+yTgFs1Ofxs1hPP8LdfMfULgnlVxfq+BMJAlXCNq2/XnGesGAlKj
eHgOBt7MQXnaB2U1hBl0LbjvhgeXQ7KK2bAvSTUEDqsXPnz1Q69BMqoHny8H3WqGhZLUR/sAwzCTkBCoGRBw+PCoQ5IK4OXrrrwK
HMC1+/ayGgipAFZcdfPlK0iVFoP64eRMlsjCRLW16nhSyKhX4AZPvKMgARgz8KwaQIEbvPLTTpKzxzWXZV/b29fdvXa9bH1W40qj
HDwmsFSo/WefS7SsisGrqyhK95qqcjLdvQcOIJYuoS1INVVld548jcToY46ERiPnRgNFRvEut0bnDIUN6mgf8DABaAMQ3HFpXzsh
3GqAKLXyPBKA88C/ukCBeQ2grHgfiY24kA0UYBsCxqM/vOiY7YCMmVVQqZ69cQDx4g+/deI+QMbMKlCGzsYOmZcHItaVuv1Pj1Xo
NMwBmSK6M6ANwx2GH/G9h7okqVSVVHb8vEMGYAna9/j07a9JolQlJel7E3TPuwaJ6LP2njkH77DOxL3FWsdMBIr8rqccrFnLXgDs
cNFPn5AiKhR5t5PkFbACYNrZ356PEVQ9JryZvrtpPu8P3wcGv++lhIUhGVrSEy1ZK2CeDGg/9t9SVEBHE3VgnhywA3/XQBVMZzhD
3tLRcdPdR57V6N5/l98FOnQZG95CU6sBzJMDJy9VVMz2NYHVVL1w3tJx0MtEjU0Yr5gzk3eq+7Hw/48dn5Mtc5HyZ4/vbsvq+N5/
HFAzqzHc62pTwVujrGFkAWDepOr3TjxRUgUfzrp5p3Tdo7toboKU3/ELqlefKAPfEIZBcmtGKnZap6Cp0Q4pWbOGXztpuVXAMhTF
U4tGjxVggAkwbfXQBJmsZ8/HATUTYDZ47s+nAkVyq/oAzotct7rE7Mo/7wQUya1KeuWMPioid9E2jDvyWRet8xAh6k1/viAnwj/4
AwdrLTFHeu2Huw2gxR2eVBYQuldtHCJ1/eOQwTRdz8J7TVS07DU6p3E5f2wrJQhMqZLKizEhTm4LI1pyG7Uk+qTG3AdveXR5d8OG
zTjlojEyJJU6m4KrYr2kufNvn/fSmoYN2ua4C2bJQGros9h+mjeIlnMFJq9wcO23K4a3ZHxGpXIpQGuWri0mdIIMpFKLhieOV1aU
WcDa19am0VtBOKAoV041vqcvk8zMAGPaxz6oZKVum3sDgUX7iTJyM7BywvM5S4rAjdrsBihyPo6i7f7IkpTDndpsTqVX78fGv1Tu
6W0pFQCufX+7n0x50H//9GdJGOeOLfFWnG+pUYYkACHMqC1Dn6aNd6osQ5IAIcyozb36C218V7cX1LpMnqecSa3d/kxheJ5xVmCS
BFIi7IDrJZU5jJZDqPE+3G3vyyWVOYfRqoKkn7e3c3ZffivbnXPcmz9MU7dcYc1XH1yKTO8eZe2YGTgJCTvt+oakCDMMkOQOdx1M
MoDD/9stKbKZVSRZgkVn08ZB3Xp+VLpHUr6sx0UpWZ7pPZEnHXrdnL/0YbHtHA0wAMkNcOANX7h3+Uhafm3BrwocwIFZH7nzZdHy
qqd/9W/g9K6sr9NxzAEnvvbpDxeYF22Wp+xz63psfMfqnu5lhuntW/37hCMOO0JZ/igBlgyYteP206ZMGFJE+cqTTz36wGJw6t2B
rY/bYcrM6cMdvbTwmccfegwY+XWpsWwbqmeNo+m+J/z5FQsVYxn5y2UKya5b+sJVt9xCq+bJqKZkRCnAzWjRk1MtkqEE4Ez71HPK
ffoJyZN7dzt9O04u3fQHrWiPkD2yLz9RlmRcYu2p1uqqboSoNbcINtQTCmottRX+t+VSjuiePOAvO2SPIjfK4akROR+twiS0/Wjb
fnnOQr7wDmtkNq4BYhNaBRJzpEaooe8zeMcUyjLo7so5x2KaF3xKpQCu7zL6s7PDqkYp5XhtHJt2yDxlEPle+rOltttUSmronYwY
aRgGGAjjxlT2pJ7c+5s/XHI8Zyo7yFc/Ruo/Bd9VQ1JDd6aR19yBBY5MRkD8yRuhRjSOP+HUXYr0DwkQ/38Z7y8F56uUFI1VO/nQ
HbZ3yzKZZQgUf6L1SYsxqi+2mfWPggO6cpbUq4+yUT8OpoZ739reAR13PfLOibIKzzX6h1i5xgFMN/vWH/zoxz9hGAHITOGMwyLK
pPXdvbQNT9fuU2QDRBfWH1jfQEARL85inz/8/Oe/cCcM5YzjUX6Q1i2l7anK6UX9IPdStRh5KImNnlCAgxQxfCYGIDrY3I2BiapZ
xwzS4e/70g+HFbPaV7+yjXe9ZIBg587p171M0eZ9fQAyjduKqhlDCducxLDB1IrdKLjwL3MXDB3ymx3/89n/jf7Rl10IOPPQ/Q++
nYveWfzo9ykDGCM7MEAwrAPbbMwYOwCrYUQKo3P08CGMnDi0zWYUw0BUb/tpuchjxh6MpqnRlqgNJo3ENhMvmTaKpkUSTQd+Ydii
Ne8vHqbtq9NWvr/bbgQKXl2cX2uGaGtDgDkTpxC2OSQGTCWamGSAmRn8HvgZ4BeOWVWAGyEGDy3XkJtgFJlaMWk3wjeZweSdwQGJ
voRoMRVOUSQGPbxiYScWbOR162qAoXuNBts0lpk+jaCaWN2LsVEnbD3eaWom1JLoXlvnmZ13IPumMAYdOgkDkNGF0z+Xr6jBYPv9
B+C2sVIwaz/DAcL6FoM2lpltGrqWYAFgtJ+4B6SNYkl28C6U1C97DKO/ihVP4wKwzB7fGoL7BlmCXU8eihkg4/8vgvoNGI+tptZA
jxwHyVpLMPKrexMOEIn5z9O/w3l4Lh4AXkr/3BGSNXPHLnpcYNR2P96L+lf1mfvCQoCZOPa8CZBCgCfY/wapNIBwFt1FElvAnlue
IAnAg6FvvOjnXRTZLDP7j+uVswDCuGkRiC1gOPffgEkAnhn/2A/+2QVM+cFKqZQEueDh29YjtoyC5Vc/QAoB5jnxxO9/PfrdF0hl
SFJA46Z7SWLLmbj1qjW4ACxwXhwynDIkKRqJey5ZDWILGrD+0tswBdVQokyqltLSS+4nBVvYSMz7zTySgqowpChDjZ9elpHY4krO
Db95miRzapVDumoPSGLLnGDkx54TgQM5pGuPBHe22JZg4uffsjUhErrjeDBni24JRpzz9l0hrjwezNnie8oMPPFta757FyReF80z
1cTrpnkYor8CAFZQOCCgDwAA8DgAnQEqbwBuAD5ZIo1FI6IhG2xVtDgFhLYAX7jLfyXmuPj9s8zGqv4H8d+xbrWi6W1P956mv0Z7
An6idKP9xPwA+Af7SfuN7wH/D/ZX3Mf4j1AP65/rfWa/7/sNf3b/lewV+znpsfvJ8EX9m/4n7ifAH/N/7x/9vYA9ADhMPLB4G/mP
Dny3fOZSDPLlxgo/wXa669/qPQI9tvuPffaoMnp/S+EX9k/z/sB/y3+i/9/+8+67/a/tb53/qH2B/5r/Yf2C9sn2N/uD7F/7GOJW
HJlGCA3cSbJwKcekS59DqcVNxh05o7uJzgzTwoVvHpf57Dgp0BFgcF8OmvRlScwKenzZtrMcLnrsYpcpnHeFPVXltjSFYHOucbSe
uhUykP79m7a6J1T3WgI/SPuSLPKX7oap0iBUCLyccIkVQmSAwuQVVGom93W4Pireup2llAAN8f65ufeRCS8r4d0O/36PebFkaZRz
2nhtCotxfSarLDKR9fJ76H9HC79qz+ocmah0R3t6ektpvqHM6vJ9ZFlwS95WZPo/DYHa+SOquGttIzTLBby3MO7uEbkj/WtJI79m
4AEg5PLn6OPsjV0+Onss/iRhegj1EWeBPzlDf+aemnAA/v/4YUwv/4AGwWYwssx2hJpTjf5uzlXP3wXF2f37Y9HhUOlznidgndUU
ErZPCpXO3lGqL/jgKUI0siL+08Tn2X0a1OZy6fRn0HlYsZ35qzdMpq6Exlp5C8yoStZ6SRWpu5OB8iPRtsH8JzpP3OU/FEu2YVdg
yYL+53F7KbtDVUELafkCK19vphEc5opqZ3dfQlQlMTUPxC0adlFCo4xVhYZejZRg7nk6aDJZl7rggmCszKbY0dmHOQvirnllzLWt
26ob5iUi1tQI5dBfDDw1NcWJqYdnB++95tpSIr08Yw8TMTgVpHDYjKyUeLItvo00XVZjLyRI8RhEgtCeqNQHDm3/3pEyfPZU8zNd
LYjLRWaOCW0XpdveAzhGSwgpn/ewZxTGHhO7FNT0m1qS0bsS+ZPwXINviPu41pElGpI+cfycCuvB/+ZqP0FyyPelPZh+T6Ct+zQh
nquEWPEWVtyIAPbXcfO1/wXjxweypRoS95v2knLrtesC4Jm+CpupZl0iUoDhzl8/rc8Jl+OYu9RGNUSCW1sWFzITzF3CqGeL07It
/ocX7AaegOxnkM97WKIAW/sVvD4qZMU3NcqxELMl369pxNUaqZdUWgGQVDbJ12vvlowmt3+6vH0hpZOE+nncSQ3/1lSsmtBbccZj
4+J/KtrO+FjCvwZfmLYvv4wee8SQiddI1w+7z7OgdC7Ddy/Z3KMLq/rJ/11375TTAifqmvx26p8bdYl4UikHH8IS/L1dhMN6JSoQ
pQRlwU434oIWLICN5Jq6gNvRXsTmaD7u9vCZ079d4JaCHasutwfa85HiDKG/bpzEwde8VE99O3tGijtXNZvi6P8finmoPYw2O7rb
YNnrcWrCwPCm9c3UCYVqoWS4SPIW+pphY7CN2+2flobxW59VmWypJRASWU/43/aCnpS3wpRPR/hzExUUG1fneiHMA3zXawYP277c
xHPzXbXPQ0OXmljQK5fY1X+q1Nizy4Z0KCmYpqjKHG2TaQATG67MDY+YX5d2KNgvhh/HD5rvldBrjWjoT/3Z1531ChV+/4TmLdXv
rK3OF+hvpLEqpQlaLwHX46NpRhCHtLc/mIScOWPw6JsmqEiZAqU6rLMj1tuEjn5u1gWd++oYHmBkcl2CU4dICOA7U3wNu/9Z/LqL
WMvEd4dWJfOpfeeBqrvKbZKfyW+lHEA/v/CdG9EH2HWpVlef7F24s9xLQqED7vvFtPbZr18GCTg57GUbZLM6XwJLXsabhpEMHKia
143JL6UOxgIIJjueI8XCo4NoSs6Z2/O1EsiARE2VdjyxGOPcufDYpUXewuiwvyFdce9/Ur+pIpGeXHBT5T0ABhNrTGB98HUoEWw+
iIU9jOwa98ZzP6CaAt2qmAe/P2mu9khmzK3qykOXyl/1P7AJOD+R2VI+ycI2sh4hTArc1jRbyNwzxwrz9Jaaz84t3Rc3Oq2ubfo9
LSHk6z4B1xRgmJciwpqNOnph1KNxitDDyf1EVjgpqVE61xw3VIm3UovxfuqnbCi8UlaC/sRXyHmTMcXvgMoVuYXEPrlqFEUI1CBm
31za9DIx4KskhFh7+v/uYhHlRBwxz697vgvQFEjTcWzmcvkBLkj5Rk0zPQCt7tdixyjfOC/3vXefSalhmABwf0PKZve8rkzrh9V3
Iti8lAdP2p9EQE0qfmDxBGGAx1yNcqQeMZUzAuIr1AqvxRXgVXvOOfJFiiP2vqYTMSxmunTeAzQO0Ovh7GletRqmhVk51wKwG+yT
0z3HVjsh1mytRZd2MD/XnOC4npa6SK+8biBoarrFMT+e6ktQl+n6dVDj2/AlDkJHW7CxtB5S6RElgdNRUZHe2A12b51gbheVkI5e
O3DkxBuvqwy+KjzMPOEQ55o7OKWD3YvZm4HWWwRrBmYDFQ6C/xQTTYwbDfTyxMFC7kXfa/XMPtGW36T9xs5Jl/8Q6ct+6XXOMNDp
uI1K65AVr8Ri7MKVMIKHXyTlIhcAuXtbqsGjGm2AnNRPZgTW+fAMo9/KKrD6CaB8/XsJxfwrFF82mxtOxuu0LbYfQ7Hd0Rr6orTG
X4s4mLEX6kglq6TepzTEF4wqRgTVSo18l/qB661IZDOwbg+XiAHa/rHDcu6N9BxAaJdQAwul8CIuCHRyGBj/yy0Zq3KCmxMFrxOa
pOxulJYU056W+dGUTHz4gh8Y0bAnRBPks+durWZvfnZ/tDbgUFZNFfaXR3/+zEXyMU6DLNmnSSbFG7YYXaSPrqZhvrq34hp/iikn
D+kXE4/FkQRJJJGY3eF1xFJ3M+C1zkhnAJMcaGd7ehsn2U/EYAwVwYLXpZKlvPcXjSrwfDHV0LwVQRDQdCkNb28whCHtCdwd+Pys
x2BgFYRS6PDf03B6DJ5KK1O3BKoceC2i/XrFDOSdDI1SjB/zgHluFTzU78Ewh5qjSAUqhocmqF+HFK365QJGihYFTl5V1RsfZ5+5
ACKfszdYh6jCAUlskUg+Megd3c5PyMU1BnLCpUWOTigWW5mI1i4A85qAZwEes7MrovDVtTzh3Btzj/dTBT63dLVNzTaBYZu6SdQ1
HBhhbflSUHRxbK/a95YcSxAZ7BYR6tlEkx8K5n/aNXpWInVNgkgOjjxJto2HOXqjqz8A4wer0Q+n81atM2/Hr6b8zA3+5j6us1d+
IQsiMLm6gTwNxhAWpSt78wC0PwVdi7feL6pVyfrZpx1+hhneGrtWw4IWeffD73ZtQVoJqkn0hffims07wc+GaI7Vrg/jcHZZJ9PF
N0fF7IYYSAhk6US5ViobyGaatGrAJxRXNKwbJddr0SDE9KIigVs59ysdtkdxL0xQpGcJF35eRfIytt9JSlwJtbO92B3tBAcZrHnH
2msu86wj5DWZZrZSzkkNKVETSsE26Uac17TD2yb6YnBmwgYugP/gsp/g4MUrXRzgzpUawaubQErA8jwPXkHicb1yiexcVRpvaX/F
BvyN/erZbdQJA4ncIZOeU35Kfuzeer4YIVhd/HCOToikOhJ+Yq+ze5uJiw6DM87VYY4sl6/FHh4MqVaFIoPLvxAOs0cgRQAzA6Mh
uNuQni9a7dGEtAZSMvHS52ICnbJ3mqdGKQIM5ltuVbzE8R5dvCLEHSP5yS+r/iK4l7xA3zT9C7yODXO6F9O2ic4M9G1cuOzxkZoU
5glvaXwAe8NVcQqoOSyFK8qpIVIPGADS37YOG8G9PROavJJ7VCaGheVKPcc6wbrUqnZwU9I9JC61WErZcNkDPzm5p80+rXeM3/ud
ZmcQheGqVp9LvMqUykGgJqVnewaluo9Vza8q4au2p0yIyMekPkHeBNueuy1bM1dKuV6i4qVwz78+mgIgxj7MfqTCZt5rM+9fc9/w
wpGpXl1p51et5/E3CK/CeB7QhRTvaPXGRZcN1kzQk/81ZX4e/7C64djvY5K09e1gFEK6XrYUAFBkyNaAAkEPNlJN0owTnvsbKuYW
bqZqxf2fPwNrYIqqqa+j/v7kImJKiDaQZXpqEQroAZ4DW2vZKT/L+vGtVpTSopTIYWk24S5LXjQ4vQ8Fi6Ro0JT4DvclwfJ9s3hD
/e4GDn+JqFV/V1L3gd5mxXwmRyRLHOxn+JLs8/Ls4wmKWdANjf9Z1aY6Ot9tvQRT6CUbVqOBgQUp084t96Y+JlVY8Blh/9dwNWOB
F2BHL9nL9Xvhm9+iSoBqDqKjrODcIPvcMNwHkqGQm/2e7gORCgH+h7D7adameqWaFtGWgnKWH2QiU7vaMn2/rPR/41V18M34ttAn
KOv5xnq6vvARZCPkShiZac0BON41pkgkx25nZEZJ5CKcWFcGSZSFBtVcCKIF/LK6jQ1MiZjpaz6pKfh811U4ja6/h8DQmcm8HMom
0Ilh14Xb/klFp0SRlA1Qe8pO6gqXh4SBojaqjaXPSskK71MiQbiDdbmnCqdRvQnCiwqFNiQ3fclvEcJDJuegJ6UrWau5Ej+Slf2M
DEnwHdGMgAvm/N4KLu836tZyrtG6diVE6ez64Bq3Z8GLStSagapWy0j8on+EZhhp3qp6Q/lY9ktnXq9cF4/p617o5i+pkk++QD3x
fTv0W2t6IO264imE31okCJfVnWfFXCVq+tjbOryXLIaK591//sw+UStr+kLN4KHFCMKqwzTuIHMkhUZdhqAGugVJHeSs7zkQ4awm
I3w7JaKp1wg37JmWu1pVRYjQlm/vqQLYA8tex/xkcxR+jlUvXJ9VBfEiHr/QOI+5QISnLATLPWYO1Mt4T2B4bIgE9od+r7iZcLv0
kG9E9RYJ1yuDFEh9ngSi6g41yE/4MsnYXfP6M3i2lbe9khHxUVfdKTzidZycC1qHRUlLRNFMZV+pJqn1ftDMGyAcAXioUT7O6Q7+
D2AjvFSFxV8+sLsDIceqLpu7i0YOfS8Qx6tciCv/gQwPHIu/7q/dPEtjE2m7pJew6QEMQD81mlOfdrpWkosiumMFwXd78LhL1uVH
wQbu0VZTYD+goHZpvmY7EHgeZIj6zqrCf5AF9RqWpECIABVbspHBWI8o38b8TXr1+PPwzVSYmlpogYxEyRiWGqx4AB8xXl7bax9M
uuNCP7WutIo7MPcJl9UICQ4y+YIsyza8sHpAMiJ5WeBcoBw3/v8P34d51ca9nIrOnr/ZIia4mG6VlGYbNB97ArJhYy1cQSm+T8c+
1FE6IY6JcsZGTTj4yzebZka5mMTjRo6/ERaTSiWa5/6BlS0AAAAAAAAAAA==
"""


def _decode(b64):
    try:
        return base64.b64decode("".join(b64.split()))
    except Exception:
        return None


LOGO_BYTES = _decode(LOGO_B64)
SHIELD_BYTES = _decode(SHIELD_B64)


def _image(data):
    if not data:
        abort(404)
    resp = Response(data, mimetype="image/webp")
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp


@app.route("/logo.webp")
def logo_img():
    return _image(LOGO_BYTES)


@app.route("/shield.webp")
def shield_img():
    return _image(SHIELD_BYTES)


@app.route("/version")
def version():
    return BUILD + (" | pillow ok" if PIL_OK else " | pillow MISSING")


# ------------------------------------------------------------------
# Admin
# ------------------------------------------------------------------
@app.route("/admin-login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def admin_login():
    err = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        pwd = request.form.get("password", "")
        a = get_db().execute("SELECT * FROM admins WHERE email=?", (email,)).fetchone()
        if a and check_password_hash(a["password_hash"], pwd):
            session.clear()
            session["is_admin"] = True
            session["admin_email"] = email
            return redirect(url_for("admin_panel"))
        ag = get_db().execute("SELECT * FROM agents WHERE lower(email)=?", (email.lower(),)).fetchone()
        if ag and check_password_hash(ag["password_hash"], pwd):
            session.clear()
            session["agent_id"] = ag["id"]
            return redirect(url_for("admin_panel"))
        err = "Wrong email or password"
        send_discord_alert(f"⚠️ Failed admin login attempt for `{email[:60]}`")
    return page("Admin Login", """
    <div class="card" style="max-width:340px;margin:60px auto">
      <h3>Admin Login</h3>
      {% if err %}<p class="err">{{ err }}</p>{% endif %}
      <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
        <input name="email" type="email" placeholder="Email" required>
        <input name="password" type="password" placeholder="Password" required>
        <button type="submit" style="width:100%">Login</button>
      </form><br><a href="/">&larr; Home</a>
    </div>""", err=err)


@app.route("/admin-logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("home"))


ADMIN_NAV_FULL = [
    {"key": "overview", "href": "/admin", "label": "Dashboard"},
    {"key": "licenses", "href": "/admin/licenses", "label": "Application"},
    {"key": "tickets", "href": "/admin/tickets", "label": "Support Tickets"},
    {"key": "certs", "href": "/admin/certificates", "label": "Verify"},
    {"key": "download", "href": "/admin/download", "label": "Download"},
    {"key": "settings", "href": "/admin/settings", "label": "Settings"},
]
ADMIN_NAV_STAFF = [
    {"key": "licenses", "href": "/admin/licenses", "label": "My Licenses"},
    {"key": "agent", "href": "/agent", "label": "Agent Dashboard"},
]


def admin_shell(active, title=None):
    staff = g.get("staff", None)
    nav = ADMIN_NAV_STAFF if staff else ADMIN_NAV_FULL
    return {"nav": nav, "active": active, "logout": "/admin-logout" if not staff else "/logout",
            "title": title or active.capitalize(), "manifest": "/admin.webmanifest"}


def _price(text):
    try:
        return float(str(text).replace("$", "").replace(",", ""))
    except ValueError:
        return 0.0


def _money(v):
    return "${:,.2f}".format(v)


def admin_dashboard(db):
    today = date.today()
    soon = (today + timedelta(days=30)).isoformat()
    rows, mrr, arr = [], 0.0, 0.0
    for name, p in PLANS.items():
        total = db.execute("SELECT COUNT(*) FROM licenses WHERE plan=?", (name,)).fetchone()[0]
        active = db.execute("SELECT COUNT(*) FROM licenses WHERE plan=? AND expiry>=?", (name, today.isoformat())).fetchone()[0]
        m, y = active * _price(p["monthly"]), active * _price(p["yearly"])
        mrr += m
        arr += y
        rows.append({"plan": name, "total": total, "active": active, "monthly": _money(m), "yearly": _money(y)})
    total_all = db.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
    active_all = db.execute("SELECT COUNT(*) FROM licenses WHERE expiry>=?", (today.isoformat(),)).fetchone()[0]
    expiring = db.execute("SELECT COUNT(*) FROM licenses WHERE expiry>=? AND expiry<=?", (today.isoformat(), soon)).fetchone()[0]
    open_tickets = db.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0]
    return page("Dashboard", r"""
    <h2>Dashboard</h2>
    <div class="g2" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">
      <div class="card"><div class="big">{{ total_all }}</div><p class="m">Licenses sold</p></div>
      <div class="card"><div class="big">{{ active_all }}</div><p class="m">Active licenses</p></div>
      <div class="card"><div class="big">{{ expiring }}</div><p class="m">Expiring in 30 days</p></div>
      <div class="card"><div class="big">{{ open_tickets }}</div><p class="m">Open tickets</p></div>
    </div>
    <div class="card"><h3>Economy analysis</h3>
      <div class="g2">
        <div><div class="big" style="font-size:1.8rem">{{ mrr }}</div><p class="m">Estimated monthly income</p></div>
        <div><div class="big" style="font-size:1.8rem">{{ arr }}</div><p class="m">Estimated yearly income</p></div>
      </div>
      <p class="m">Based on active licenses at the plan list prices. The monthly or yearly choice of each client is not stored, so these are estimates.</p>
    </div>
    <h3>Plans bought</h3>
    <div class="g2" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">
      {% for r in rows %}<div class="card"><div class="big">{{ r.total }}</div><p class="m">{{ r.plan }}<br>{{ r.active }} active</p></div>{% endfor %}
    </div>
    <div class="card"><table><tr><th>Plan</th><th>Bought</th><th>Active</th><th>Monthly</th><th>Yearly</th></tr>
      {% for r in rows %}<tr><td>{{ r.plan }}</td><td>{{ r.total }}</td><td>{{ r.active }}</td><td>{{ r.monthly }}</td><td>{{ r.yearly }}</td></tr>{% endfor %}
      <tr><th>Total</th><th>{{ total_all }}</th><th>{{ active_all }}</th><th>{{ mrr }}</th><th>{{ arr }}</th></tr></table></div>
    """, shell=admin_shell("overview", "Dashboard"), rows=rows, total_all=total_all, active_all=active_all,
        expiring=expiring, open_tickets=open_tickets, mrr=_money(mrr), arr=_money(arr))


@app.route("/admin", methods=["GET"])
@staff_required
def admin_panel():
    db = get_db()
    staff = g.staff
    if staff is None:
        return admin_dashboard(db)
    owner = "admin" if staff is None else "agent:%d" % staff["id"]
    base_sql = "SELECT l.*, (SELECT COUNT(*) FROM devices d WHERE d.license_key=l.key) AS used FROM licenses l"
    if staff is None:
        licenses = db.execute(base_sql + " ORDER BY created DESC LIMIT 5").fetchall()
        total_lic = db.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
    else:
        licenses = db.execute(base_sql + " WHERE l.created_by=? ORDER BY created DESC LIMIT 5", (owner,)).fetchall()
        total_lic = db.execute("SELECT COUNT(*) FROM licenses WHERE created_by=?", (owner,)).fetchone()[0]
    open_tickets = db.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0] if staff is None else 0
    certs_active = db.execute("SELECT COUNT(*) FROM certificates WHERE status!='revoked'").fetchone()[0] if staff is None else 0
    agents_n = db.execute("SELECT COUNT(*) FROM agents").fetchone()[0] if staff is None else 0
    return page("Overview", r"""
    <h2>{{ 'Staff Overview (agent)' if staff else 'Admin Overview' }}</h2>
    <div class="g2" style="grid-template-columns:repeat(auto-fit,minmax(160px,1fr))">
      <div class="card"><div class="big">{{ total_lic }}</div><p class="m">{{ 'Your licenses' if staff else 'Total licenses' }}</p></div>
      {% if not staff %}<div class="card"><div class="big">{{ open_tickets }}</div><p class="m">Open tickets</p></div>
      <div class="card"><div class="big">{{ certs_active }}</div><p class="m">Active certificates</p></div>
      <div class="card"><div class="big">{{ agents_n }}</div><p class="m">Agents</p></div>{% endif %}
    </div>
    <div class="card"><h3>Recent licenses</h3>
      <table><tr><th>Key</th><th>Client</th><th>Plan</th><th>Devices</th><th>Expiry</th></tr>
      {% for l in licenses %}<tr><td><code>{{ l.key }}</code></td><td>{{ l.name }}</td><td>{{ l.plan }}</td>
        <td>{{ l.used }}/{{ 'Unlimited' if l.max_devices|int == 0 else l.max_devices }}</td><td>{{ l.expiry }}</td></tr>
      {% else %}<tr><td colspan="5" class="m">No licenses yet.</td></tr>{% endfor %}</table>
      <p class="m" style="margin-top:10px"><a href="/admin/licenses">Manage all licenses &rarr;</a></p></div>
    """, shell=admin_shell("overview", "Overview"), staff=staff, licenses=licenses, total_lic=total_lic,
                open_tickets=open_tickets, certs_active=certs_active, agents_n=agents_n)


@app.route("/admin/licenses", methods=["GET", "POST"])
@staff_required
def admin_licenses():
    db = get_db()
    msg = ""
    staff = g.staff
    owner = "admin" if staff is None else "agent:%d" % staff["id"]
    if request.method == "POST":
        action = request.form.get("action")
        if staff is not None and action != "add_license":
            abort(403)
        if action == "add_license":
            key = request.form.get("l_key", "").strip() or "KEY-" + secrets.token_hex(6).upper()
            name = request.form.get("l_name", "").strip()
            org = request.form.get("l_org", "").strip()
            plan = request.form.get("l_plan", "Basic Plan").strip()
            expiry = request.form.get("l_expiry", "").strip() or "2027-01-01"
            user = request.form.get("l_user", "").strip() or "admin"
            pwd = request.form.get("l_pwd", "") or "admin"
            try:
                date.fromisoformat(expiry)
            except ValueError:
                msg = "❌ Invalid expiry date (use YYYY-MM-DD)"
            else:
                if not (name and org):
                    msg = "❌ Client name and organization are required"
                elif db.execute("SELECT 1 FROM licenses WHERE key=?", (key,)).fetchone():
                    msg = "❌ License key already exists"
                else:
                    db.execute("INSERT INTO licenses(key,name,org,expiry,max_devices,plan,client_user,client_pwd_hash,created,must_change,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                               (key, name, org, expiry, plan_devices(plan), plan, user,
                                generate_password_hash(pwd), now(), 1 if pwd == "admin" else 0, owner))
                    db.commit()
                    send_discord_alert(f"🔑 New license `{key}` | **{name}** ({org}) | {plan}")
                    msg = f"✅ License '{key}' created. Client login: {user} / {pwd} (they must change it at first login)"
        elif action == "delete_license":
            db.execute("DELETE FROM licenses WHERE key=?", (request.form.get("key", ""),))
            db.commit()
            msg = "🗑️ License deleted"

    base_sql = "SELECT l.*, (SELECT COUNT(*) FROM devices d WHERE d.license_key=l.key) AS used FROM licenses l"
    if staff is None:
        licenses = db.execute(base_sql + " ORDER BY created DESC").fetchall()
    else:
        licenses = db.execute(base_sql + " WHERE l.created_by=? ORDER BY created DESC", (owner,)).fetchall()
    return page("Application", r"""
    <h2>Application</h2>
    {% if msg %}<p class="ok">{{ msg }}</p>{% endif %}
    <div class="card"><h3>Create client license</h3>
      <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
        <input type="hidden" name="action" value="add_license">
        <input name="l_key" placeholder="License Key (empty = auto generate)">
        <input name="l_name" placeholder="Client Name" required>
        <input name="l_org" placeholder="Organization" required>
        <select name="l_plan"><option>1-Day Plan</option><option>Basic Plan</option><option>Standard Plan</option><option>Pro Plan</option><option>Enterprise Plan</option></select>
        <input name="l_expiry" placeholder="Expiry YYYY-MM-DD (default 2027-01-01)">
        <input name="l_user" placeholder="Client username (empty = admin)">
        <input name="l_pwd" type="password" placeholder="Client password (empty = admin)">
        <button type="submit">Create License & Notify Discord</button>
      </form></div>
    <div class="card"><h3>All licenses</h3>
      <table><tr><th>Key</th><th>Client</th><th>Org</th><th>Plan</th><th>Devices</th><th>Expiry</th><th></th></tr>
      {% for l in licenses %}<tr>
        <td><code>{{ l.key }}</code></td><td>{{ l.name }}</td><td>{{ l.org }}</td>
        <td>{{ l.plan }}</td><td>{{ l.used }}/{{ 'Unlimited' if l.max_devices|int == 0 else l.max_devices }}</td><td>{{ l.expiry }}</td>
        <td>{% if not staff %}<form method="POST" onsubmit="return confirm('Delete?')">
          <input type="hidden" name="csrf" value="{{ csrf() }}">
          <input type="hidden" name="action" value="delete_license">
          <input type="hidden" name="key" value="{{ l.key }}"><button class="btn2">Delete</button></form>{% endif %}</td>
      </tr>{% endfor %}</table></div>
    """, shell=admin_shell("licenses", "Licenses"), msg=msg, licenses=licenses, staff=staff)


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    db = get_db()
    msg = ""
    if request.method == "POST" and request.form.get("action") == "add_admin":
        em = request.form.get("a_email", "").strip()
        un = request.form.get("a_user", "").strip()
        pw = request.form.get("a_pwd", "")
        if em and un and len(pw) >= 8:
            try:
                db.execute("INSERT INTO admins VALUES(?,?,?)", (em, un, generate_password_hash(pw)))
                db.commit()
                msg = "✅ Admin added"
            except sqlite3.IntegrityError:
                msg = "❌ Admin already exists"
        else:
            msg = "❌ Invalid admin data (password min 8 chars)"
    admins = db.execute("SELECT email, username FROM admins").fetchall()
    return page("Settings", r"""
    <h2>Settings</h2>
    {% if msg %}<p class="ok">{{ msg }}</p>{% endif %}
    <div class="card"><h3>Admins</h3><table><tr><th>Email</th><th>Username</th></tr>
      {% for a in admins %}<tr><td>{{ a.email }}</td><td>{{ a.username }}</td></tr>{% endfor %}</table></div>
    <div class="card"><h3>Add admin</h3>
      <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
        <input type="hidden" name="action" value="add_admin">
        <input name="a_email" type="email" placeholder="Email" required>
        <input name="a_user" placeholder="Username" required>
        <input name="a_pwd" type="password" placeholder="Password (min 8)" required>
        <button type="submit">Add Admin</button></form></div>
    """, shell=admin_shell("settings", "Settings"), msg=msg, admins=admins)


@app.route("/admin/tickets")
@admin_required
def admin_tickets():
    rows = get_db().execute("""SELECT t.*, l.org FROM tickets t
        LEFT JOIN licenses l ON l.key=t.license_key ORDER BY t.id DESC""").fetchall()
    return page("Support Tickets", r"""
    <h2>Support Tickets</h2>
    <div class="card"><table><tr><th>#</th><th>Org</th><th>Subject</th><th>Status</th><th>Date</th></tr>
    {% for t in rows %}<tr><td><a href="/admin/tickets/{{ t.id }}">{{ t.id }}</a></td>
      <td>{{ t.org }}</td><td>{{ t.subject }}</td><td>{{ t.status }}</td><td>{{ t.created }}</td></tr>
    {% else %}<tr><td colspan="5" class="m">No tickets yet.</td></tr>{% endfor %}</table></div>""",
                shell=admin_shell("tickets", "Support Tickets"), rows=rows)


@app.route("/admin/tickets/<int:tid>", methods=["GET", "POST"])
@admin_required
def admin_ticket(tid):
    db = get_db()
    t = db.execute("SELECT * FROM tickets WHERE id=?", (tid,)).fetchone()
    if not t:
        abort(404)
    if request.method == "POST":
        if request.form.get("action") == "close":
            db.execute("UPDATE tickets SET status='closed' WHERE id=?", (tid,))
        else:
            body = request.form.get("body", "").strip()[:2000]
            if body:
                db.execute("INSERT INTO ticket_messages(ticket_id,sender,body,created) VALUES(?,?,?,?)",
                           (tid, "support", body, now()))
        db.commit()
        return redirect(url_for("admin_ticket", tid=tid))
    msgs = db.execute("SELECT * FROM ticket_messages WHERE ticket_id=? ORDER BY id", (tid,)).fetchall()
    return page("Ticket #%d" % tid, r"""
    <h2>#{{ t.id }} - {{ t.subject }} ({{ t.status }})</h2>
    <a href="/admin/tickets">&larr; All tickets</a>
    <div class="card">{% for m in msgs %}
      <div class="{{ 'me' if m.sender=='support' else 'them' }}"><b>{{ m.sender }}</b> · {{ m.created }}<br>{{ m.body }}</div>
    {% endfor %}</div>
    {% if t.status == 'open' %}
    <div class="card"><form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
      <textarea name="body" rows="3" placeholder="Reply..." required></textarea>
      <button type="submit">Send Reply</button></form><br>
      <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
      <input type="hidden" name="action" value="close"><button class="btn2">Close Ticket</button></form></div>
    {% endif %}""", shell=admin_shell("tickets", "Ticket #%d" % tid), t=t, msgs=msgs)


# ------------------------------------------------------------------
# Client portal
# ------------------------------------------------------------------
@app.route("/client-login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def client_login():
    err = ""
    if request.method == "POST":
        key = request.form.get("lic_key", "").strip()
        user = request.form.get("username", "").strip()
        pwd = request.form.get("password", "")
        lic = get_db().execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
        if not lic or lic["client_user"] != user or not check_password_hash(lic["client_pwd_hash"], pwd):
            err = "Invalid credentials!"
        elif lic["expiry"] < date.today().isoformat():
            err = "License expired. Please contact support."
        else:
            session.clear()
            session["client_license"] = key
            return redirect(url_for("client_dashboard"))
    return page("Client Login", """
    <div class="card" style="max-width:340px;margin:60px auto"><h3>Client Portal Login</h3>
      {% if err %}<p class="err">{{ err }}</p>{% endif %}
      <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
        <input name="lic_key" placeholder="License Key" required>
        <input name="username" placeholder="Username" required>
        <input name="password" type="password" placeholder="Password" required>
        <button type="submit" style="width:100%">Login</button></form>
      <br><a href="/">&larr; Home</a></div>""", err=err)


# ------------------------------------------------------------------
# Payments: Paddle (card) and USDT on BNB Smart Chain
# The customer pays on Paddle's own secure page, or sends USDT to the wallet. This server never
# sees or stores a card number. Only the order, the amount and the transaction id are kept.
# Set the keys as environment variables on Render.
# ------------------------------------------------------------------
SITE_URL = os.environ.get("SITE_URL", "https://iss-sentinel.onrender.com").rstrip("/")
BDT_PER_USD = float(os.environ.get("BDT_PER_USD", "122"))


# USDT on BNB Smart Chain (BEP-20) goes straight to this wallet address. The server only READS the
# blockchain to confirm a payment; it never holds a private key and can never send money.
USDT_WALLET = os.environ.get("USDT_WALLET", "0x2602955d19883d77Ea3bf585707Ecfb31eA54D10").strip()
USDT_CONTRACT = "0x55d398326f99059fF775485246999027B3197955"  # Binance-Peg USDT, 18 decimals
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
BSC_RPCS = [u.strip() for u in os.environ.get(
    "BSC_RPC", "https://bsc-dataseed.binance.org,https://bsc-rpc.publicnode.com,https://bsc-dataseed1.defibit.io").split(",") if u.strip()]
USDT_CONFIRMATIONS = 15
USDT_ORDER_HOURS = 48


class PayError(Exception):
    pass


def _http(method, url, headers=None, data=None, form=None, timeout=25):
    hdrs = dict(headers or {})
    body = None
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif data is not None:
        body = json.dumps(data).encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw, code = r.read(), r.status
    except urllib.error.HTTPError as e:
        raw, code = e.read(), e.code
    except Exception:
        raise PayError("Could not reach the payment provider. Please try again.")
    try:
        return code, json.loads(raw.decode("utf-8") or "{}")
    except ValueError:
        return code, {}


def _plog(provider, what, resp):
    print("[pay:%s] %s: %s" % (provider, what, json.dumps(resp)[:300]))


PADDLE_MIN_USD = Decimal("0.70")  # Paddle can not charge less than 70 cents


def provider_ready(usd=None):
    """Payment methods shown at checkout."""
    e = os.environ.get
    return {
        "paddle": bool(e("PADDLE_API_KEY") and e("PADDLE_CLIENT_TOKEN") and (usd is None or Decimal(str(usd)) >= PADDLE_MIN_USD)),
        "usdt": bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", USDT_WALLET)),
    }


# ---- Paddle (Paddle Billing): card payments on Paddle's secure checkout. Paddle is the seller of record.
def paddle_base():
    return "https://api.paddle.com" if os.environ.get("PADDLE_ENV", "sandbox") == "live" else "https://sandbox-api.paddle.com"


def paddle_headers():
    return {"Authorization": "Bearer " + os.environ["PADDLE_API_KEY"], "Accept": "application/json"}


def paddle_start(order):
    cents = str(int((Decimal(order["usd"]) * 100).to_integral_value()))
    code, r = _http("POST", paddle_base() + "/transactions", paddle_headers(), data={
        "items": [{"quantity": 1, "price": {
            "name": "ISS " + order["plan"], "description": "ISS %s license, order %s" % (order["plan"], order["id"]),
            "tax_mode": "external", "unit_price": {"amount": cents, "currency_code": "USD"},
            "product": {"name": "ISS " + order["plan"], "description": "ISS security license", "tax_category": "standard"}}}],
        "collection_mode": "automatic", "currency_code": "USD",
        "custom_data": {"order_id": order["id"]},
        "checkout": {"url": SITE_URL + "/pay/paddle"}})
    d = r.get("data") or {}
    url = (d.get("checkout") or {}).get("url")
    if not d.get("id") or not url:
        err = r.get("error") or {}
        _plog("paddle", "create", {"http": code, "code": err.get("code"), "detail": err.get("detail")})
        raise PayError("Paddle could not start the payment.")
    return d["id"], url


def paddle_finish(order, txn):
    if not txn or txn != order["provider_ref"]:
        raise PayError("This Paddle payment does not match the order.")
    code, r = _http("GET", paddle_base() + "/transactions/" + urllib.parse.quote(txn), paddle_headers())
    d = r.get("data") or {}
    if d.get("status") not in ("completed", "paid"):
        _plog("paddle", "verify", {"http": code, "status": d.get("status")})
        raise PayError("Paddle has not confirmed this payment yet. Wait a minute and press Check payment.")
    if (d.get("custom_data") or {}).get("order_id") != order["id"] or d.get("currency_code") != "USD":
        raise PayError("This Paddle payment does not match the order.")
    totals = (d.get("details") or {}).get("totals") or {}
    try:
        ok = Decimal(str(totals.get("subtotal", "0"))) - Decimal(str(totals.get("discount") or "0")) >= Decimal(order["usd"]) * 100
    except Exception:
        ok = False
    if not ok:
        raise PayError("The Paddle payment amount does not match the order.")
    return d["id"]


def order_price(plan, cycle):
    """(cycle, usd, bdt, days) for a plan. The 1-Day plan costs exactly 1 BDT."""
    p = PLANS[plan]
    if p.get("days"):
        return "day", _price(p["monthly"]), float(p["bdt"]), int(p["days"])
    if cycle == "yearly":
        usd = _price(p["yearly"])
        return "yearly", usd, round(usd * BDT_PER_USD, 2), 365
    usd = _price(p["monthly"])
    return "monthly", usd, round(usd * BDT_PER_USD, 2), 30


# ---- USDT on BNB Smart Chain
def _rpc(method, params):
    for url in BSC_RPCS:
        try:
            code, r = _http("POST", url, data={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=15)
        except PayError:
            continue
        if "result" in r:
            return r["result"]
    raise PayError("Could not read the BNB Smart Chain right now. Please try again in a minute.")


def usdt_start(db, order):
    """Give the order its own exact amount (price + 0.001 to 0.099) so each payment can be matched to one order."""
    base = Decimal(order["usd"])
    cutoff = (datetime.utcnow() - timedelta(hours=USDT_ORDER_HOURS)).strftime("%Y-%m-%d %H:%M")
    taken = {r[0] for r in db.execute("SELECT usd FROM orders WHERE provider='usdt' AND status='pending' AND created>=?", (cutoff,))}
    free = [str((base + Decimal(k) / 1000).quantize(Decimal("0.001"))) for k in range(1, 100)]
    free = [a for a in free if a not in taken]
    if not free:
        raise PayError("Too many open USDT orders right now. Please try again later.")
    db.execute("UPDATE orders SET usd=? WHERE id=?", (secrets.choice(free), order["id"]))
    db.commit()
    return "", "/order/" + order["id"]


def usdt_finish(order, txhash):
    created = datetime.strptime(order["created"], "%Y-%m-%d %H:%M")
    if datetime.utcnow() - created > timedelta(hours=USDT_ORDER_HOURS):
        raise PayError("This order has expired. Please start a new order.")
    txhash = (txhash or "").strip().lower()
    if not re.fullmatch(r"0x[0-9a-f]{64}", txhash):
        raise PayError("Paste the transaction hash: 0x followed by 64 letters and numbers.")
    rc = _rpc("eth_getTransactionReceipt", [txhash])
    if not rc:
        raise PayError("Transaction not found yet. Wait a minute and try again. It must be on BNB Smart Chain (BEP-20).")
    if rc.get("status") != "0x1":
        raise PayError("That transaction failed on the blockchain.")
    conf = int(_rpc("eth_blockNumber", []), 16) - int(rc["blockNumber"], 16) + 1
    if conf < USDT_CONFIRMATIONS:
        raise PayError("Waiting for blockchain confirmations (%d of %d). Try again in a minute." % (conf, USDT_CONFIRMATIONS))
    wallet, got = USDT_WALLET.lower()[2:], 0
    for lg in rc.get("logs", []):
        t = lg.get("topics", [])
        if (str(lg.get("address", "")).lower() == USDT_CONTRACT.lower() and len(t) == 3
                and t[0].lower() == TRANSFER_TOPIC and t[2][-40:].lower() == wallet):
            got += int(lg.get("data", "0x0"), 16)
    paid, want = Decimal(got) / Decimal(10 ** 18), Decimal(order["usd"])
    if got == 0:
        raise PayError("No USDT (BEP-20) transfer to our wallet was found in this transaction.")
    if not (want <= paid < want + Decimal("0.001")):
        raise PayError("This transaction sent %s USDT, but this order needs exactly %s USDT. "
                       "Contact support with order %s if you already paid." % (paid.normalize(), want, order["id"]))
    return txhash


# ---- orders and fulfilment
def fulfill_order(db, order, trx):
    """Mark the order paid and create the license, exactly once even if the provider calls twice."""
    try:
        cur = db.execute("UPDATE orders SET status='paid', trx=?, paid=? WHERE id=? AND status='pending'", (trx, now(), order["id"]))
    except sqlite3.IntegrityError:
        db.rollback()
        raise PayError("This payment was already used for another order.")
    if cur.rowcount == 0:
        db.commit()
        return
    plan = PLANS[order["plan"]]
    days = int(plan["days"]) if plan.get("days") else (365 if order["cycle"] == "yearly" else 30)
    key = "KEY-" + secrets.token_hex(6).upper()
    db.execute("INSERT INTO licenses(key,name,org,expiry,max_devices,plan,client_user,client_pwd_hash,created,must_change,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
               (key, order["name"], order["org"], (date.today() + timedelta(days=days)).isoformat(), plan_devices(order["plan"]),
                order["plan"], order["client_user"], order["pwd_hash"], now(), 0, "shop"))
    db.execute("UPDATE orders SET license_key=? WHERE id=?", (key, order["id"]))
    db.commit()
    send_discord_alert(f"💳 New paid order `{order['id']}` via {order['provider']} | **{order['name']}** ({order['org']}) | {order['plan']} | license `{key}`")


def set_order(db, oid, status):
    db.execute("UPDATE orders SET status=? WHERE id=? AND status='pending'", (status, oid))
    db.commit()


def get_order(db, oid):
    return db.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()


def verify_and_fulfill(db, order, **args):
    """Check the payment with the provider and, only if it really succeeded, issue the license."""
    if order["provider"] == "paddle":
        trx = paddle_finish(order, args.get("txn"))
    else:
        trx = usdt_finish(order, args.get("txid"))
    fulfill_order(db, order, trx)


CHECKOUT_TPL = r"""
<div class="top"><h2>Checkout</h2><a class="btn btn2" href="/#plans">&larr; Plans</a></div>
{% if error %}<p class="err">{{ error }}</p>{% endif %}
<div class="card"><h3>{{ plan }}</h3>
  <p class="m">{{ info }}</p>
  <form method="POST" action="/checkout"><input type="hidden" name="csrf" value="{{ csrf() }}"><input type="hidden" name="plan" value="{{ plan }}">
    {% if prices %}<p class="m">Billing</p>
    {% for c in prices %}<label style="display:block;margin:6px 0"><input type="radio" name="cycle" value="{{ c.key }}" {% if c.key == cycle %}checked{% endif %} style="width:auto"> {{ c.label }}</label>{% endfor %}{% endif %}
    <input name="name" placeholder="Your full name" value="{{ v.name }}" required maxlength="80">
    <input name="email" type="email" placeholder="Email" value="{{ v.email }}" required maxlength="120">
    <input name="org" placeholder="Organization (optional)" value="{{ v.org }}" maxlength="80">
    <input name="username" placeholder="Choose a portal username" value="{{ v.username }}" required minlength="3" maxlength="40">
    <input name="password" type="password" placeholder="Choose a portal password (min 8 characters)" required minlength="8" maxlength="100">
    <p class="m" style="margin-top:14px">Pay with</p>
    <button type="submit" name="provider" value="paddle" {% if not ready.paddle %}disabled title="Not available"{% endif %}>Card (Paddle)</button>
    <button type="submit" name="provider" value="usdt" {% if not ready.usdt %}disabled title="Not available yet"{% endif %}>USDT (BNB Smart Chain)</button>
  </form>
  <p class="m">You will be sent to the payment provider's own secure page to pay. ISS never sees or stores your card, wallet number, PIN or OTP.
  Card payments are handled by Paddle, our payment partner (charged in US dollars, tax is added at checkout). For USDT you get an exact amount and a wallet address on the next page (BNB Smart Chain BEP-20 only). After payment your license is created automatically.{% if paddle_note %} {{ paddle_note }}{% endif %}</p>
</div>
"""


def checkout_page(plan, cycle="monthly", values=None, error=""):
    p = PLANS[plan]
    cycle, usd, bdt, days = order_price(plan, cycle)
    if p.get("days"):
        prices, info = None, "Price: %s (about ৳%s) for %d day." % (p["monthly"], p["bdt"], days)
    else:
        prices = []
        for k, label in (("monthly", "Monthly"), ("yearly", "Yearly")):
            _, u, b, _d = order_price(plan, k)
            prices.append({"key": k, "label": "%s: $%.2f (about ৳%s)" % (label, u, "{:,.2f}".format(b))})
        info = ""
    v = {"name": "", "email": "", "org": "", "username": ""}
    v.update(values or {})
    note = "" if usd >= float(PADDLE_MIN_USD) else "Card payment needs at least $0.70, so this plan can only be paid with USDT."
    return page("Checkout", CHECKOUT_TPL, plan=plan, cycle=cycle, prices=prices, info=info, v=v,
                ready=provider_ready(usd), paddle_note=note, error=error)


@app.route("/checkout", methods=["GET", "POST"])
@limiter.limit("30 per hour")
def checkout():
    plan = (request.values.get("plan") or "").strip()
    if plan not in PLANS:
        return redirect("/#plans")
    if request.method == "GET":
        return checkout_page(plan, request.args.get("cycle", "monthly"))
    f = request.form
    vals = {k: f.get(k, "").strip() for k in ("name", "email", "org", "username")}
    cycle = f.get("cycle", "monthly")
    provider = f.get("provider", "")
    password = f.get("password", "")
    ready = provider_ready(order_price(plan, cycle)[1])
    if provider not in ready or not ready[provider]:
        return checkout_page(plan, cycle, vals, "That payment method is not available yet.")
    if len(vals["name"]) < 2 or "@" not in vals["email"] or len(vals["username"]) < 3 or len(password) < 8:
        return checkout_page(plan, cycle, vals, "Please fill every field. The password needs at least 8 characters.")
    cycle, usd, bdt, days = order_price(plan, cycle)
    db = get_db()
    oid = "ISS" + secrets.token_hex(7).upper()
    db.execute("INSERT INTO orders(id,plan,cycle,usd,bdt,provider,status,name,email,org,client_user,pwd_hash,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (oid, plan, cycle, "%.2f" % usd, "%.2f" % bdt, provider, "pending", vals["name"], vals["email"],
                vals["org"] or vals["name"], vals["username"], generate_password_hash(password), now()))
    db.commit()
    order = get_order(db, oid)
    try:
        if provider == "paddle":
            ref, url = paddle_start(order)
        else:
            ref, url = usdt_start(db, order)
    except PayError as e:
        set_order(db, oid, "failed")
        return checkout_page(plan, cycle, vals, str(e))
    db.execute("UPDATE orders SET provider_ref=? WHERE id=?", (ref, oid))
    db.commit()
    return redirect(url)


def _finish_redirect(db, order, **args):
    if order["status"] == "pending":
        try:
            verify_and_fulfill(db, order, **args)
        except PayError as e:
            flash(str(e))
    return redirect("/order/" + order["id"])


PADDLE_TPL = r"""
<div class="top"><h2>Secure payment</h2></div>
<div class="card"><p class="m" id="pmsg">Opening the secure Paddle checkout...</p>
  <p class="m">Payments are processed by Paddle. ISS never sees your card details.</p></div>
<script src="https://cdn.paddle.com/paddle/v2/paddle.js"></script>
<script>
(function(){
var msg=document.getElementById('pmsg');
var txn=new URLSearchParams(location.search).get('_ptxn')||'';
if(!txn){msg.textContent='No payment found. Please start again from the plans page.';return}
if('{{ env }}'==='sandbox'){Paddle.Environment.set('sandbox')}
Paddle.Initialize({token:'{{ token }}',eventCallback:function(e){
  if(e.name==='checkout.completed'){msg.textContent='Payment received. Creating your license...';location.href='/pay/paddle/done?txn='+encodeURIComponent(txn)}
}});
})();
</script>
"""


@app.route("/pay/paddle")
@limiter.exempt
def pay_paddle():
    env = "production" if os.environ.get("PADDLE_ENV", "sandbox") == "live" else "sandbox"
    return page("Pay", PADDLE_TPL, token=os.environ.get("PADDLE_CLIENT_TOKEN", ""), env=env)


@app.route("/pay/paddle/done")
def pay_paddle_done():
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE provider='paddle' AND provider_ref=?", (request.args.get("txn", ""),)).fetchone()
    if not order:
        abort(404)
    return _finish_redirect(db, order, txn=order["provider_ref"])


@app.route("/webhooks/paddle", methods=["POST"])
@limiter.exempt
def paddle_webhook():
    """Paddle tells us a payment completed even if the buyer closed the browser. The signature is checked first."""
    secret = os.environ.get("PADDLE_WEBHOOK_SECRET", "")
    raw = request.get_data()
    parts = dict(x.split("=", 1) for x in request.headers.get("Paddle-Signature", "").split(";") if "=" in x)
    ts, h1 = parts.get("ts", ""), parts.get("h1", "")
    if not secret or not ts.isdigit() or abs(time.time() - int(ts)) > 300:
        return "bad request", 400
    if not hmac.compare_digest(hmac.new(secret.encode(), ts.encode() + b":" + raw, hashlib.sha256).hexdigest(), h1):
        return "bad signature", 400
    try:
        event = json.loads(raw.decode("utf-8"))
    except ValueError:
        return "bad request", 400
    if event.get("event_type") == "transaction.completed":
        d = event.get("data") or {}
        db = get_db()
        order = get_order(db, (d.get("custom_data") or {}).get("order_id", ""))
        if order and order["provider"] == "paddle" and order["status"] == "pending":
            try:
                verify_and_fulfill(db, order, txn=d.get("id", ""))
            except PayError as e:
                _plog("paddle", "webhook", {"order": order["id"], "error": str(e)})
    return "ok", 200


@app.route("/order/<oid>/usdt", methods=["POST"])
@limiter.limit("30 per hour")
def order_usdt(oid):
    db = get_db()
    order = get_order(db, oid)
    if not order or order["provider"] != "usdt":
        abort(404)
    if order["status"] == "pending":
        try:
            verify_and_fulfill(db, order, txid=request.form.get("txid", ""))
        except PayError as e:
            flash(str(e))
    return redirect("/order/" + oid)


@app.route("/order/<oid>/check", methods=["POST"])
@limiter.limit("20 per hour")
def order_check(oid):
    db = get_db()
    order = get_order(db, oid)
    if not order:
        abort(404)
    if order["status"] == "pending" and order["provider"] != "usdt" and order["provider_ref"]:
        try:
            verify_and_fulfill(db, order, txn=order["provider_ref"])
        except PayError as e:
            flash(str(e))
    return redirect("/order/" + oid)


ORDER_TPL = r"""
<div class="top"><h2>Your order</h2><a class="btn btn2" href="/">&larr; Home</a></div>
<div class="card">
{% if o.status == 'paid' %}
  <h3>Payment confirmed</h3>
  <p class="m">{{ o.plan }} | paid with {{ o.provider }} | reference {{ o.trx }}</p>
  <p>License key</p><p class="big" style="font-size:1.5rem"><code>{{ o.license_key }}</code></p>
  <p class="m">Valid until {{ expiry }}. Log in to the Client Portal with this license key, the username <b>{{ o.client_user }}</b> and the password you chose.</p>
  <a class="btn" href="/client-login">Open Client Portal</a>
{% elif o.status == 'pending' and o.provider == 'usdt' %}
  <h3>Pay with USDT</h3>
  <p class="m">Network: <b>BNB Smart Chain (BEP-20) only</b>. Money sent on any other network is lost.</p>
  <p>Send exactly</p><p class="big" style="font-size:1.6rem">{{ o.usd }} <small>USDT</small></p>
  <p class="m">The wallet must receive between {{ o.usd }} and {{ upper }} USDT. Exchanges such as Binance take their fee out of the amount, so add the fee and check that the receive amount equals {{ o.usd }}.</p>
  <p>To this address</p><p><code id="addr" style="word-break:break-all">{{ wallet }}</code></p>
  <button type="button" class="btn2" onclick="navigator.clipboard&&navigator.clipboard.writeText(document.getElementById('addr').textContent)">Copy address</button>
  <p class="m" style="margin-top:14px">After sending, wait about a minute, then paste the transaction hash (TxID) from your wallet or exchange.</p>
  <form method="POST" action="/order/{{ o.id }}/usdt"><input type="hidden" name="csrf" value="{{ csrf() }}">
    <input name="txid" placeholder="0x... transaction hash" required maxlength="80"><button type="submit">Verify payment</button></form>
{% elif o.status == 'pending' %}
  <h3>Waiting for payment confirmation</h3>
  <p class="m">We have not received the confirmation from {{ o.provider }} yet. If you already paid, press the button below.</p>
  <form method="POST" action="/order/{{ o.id }}/check"><input type="hidden" name="csrf" value="{{ csrf() }}"><button type="submit">Check payment now</button></form>
{% elif o.status == 'cancelled' %}
  <h3>Payment cancelled</h3><p class="m">Nothing was charged.</p><a class="btn" href="/checkout?plan={{ o.plan|urlencode }}">Try again</a>
{% else %}
  <h3>Payment not completed</h3><p class="m">The payment was not confirmed, so no license was created. If money was taken, contact support with the reference {{ o.id }}.</p>
  <a class="btn" href="/checkout?plan={{ o.plan|urlencode }}">Try again</a>
{% endif %}
</div>
"""


@app.route("/order/<oid>")
def order_status(oid):
    db = get_db()
    order = get_order(db, oid)
    if not order:
        abort(404)
    lic = db.execute("SELECT expiry FROM licenses WHERE key=?", (order["license_key"],)).fetchone() if order["license_key"] else None
    upper = str((Decimal(order["usd"]) + Decimal("0.001")).quantize(Decimal("0.001"))) if order["provider"] == "usdt" else ""
    return page("Your order", ORDER_TPL, o=order, expiry=lic["expiry"] if lic else "", wallet=USDT_WALLET, upper=upper)


# ------------------------------------------------------------------
# Installable apps (PWA): the Admin panel and the Client portal can be installed
# on Windows, macOS, Linux and Android from their Download page
# ------------------------------------------------------------------
def _manifest(name, short, start, scope):
    body = json.dumps({
        "name": name, "short_name": short, "description": "International System Security (ISS)",
        "start_url": start, "scope": scope, "display": "standalone",
        "background_color": "#07090c", "theme_color": "#07090c",
        "icons": [{"src": "/pwa-icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
                  {"src": "/pwa-icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"}]})
    return Response(body, mimetype="application/manifest+json", headers={"Cache-Control": "no-cache"})


@app.route("/admin.webmanifest")
@limiter.exempt
def admin_manifest():
    return _manifest("ISS Admin Panel", "ISS Admin", "/admin", "/admin")


@app.route("/client.webmanifest")
@limiter.exempt
def client_manifest():
    return _manifest("ISS Client Portal", "ISS Client", "/client-dashboard", "/client")


@app.route("/pwa-sw.js")
@limiter.exempt
def pwa_sw():
    js = ("self.addEventListener('install',function(){self.skipWaiting()});"
          "self.addEventListener('activate',function(e){e.waitUntil(self.clients.claim())});"
          "self.addEventListener('fetch',function(e){if(e.request.method==='GET'){e.respondWith(fetch(e.request))}});")
    return Response(js, mimetype="application/javascript",
                    headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"})


_ICON_CACHE = {}


@app.route("/pwa-icon-<int:size>.png")
@limiter.exempt
def pwa_icon(size):
    if size not in (192, 512) or not PIL_OK:
        abort(404)
    if size not in _ICON_CACHE:
        canvas = Image.new("RGB", (size, size), (7, 9, 12))
        try:
            im = Image.open(io.BytesIO(LOGO_BYTES)).convert("RGBA")
            im.thumbnail((int(size * 0.8), int(size * 0.8)))
            canvas.paste(im, ((size - im.width) // 2, (size - im.height) // 2), im)
        except Exception:
            ImageDraw.Draw(canvas).text((size // 4, size // 3), "ISS", fill=(0, 217, 255), font=_font(size // 3))
        out = io.BytesIO()
        canvas.save(out, "PNG")
        _ICON_CACHE[size] = out.getvalue()
    return Response(_ICON_CACHE[size], mimetype="image/png", headers={"Cache-Control": "public, max-age=86400"})


DOWNLOAD_TPL = r"""
<h2>Download</h2>
<div class="card"><h3>{{ app_name }}</h3>
  <p class="m">Install it as an app. It opens in its own window with its own icon, like a normal program.</p>
  <button id="pwaBtn" type="button" disabled>Install app</button>
  <p class="m" id="pwaMsg">Checking this device...</p></div>
<div class="g2" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr))">
  <div class="card" data-os="windows"><h3>Windows</h3><p class="m">Open this page in Edge or Chrome and press Install app.</p></div>
  <div class="card" data-os="macos"><h3>macOS</h3><p class="m">Open this page in Chrome or Edge and press Install app.</p></div>
  <div class="card" data-os="linux"><h3>Linux</h3><p class="m">Open this page in Chrome, Chromium or Edge and press Install app.</p></div>
  <div class="card" data-os="android"><h3>Android</h3><p class="m">Open this page in Chrome and press Install app.</p></div>
</div>
<script>
(function(){
var btn=document.getElementById('pwaBtn'),msg=document.getElementById('pwaMsg'),ev=null;
var ua=navigator.userAgent;
var os=/Android/i.test(ua)?'android':/Windows/i.test(ua)?'windows':/Mac OS X|Macintosh/i.test(ua)?'macos':/Linux/i.test(ua)?'linux':'';
document.querySelectorAll('[data-os]').forEach(function(c){if(c.getAttribute('data-os')===os){c.style.borderColor='var(--cy)'}});
if(window.matchMedia('(display-mode: standalone)').matches||navigator.standalone){msg.textContent='This app is already installed on this device.';return}
if('serviceWorker' in navigator){navigator.serviceWorker.register('/pwa-sw.js',{scope:'{{ scope }}'}).catch(function(){})}
window.addEventListener('beforeinstallprompt',function(e){e.preventDefault();ev=e;btn.disabled=false;msg.textContent='Ready to install on this device.'});
window.addEventListener('appinstalled',function(){msg.textContent='Installed. Open it from your apps.';btn.disabled=true});
btn.addEventListener('click',function(){if(!ev)return;ev.prompt();ev.userChoice.then(function(){ev=null;btn.disabled=true})});
setTimeout(function(){if(!ev){msg.textContent='If the button stays off, open your browser menu and choose Install app or Add to Home screen.'}},2500);
})();
</script>
"""


@app.route("/admin/download")
@admin_required
def admin_download():
    return page("Download", DOWNLOAD_TPL, shell=admin_shell("download", "Download"),
                app_name="ISS Admin Panel", scope="/admin")


CLIENT_NAV = [
    {"key": "overview", "href": "/client-dashboard", "label": "Dashboard"},
    {"key": "devices", "href": "/client/devices", "label": "Add Device"},
    {"key": "account", "href": "/client/account", "label": "Users"},
    {"key": "auth", "href": "/client/auth", "label": "Auth"},
    {"key": "scan", "href": "/client/scan", "label": "Scan"},
    {"key": "download", "href": "/client/download", "label": "Download"},
    {"key": "reports", "href": "/client/reports", "label": "Reports"},
    {"key": "tickets", "href": "/client/tickets", "label": "Support"},
]


def client_shell(active, title=None):
    return {"nav": CLIENT_NAV, "active": active, "logout": "/client-logout", "home": "/",
            "title": title or active.capitalize(), "manifest": "/client.webmanifest"}


OVERVIEW_TPL = r"""
<h2>Dashboard</h2>
<div class="card">
  <form method="POST" action="/client/activate-device" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf() }}">
    <button class="status" type="submit"><span class="dot"></span>Active now</button></form>
  <span class="m">&nbsp;Press to add this device to your license.</span>
  <h1 style="margin-top:14px">{{ v.org }}</h1>
  <p class="m">{{ v.plan }} &middot; expires {{ v.expiry }} ({{ days }} days left)</p>
</div>
<div class="g2" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">
  <div class="card"><div class="big">{{ used }} <small>of {{ limit_text }}</small></div><p class="m">Devices active</p></div>
  <div class="card"><div class="big">{{ today_count }}</div><p class="m">Threats blocked today</p></div>
  <div class="card"><div class="big">{{ open_tickets }}</div><p class="m">Open support tickets</p></div>
</div>
<div class="g2">
  <a class="card" href="/client/devices" style="text-decoration:none;color:inherit;display:block"><h3>Add Device &rarr;</h3><p class="m">Add a device, see all devices and download config.json.</p></a>
  <a class="card" href="/client/reports" style="text-decoration:none;color:inherit;display:block"><h3>Reports &rarr;</h3><p class="m">Today and this week's blocked threats, plus plan details.</p></a>
</div>
"""


DEVICES_TPL = r"""
<h2>Add Device</h2>
<div class="g2">
  <div class="card"><h3>Device slots</h3>
    <div class="big">{{ used }} <small>of {{ limit_text }}</small></div>
    {% if limit %}<div class="meter"><i style="width:{{ pct }}%"></i></div>{% endif %}
    <p class="m">{% if limit and used >= limit %}All slots are in use. Remove a device or upgrade your plan.{% elif limit %}{{ limit - used }} more device(s) can be added.{% else %}This plan has no device limit.{% endif %}</p>
    <form method="POST" action="/client/activate-device" style="margin-top:10px"><input type="hidden" name="csrf" value="{{ csrf() }}">
      <button class="status" type="submit"><span class="dot"></span>Active now</button></form>
    <p class="m">The first device added becomes the admin device.</p></div>
  <div class="card"><h3>Setup</h3>
    <p class="m">Put config.json in your ISS agent folder and start the agent. Devices register themselves.</p>
    <a class="btn" href="/client/config.json">Download config.json</a>
    <p class="m">License key: <code>{{ v.key }}</code></p></div>
</div>

<div class="card"><h3>All devices</h3>
  {% if devices %}<table><tr><th>Device</th><th>Role</th><th>Status</th><th>Last seen (UTC)</th><th></th></tr>
  {% for d in devices %}<tr {% if d.mine %}class="cur"{% endif %}><td>{{ d.name }}{% if d.mine %} <span class="m">(this device)</span>{% endif %}</td>
    <td>{% if d.is_admin %}<span class="pill g">admin</span>{% else %}<span class="pill">device</span>{% endif %}</td>
    <td>{% if d.online %}<span class="pill g">online</span>{% else %}<span class="pill">offline</span>{% endif %}</td><td>{{ d.last_seen }}</td>
    <td>{% if can_manage %}{% if not d.is_admin %}<form method="POST" action="/client/devices/make-admin" style="display:inline" onsubmit="return confirm('Give admin rights to this device?')">
      <input type="hidden" name="csrf" value="{{ csrf() }}"><input type="hidden" name="id" value="{{ d.id }}"><button class="btn2">Make admin</button></form> {% endif %}
      <form method="POST" action="/client/devices/remove" style="display:inline" onsubmit="return confirm('Disconnect this device?')">
      <input type="hidden" name="csrf" value="{{ csrf() }}"><input type="hidden" name="id" value="{{ d.id }}"><button class="btn2">Disconnect</button></form>{% endif %}</td></tr>{% endfor %}</table>
  {% if not can_manage %}<p class="m">Only an admin device can disconnect devices or give admin rights.</p>{% endif %}
  {% else %}<p class="m">No device yet. Press "Active now" or start the ISS agent on a PC.</p>{% endif %}</div>
"""


REPORTS_TPL = r"""
<h2>Reports</h2>
<div class="card"><div class="g2">
    <div><h4 style="margin:0 0 6px">Today</h4><p class="big" style="font-size:1.8rem">{{ rep_today.count }} <small>blocked</small></p>
      <div class="bars">{% for b in rep_today.bars %}<div class="bar" style="--h:{{ b.pct }}%" title="{{ b.label }}: {{ b.count }}"></div>{% endfor %}</div>
      <p class="m">By hour, last 24h</p></div>
    <div><h4 style="margin:0 0 6px">This week</h4><p class="big" style="font-size:1.8rem">{{ rep_week.count }} <small>blocked</small></p>
      <div class="bars">{% for b in rep_week.bars %}<div class="bar" style="--h:{{ b.pct }}%" title="{{ b.label }}: {{ b.count }}"></div>{% endfor %}</div>
      <p class="m">By day, last 7 days</p></div>
  </div>
  <p class="m" style="margin-top:14px">Check this report from Discord any time: run <code>/report</code> or <code>/weekly_report</code> and enter your license key.</p></div>
<div class="card"><h3>Recent activity</h3>
  {% if events %}<table><tr><th>Time (UTC)</th><th>Device</th><th>Result</th></tr>
  {% for e in events %}<tr><td>{{ e.created }}</td><td>{{ e.dname or 'Unknown' }}</td><td>
    {% if e.type == 'test_blocked' %}<span class="pill g">Test virus blocked</span>{% elif e.type == 'ransomware_pattern_blocked' %}<span class="pill r">Mass-encryption pattern blocked</span> {{ e.detail }}{% else %}<span class="pill g">Threat blocked</span> {{ e.detail }}{% endif %}</td></tr>{% endfor %}</table>
  {% else %}<p class="m">No activity yet.</p>{% endif %}</div>
<div class="card"><h3>Plans</h3><table><tr><th>Plan</th><th>Devices</th><th>Monthly</th><th>Yearly</th></tr>
  {% for name, p in plans.items() %}<tr {% if name == v.plan %}class="cur"{% endif %}><td>{{ name }}</td><td>{{ 'Unlimited' if p.devices == 0 else p.devices }}</td><td>{{ p.monthly }}</td><td>{{ p.yearly }}</td></tr>{% endfor %}</table>
  <p class="m">To change plan or for custom needs, open a support ticket.</p></div>
"""


TICKETS_TPL = r"""
<h2>Support</h2>
<div class="card"><h3>New support ticket</h3>
  <form method="POST" action="/client/tickets/new"><input type="hidden" name="csrf" value="{{ csrf() }}">
    <input name="subject" placeholder="Subject" maxlength="120" required>
    <textarea name="body" rows="3" placeholder="Describe your problem" required></textarea>
    <button type="submit">Submit ticket</button></form></div>
<div class="card"><h3>My tickets</h3><table><tr><th>#</th><th>Subject</th><th>Status</th><th>Date</th></tr>
  {% for t in tickets %}<tr><td><a href="/client/tickets/{{ t.id }}">#{{ t.id }}</a></td><td>{{ t.subject }}</td><td>{{ t.status }}</td><td>{{ t.created }}</td></tr>
  {% else %}<tr><td colspan="4" class="m">No tickets yet.</td></tr>{% endfor %}</table></div>
"""


def is_online(last_seen):
    try:
        return (datetime.utcnow() - datetime.strptime(last_seen, "%Y-%m-%d %H:%M")).total_seconds() < 240
    except (TypeError, ValueError):
        return False


def hour_report(db, key):
    now_dt = datetime.utcnow()
    counts = [0] * 24
    for r in db.execute("SELECT created FROM events WHERE license_key=? AND type IN ('threat_blocked','test_blocked','ransomware_pattern_blocked') AND created>=?",
                        (key, (now_dt - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M"))).fetchall():
        try:
            dt = datetime.strptime(r["created"], "%Y-%m-%d %H:%M")
        except ValueError:
            continue
        age_h = int((now_dt - dt).total_seconds() // 3600)
        if 0 <= age_h < 24:
            counts[23 - age_h] += 1
    m = max(counts) or 1
    bars = [{"pct": int(c * 100 / m) if c else 4, "count": c, "label": f"{23-i}h ago"} for i, c in enumerate(counts)]
    return {"count": sum(counts), "bars": bars}


def day_report(db, key):
    today = date.today()
    counts = [0] * 7
    for r in db.execute("SELECT created FROM events WHERE license_key=? AND type IN ('threat_blocked','test_blocked','ransomware_pattern_blocked') AND created>=?",
                        (key, (today - timedelta(days=6)).isoformat())).fetchall():
        try:
            d = datetime.strptime(r["created"][:10], "%Y-%m-%d").date()
        except ValueError:
            continue
        age_d = (today - d).days
        if 0 <= age_d < 7:
            counts[6 - age_d] += 1
    m = max(counts) or 1
    bars = [{"pct": int(c * 100 / m) if c else 4, "count": c, "label": (today - timedelta(days=6 - i)).strftime("%a")} for i, c in enumerate(counts)]
    return {"count": sum(counts), "bars": bars}


def client_common():
    """Shared data every client page needs: device list, events, slot usage."""
    db = get_db()
    key = g.lic["key"]
    devices = [dict(d, online=is_online(d["last_seen"])) for d in db.execute(
        "SELECT * FROM devices WHERE license_key=? ORDER BY last_seen DESC", (key,)).fetchall()]
    events = db.execute("""SELECT e.*, d.name AS dname FROM events e
        LEFT JOIN devices d ON d.device_id=e.device_id AND d.license_key=e.license_key
        WHERE e.license_key=? ORDER BY e.id DESC LIMIT 10""", (key,)).fetchall()
    limit = device_limit(g.lic)
    used = len(devices)
    pct = min(100, int(used * 100 / limit)) if limit else 0
    return db, key, devices, events, limit, used, pct


@app.route("/client-dashboard")
@client_required
def client_dashboard():
    db, key, devices, events, limit, used, pct = client_common()
    try:
        days = (date.fromisoformat(g.lic["expiry"]) - date.today()).days
    except ValueError:
        days = 0
    open_tickets = db.execute("SELECT COUNT(*) FROM tickets WHERE license_key=? AND status='open'", (key,)).fetchone()[0]
    today_count = hour_report(db, key)["count"]
    return page("Dashboard", OVERVIEW_TPL, shell=client_shell("overview", "Dashboard"), v=g.lic,
                limit=limit, limit_text=limit_text(limit), used=used, days=days,
                today_count=today_count, open_tickets=open_tickets)


@app.route("/client/devices")
@client_required
def client_devices():
    db, key, devices, events, limit, used, pct = client_common()
    mine = web_device_id()
    has_admin = any(d["is_admin"] for d in devices)
    can_manage = (not has_admin) or any(d["is_admin"] and d["device_id"] == mine for d in devices)
    for d in devices:
        d["mine"] = bool(mine) and d["device_id"] == mine
    return page("Add Device", DEVICES_TPL, shell=client_shell("devices", "Add Device"), v=g.lic,
                devices=devices, limit=limit, limit_text=limit_text(limit), used=used, pct=pct,
                can_manage=can_manage)


@app.route("/client/reports")
@client_required
def client_reports():
    db, key, devices, events, limit, used, pct = client_common()
    return page("Reports", REPORTS_TPL, shell=client_shell("reports", "Reports"), v=g.lic, events=events,
                rep_today=hour_report(db, key), rep_week=day_report(db, key), plans=PLANS)


@app.route("/client/tickets")
@client_required
def client_tickets():
    tickets = get_db().execute("SELECT * FROM tickets WHERE license_key=? ORDER BY id DESC", (g.lic["key"],)).fetchall()
    return page("Support", TICKETS_TPL, shell=client_shell("tickets", "Support"), tickets=tickets)


def web_device_id():
    dev = request.cookies.get("iss_dev")
    return ("web-" + dev) if dev else None


def device_admin_state(db, key):
    """(license has an admin device, this browser is an admin device)"""
    rows = db.execute("SELECT device_id FROM devices WHERE license_key=? AND is_admin=1", (key,)).fetchall()
    mine = web_device_id()
    return bool(rows), bool(mine) and any(r["device_id"] == mine for r in rows)


@app.route("/client/devices/remove", methods=["POST"])
@client_required
def client_device_remove():
    db = get_db()
    key = g.lic["key"]
    has_admin, is_admin = device_admin_state(db, key)
    if has_admin and not is_admin:
        flash("Only an admin device can disconnect devices.")
        return redirect(url_for("client_devices"))
    row = db.execute("SELECT * FROM devices WHERE id=? AND license_key=?", (request.form.get("id", ""), key)).fetchone()
    if row and row["is_admin"]:
        total = db.execute("SELECT COUNT(*) FROM devices WHERE license_key=?", (key,)).fetchone()[0]
        admins = db.execute("SELECT COUNT(*) FROM devices WHERE license_key=? AND is_admin=1", (key,)).fetchone()[0]
        if total > 1 and admins <= 1:
            flash("This is the only admin device. Make another device admin first.")
            return redirect(url_for("client_devices"))
    db.execute("DELETE FROM devices WHERE id=? AND license_key=?", (request.form.get("id", ""), key))
    db.commit()
    return redirect(url_for("client_devices"))


@app.route("/client/devices/make-admin", methods=["POST"])
@client_required
def client_device_make_admin():
    db = get_db()
    key = g.lic["key"]
    has_admin, is_admin = device_admin_state(db, key)
    if has_admin and not is_admin:
        flash("Only an admin device can give admin rights.")
    else:
        db.execute("UPDATE devices SET is_admin=1 WHERE id=? AND license_key=?", (request.form.get("id", ""), key))
        db.commit()
        flash("Admin rights given to the device.")
    return redirect(url_for("client_devices"))


@app.route("/client/config.json")
@client_required
def client_config():
    body = json.dumps({"license_key": g.lic["key"]}, indent=2)
    return Response(body, mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=config.json"})


# ------------------------------------------------------------------
# Agent API: license and device limit checks
# ------------------------------------------------------------------
def api_authorize(data):
    key = str(data.get("license_key", "")).strip()
    dev = str(data.get("device_id", "")).strip()[:64]
    name = str(data.get("device_name", "")).strip()[:60]
    if not key or not dev:
        return None, ({"status": "error", "message": "license_key and device_id are required"}, 400)
    conn = connect()
    try:
        lic = conn.execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
        if not lic:
            return None, ({"status": "denied", "message": "Invalid license key"}, 403)
        if lic["expiry"] < date.today().isoformat():
            return None, ({"status": "denied", "message": "License expired. Please renew."}, 403)
        limit = device_limit(lic)
        used = conn.execute("SELECT COUNT(*) FROM devices WHERE license_key=?", (key,)).fetchone()[0]
        known = conn.execute("SELECT 1 FROM devices WHERE license_key=? AND device_id=?", (key, dev)).fetchone()
        if known:
            conn.execute("UPDATE devices SET last_seen=?, name=COALESCE(NULLIF(?, ''), name) WHERE license_key=? AND device_id=?",
                         (now(), name, key, dev))
        elif limit and used >= limit:
            return None, ({"status": "denied",
                           "message": f"Device limit reached ({used} of {limit}). Remove a device in the Client Portal or upgrade your plan."}, 403)
        else:
            conn.execute("INSERT INTO devices(license_key,device_id,name,first_seen,last_seen) VALUES(?,?,?,?,?)",
                         (key, dev, name or "Unnamed PC", now(), now()))
            used += 1
        conn.commit()
        return {"lic": dict(lic), "used": used, "limit": limit, "device": name}, None
    finally:
        conn.close()


@app.route("/api/activate", methods=["POST"])
@limiter.limit("30 per minute")
def api_activate():
    info, err = api_authorize(request.get_json(silent=True) or {})
    if err:
        return err
    return {"status": "active", "plan": info["lic"]["plan"], "expiry": info["lic"]["expiry"],
            "devices_used": info["used"], "devices_max": limit_text(info["limit"])}


@app.route("/scan", methods=["POST"])
@limiter.limit("120 per minute")
def api_scan():
    data = request.get_json(silent=True) or {}
    info, err = api_authorize(data)
    if err:
        return {"status": err[0]["status"], "message": err[0]["message"]}, err[1]
    h = str(data.get("hash", "")).strip().lower()
    conn = connect()
    t = conn.execute("SELECT name FROM threats WHERE hash=?", (h,)).fetchone()
    conn.close()
    if t:
        send_discord_alert(f"🚨 Threat `{t['name']}` found: {data.get('filename','file')} on {info['device']} ({info['lic']['org']})")
        return {"status": "threat", "message": f"Threat detected: {t['name']}"}
    return {"status": "clean", "message": "File is clean"}


@app.route("/client-logout", methods=["POST"])
def client_logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/client/tickets/new", methods=["POST"])
@client_required
def client_ticket_new():
    subject = request.form.get("subject", "").strip()[:120]
    body = request.form.get("body", "").strip()[:2000]
    if subject and body:
        db = get_db()
        cur = db.execute("INSERT INTO tickets(license_key,subject,created) VALUES(?,?,?)",
                         (g.lic["key"], subject, now()))
        db.execute("INSERT INTO ticket_messages(ticket_id,sender,body,created) VALUES(?,?,?,?)",
                   (cur.lastrowid, "client", body, now()))
        db.commit()
        send_discord_alert(f"🎫 New ticket #{cur.lastrowid} from **{g.lic['org']}**: {subject}")
        return redirect(url_for("client_ticket", tid=cur.lastrowid))
    return redirect(url_for("client_dashboard"))


@app.route("/client/tickets/<int:tid>", methods=["GET", "POST"])
@client_required
def client_ticket(tid):
    db = get_db()
    t = db.execute("SELECT * FROM tickets WHERE id=? AND license_key=?",
                   (tid, g.lic["key"])).fetchone()
    if not t:
        abort(404)
    if request.method == "POST" and t["status"] == "open":
        body = request.form.get("body", "").strip()[:2000]
        if body:
            db.execute("INSERT INTO ticket_messages(ticket_id,sender,body,created) VALUES(?,?,?,?)",
                       (tid, "client", body, now()))
            db.commit()
        return redirect(url_for("client_ticket", tid=tid))
    msgs = db.execute("SELECT * FROM ticket_messages WHERE ticket_id=? ORDER BY id", (tid,)).fetchall()
    return page("Ticket #%d" % tid, """
    <h2>#{{ t.id }} - {{ t.subject }} ({{ t.status }})</h2>
    <p class="m"><a href="/client/tickets">&larr; All tickets</a></p>
    <div class="card">{% for m in msgs %}
      <div class="{{ 'them' if m.sender=='support' else 'me' }}"><b>{{ m.sender }}</b> · {{ m.created }}<br>{{ m.body }}</div>
    {% endfor %}</div>
    {% if t.status == 'open' %}
    <div class="card"><form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
      <textarea name="body" rows="3" placeholder="Write a message..." required></textarea>
      <button type="submit">Send</button></form></div>{% endif %}""", shell=client_shell("tickets", "Ticket #%d" % tid), t=t, msgs=msgs)


# ------------------------------------------------------------------
# Accounts: one Login for everyone, Register for customers
# ------------------------------------------------------------------
def auth_nav():
    """Compact pill buttons for the always-visible quick-access bar next to the
    hamburger icon (NOT inside the hamburger menu, so people do not have to go
    looking for Login, Register or their portal)."""
    if session.get("is_admin"):
        items = '<a class="qbtn solid" href="/admin">Admin Portal</a>'
    elif session.get("agent_id"):
        items = '<a class="qbtn solid" href="/agent">Agent Dashboard</a><a class="qbtn" href="/admin">Admin Portal (staff)</a>'
    elif session.get("user_id"):
        items = f'<a class="qbtn" href="/account">{escape(session.get("user_name", "Account"))}</a>'
    else:
        return '<a class="qbtn" href="/login">Login</a><a class="qbtn solid" href="/register">Register</a>'
    return items + (f'<form class="qform" method="POST" action="/logout">'
                    f'<input type="hidden" name="csrf" value="{csrf_token()}"><button class="qbtn">Logout</button></form>')


AUTH_TPL = r"""
<div class="card" style="max-width:380px;margin:50px auto"><h3>{{ heading }}</h3>
  {% if err %}<p class="err">{{ err }}</p>{% endif %}
  <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
    {% if register %}<input name="name" placeholder="Full name" required>{% endif %}
    <input name="email" type="email" placeholder="Email" required>
    <input name="password" type="password" placeholder="Password{% if register %} (min 8 characters){% endif %}" required>
    <button type="submit" style="width:100%">{{ heading }}</button></form>
  <p class="m" style="text-align:center;margin:14px 0">or</p>
  <a class="btn btn2" href="/auth/google" style="display:block;text-align:center">{% if register %}Sign up with Google{% else %}Sign in with Google{% endif %}</a>
  <p class="m">{% if register %}Already have an account? <a href="/login">Login</a>{% else %}New here? <a href="/register">Register</a>{% endif %}
  &middot; <a href="/">Home</a> &middot; <a href="/client-login">Client Portal</a></p></div>
"""


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    err = ""
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:60]
        email = request.form.get("email", "").strip().lower()[:120]
        pwd = request.form.get("password", "")
        db = get_db()
        if not name or "@" not in email:
            err = "Enter your name and a valid email."
        elif len(pwd) < 8:
            err = "Password must be at least 8 characters."
        elif db.execute("SELECT 1 FROM users WHERE email=? UNION SELECT 1 FROM agents WHERE lower(email)=? UNION SELECT 1 FROM admins WHERE lower(email)=?",
                        (email, email, email)).fetchone():
            err = "This email is already registered."
        else:
            cur = db.execute("INSERT INTO users(email,name,password_hash,created) VALUES(?,?,?,?)",
                             (email, name, generate_password_hash(pwd), now()))
            db.commit()
            session.clear()
            session["user_id"], session["user_name"] = cur.lastrowid, name
            return redirect(url_for("account"))
    return page("Register", AUTH_TPL, heading="Register", register=True, err=err)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    err = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pwd = request.form.get("password", "")
        db = get_db()
        a = db.execute("SELECT * FROM admins WHERE lower(email)=?", (email,)).fetchone()
        ag = db.execute("SELECT * FROM agents WHERE lower(email)=?", (email,)).fetchone()
        u = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if a and check_password_hash(a["password_hash"], pwd):
            session.clear()
            session["is_admin"], session["admin_email"] = True, a["email"]
            return redirect(url_for("home"))
        if ag and check_password_hash(ag["password_hash"], pwd):
            session.clear()
            session["agent_id"] = ag["id"]
            return redirect(url_for("agent_dashboard"))
        if u and check_password_hash(u["password_hash"], pwd):
            session.clear()
            session["user_id"], session["user_name"] = u["id"], u["name"]
            return redirect(url_for("account"))
        err = "Wrong email or password."
    return page("Login", AUTH_TPL, heading="Login", register=False, err=err)


GOOGLE_REDIRECT = SITE_URL + "/auth/google/callback"


def _login_error(msg):
    flash(msg)
    return redirect(url_for("login"))


@app.route("/auth/google")
@limiter.limit("20 per hour")
def google_start():
    cid = os.environ.get("GOOGLE_CLIENT_ID")
    if not cid or not os.environ.get("GOOGLE_CLIENT_SECRET"):
        return _login_error("Google sign-in is not set up yet.")
    state = secrets.token_urlsafe(24)
    session["g_state"] = state
    return redirect("https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode({
        "client_id": cid, "redirect_uri": GOOGLE_REDIRECT, "response_type": "code",
        "scope": "openid email profile", "state": state, "prompt": "select_account"}))


@app.route("/auth/google/callback")
@limiter.limit("20 per hour")
def google_callback():
    state = session.pop("g_state", "")
    code = request.args.get("code", "")
    if request.args.get("error") or not code or not state or not secrets.compare_digest(state, request.args.get("state", "")):
        return _login_error("Google sign-in was cancelled or failed. Please try again.")
    try:
        _, tok = _http("POST", "https://oauth2.googleapis.com/token", form={
            "code": code, "client_id": os.environ["GOOGLE_CLIENT_ID"], "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "redirect_uri": GOOGLE_REDIRECT, "grant_type": "authorization_code"})
        if not tok.get("access_token"):
            return _login_error("Google sign-in failed. Please try again.")
        _, info = _http("GET", "https://openidconnect.googleapis.com/v1/userinfo",
                        {"Authorization": "Bearer " + tok["access_token"]})
    except (PayError, KeyError):
        return _login_error("Could not reach Google. Please try again.")
    email = str(info.get("email", "")).strip().lower()[:120]
    if not email or info.get("email_verified") is not True:
        return _login_error("Your Google email is not verified.")
    db = get_db()
    if db.execute("SELECT 1 FROM admins WHERE lower(email)=? UNION SELECT 1 FROM agents WHERE lower(email)=?", (email, email)).fetchone():
        return _login_error("This email belongs to the ISS team. Please log in with your password.")
    u = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not u:
        name = (str(info.get("name", "")).strip() or email.split("@")[0])[:60]
        cur = db.execute("INSERT INTO users(email,name,password_hash,created) VALUES(?,?,?,?)",
                         (email, name, generate_password_hash(secrets.token_hex(32)), now()))
        db.commit()
        u = db.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
    session.clear()
    session["user_id"], session["user_name"] = u["id"], u["name"]
    return redirect(url_for("account"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/account")
def account():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    return page("My Account", """
    <h2>Welcome, {{ name }}</h2><p class="m">Thank you for joining ISS.</p>
    <div class="card"><h3>Quick links</h3>
      <a class="btn" href="/#plans">View plans</a> <a class="btn btn2" href="/verify">Verify a seller</a>
      <a class="btn btn2" href="/client-login">Client Portal</a></div>
    <div class="card"><h3>How to buy</h3><p class="m">Join our Discord, open the ISS Cyber Defence Suite category and click Buy Now. Always ask the seller for a Trade Certificate and verify it first.</p></div>
    """, name=session.get("user_name", ""))


# ------------------------------------------------------------------
# Trade certificates (image) + exact verification
# ------------------------------------------------------------------
if PIL_OK:
    Image.MAX_IMAGE_PIXELS = 20_000_000


def _font(size):
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def make_certificate(c):
    W, H = 1600, 1100
    im = Image.new("RGB", (W, H), (7, 9, 12))
    d = ImageDraw.Draw(im)
    cy, am, tx, mu = (0, 217, 255), (255, 178, 36), (220, 230, 238), (127, 147, 163)
    for x in range(0, W, 64):
        d.line([(x, 0), (x, H)], fill=(14, 22, 30))
    for y in range(0, H, 64):
        d.line([(0, y), (W, y)], fill=(14, 22, 30))
    d.rectangle([30, 30, W - 30, H - 30], outline=cy, width=3)
    d.rectangle([48, 48, W - 48, H - 48], outline=(29, 42, 53), width=2)
    for x, y, dx, dy in [(30, 30, 1, 1), (W - 30, 30, -1, 1), (30, H - 30, 1, -1), (W - 30, H - 30, -1, -1)]:
        d.line([(x, y), (x + dx * 90, y)], fill=am, width=8)
        d.line([(x, y), (x, y + dy * 90)], fill=am, width=8)

    def ct(y, text, size, fill, maxw=W - 220):
        f = _font(size)
        while d.textbbox((0, 0), text, font=f)[2] > maxw and size > 14:
            size -= 2
            f = _font(size)
        b = d.textbbox((0, 0), text, font=f)
        d.text(((W - (b[2] - b[0])) // 2, y), text, font=f, fill=fill)

    if LOGO_BYTES:
        try:
            logo = Image.open(io.BytesIO(LOGO_BYTES)).convert("RGBA")
            logo.thumbnail((300, 180))
            im.paste(logo, ((W - logo.width) // 2, 80), logo)
        except Exception:
            pass
    ct(290, "TRADE CERTIFICATE", 86, cy)
    ct(395, c["role"].upper(), 34, am)
    ct(470, "This is to certify that", 32, mu)
    ct(525, c["name"], 78, (255, 255, 255))
    ct(630, c["org"] or "", 40, tx)
    ct(705, "is an officially recognized representative of International System Security", 30, mu)
    ct(745, "and is authorized to sell ISS Cyber Defence Suite plans.", 30, mu)
    fields = [("CERTIFICATE ID", c["cert_id"]), ("COUNTRY", c["country"] or "-"), ("VALID FROM", c["valid_from"]), ("VALID UNTIL", c["valid_to"])]
    colw = (W - 240) // 4
    for i, (k, v) in enumerate(fields):
        x = 120 + i * colw
        d.text((x, 860), k, font=_font(22), fill=mu)
        d.text((x, 895), str(v), font=_font(30), fill=tx)
    d.line([(120, 970), (W - 120, 970)], fill=(29, 42, 53), width=2)
    ct(990, "International System Security  |  New window of world wide web", 28, mu)
    ct(1035, "Verify authenticity: upload this exact image at " + request.host + "/verify", 22, mu)
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


def pixel_hash(data):
    """Exact pixel-level fingerprint: any changed pixel gives a different hash."""
    try:
        im = Image.open(io.BytesIO(data))
        if im.size[0] * im.size[1] > 16_000_000:
            return None
        im = im.convert("RGBA")
        return hashlib.sha256(("%dx%d" % im.size).encode() + im.tobytes()).hexdigest()
    except Exception:
        return None


def cert_state(c):
    today = date.today().isoformat()
    if c["status"] == "revoked":
        return "revoked"
    if c["valid_to"] < today:
        return "expired"
    if c["valid_from"] > today:
        return "not yet valid"
    return "valid"


CERTS_TPL = r"""
<h2>Verify</h2>
<div class="card"><h3>Issue a trade certificate</h3>
  <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}"><input type="hidden" name="action" value="issue">
    <input name="name" placeholder="Full name" required>
    <input name="email" type="email" placeholder="Email" required>
    <input name="org" placeholder="Business / shop name" required>
    <input name="country" placeholder="Country">
    <input name="phone" placeholder="Phone">
    <input name="discord" placeholder="Discord username">
    <input name="role" placeholder="Role (default: Authorized ISS Seller)">
    <input name="valid_from" placeholder="Valid from YYYY-MM-DD (default today)">
    <input name="valid_to" placeholder="Valid until YYYY-MM-DD" required>
    <button type="submit">Generate certificate</button></form></div>
<div class="card"><h3>Issued certificates</h3>
  <table><tr><th>ID</th><th>Holder</th><th>Valid until</th><th>Status</th><th>Checks</th><th></th></tr>
  {% for c in certs %}<tr><td>{{ c.cert_id }}</td><td>{{ c.name }}<br><span class="m">{{ c.org }} &middot; {{ c.email }}</span></td><td>{{ c.valid_to }}</td>
    <td>{% if c.state == 'valid' %}<span class="pill g">valid</span>{% else %}<span class="pill r">{{ c.state }}</span>{% endif %}</td><td>{{ c.verified_count }}</td>
    <td><a class="btn btn2" href="/admin/certificates/{{ c.id }}.png?view=1" target="_blank" style="padding:7px 12px">View</a> <a class="btn" href="/admin/certificates/{{ c.id }}.png" style="padding:7px 12px">Download</a>
    {% if c.status != 'revoked' %}<form method="POST" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf() }}"><input type="hidden" name="action" value="revoke"><input type="hidden" name="id" value="{{ c.id }}"><button class="btn2" style="padding:7px 12px">Revoke</button></form>{% endif %}
    <form method="POST" style="display:inline" onsubmit="return confirm('Delete this certificate for good? Its keys stay in the key history.')"><input type="hidden" name="csrf" value="{{ csrf() }}"><input type="hidden" name="action" value="delete_cert"><input type="hidden" name="id" value="{{ c.id }}"><button class="btn2" style="padding:7px 12px">Delete</button></form></td></tr>{% endfor %}</table></div>
<div class="card"><h3>Identification key</h3>
  <p class="m">The key is always made for the certificate of the account you are logged in with. It works once and expires in 15 minutes. The buyer enters it on the Verify Seller page, and sees every detail below.</p>
  {% if my_cert %}<table><tr><th>Name</th><td>{{ my_cert.name }}</td></tr><tr><th>Business</th><td>{{ my_cert.org }}</td></tr><tr><th>Email</th><td>{{ my_cert.email }}</td></tr>
    <tr><th>Country</th><td>{{ my_cert.country }}</td></tr><tr><th>Discord</th><td>{{ my_cert.discord }}</td></tr><tr><th>Role</th><td>{{ my_cert.role }}</td></tr>
    <tr><th>Certificate ID</th><td>{{ my_cert.cert_id }}</td></tr><tr><th>Valid</th><td>{{ my_cert.valid_from }} to {{ my_cert.valid_to }}</td></tr></table>
  <form method="POST" action="/admin/keys/create"><input type="hidden" name="csrf" value="{{ csrf() }}">
    <button type="submit">Create identification key</button></form>
  {% else %}<p class="err">No valid trade certificate is linked to your email ({{ my_email }}). Issue one with this exact email above, then come back here.</p>{% endif %}
  {% if keys %}<h3 style="margin-top:18px">Key history</h3><table><tr><th>Key</th><th>Certificate</th><th>Created</th><th>Used</th><th>Status</th></tr>
  {% for k in keys %}<tr><td><code>{{ k.key }}</code></td><td>{{ k.cert }}<br><span class="m">{{ k.name }}</span></td><td>{{ k.created }}</td><td>{{ k.used }}</td><td>{% if k.state == 'active' %}<span class="pill g">active {{ k.left }}</span>{% elif k.state == 'used' %}<span class="pill">used</span>{% else %}<span class="pill r">expired</span>{% endif %}</td></tr>{% endfor %}</table>{% endif %}</div>
<div class="card"><h3>Add agent</h3><p class="m">Agents can open the Admin Portal to create licenses for you (they only see their own) and create identification keys for seller verification. Add trusted people only.</p>
  <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}"><input type="hidden" name="action" value="add_agent">
    <input name="username" placeholder="Username" required><input name="email" type="email" placeholder="Email (same as on the certificate)" required>
    <input name="password" type="password" placeholder="Password (min 8)" required><button type="submit">Save</button></form>
  {% if agents %}<table style="margin-top:14px"><tr><th>Username</th><th>Email</th><th></th></tr>
  {% for a in agents %}<tr><td>{{ a.username }}</td><td>{{ a.email }}</td><td><form method="POST" onsubmit="return confirm('Delete agent?')"><input type="hidden" name="csrf" value="{{ csrf() }}"><input type="hidden" name="action" value="delete_agent"><input type="hidden" name="id" value="{{ a.id }}"><button class="btn2" style="padding:7px 12px">Delete</button></form></td></tr>{% endfor %}</table>{% endif %}</div>
"""


@app.route("/admin/certificates", methods=["GET", "POST"])
@admin_required
def admin_certificates():
    db = get_db()
    if request.method == "POST":
        act = request.form.get("action")
        f = request.form
        if act == "issue" and not PIL_OK:
            flash("Certificates need the pillow library. Add pillow to requirements.txt and redeploy.")
            return redirect(url_for("admin_certificates"))
        if act == "issue":
            # Only name, email, organization and an expiry date are required.
            # Country, phone, Discord and role are all optional.
            name, email, org = f.get("name", "").strip()[:80], f.get("email", "").strip().lower()[:120], f.get("org", "").strip()[:80]
            vfrom = f.get("valid_from", "").strip() or date.today().isoformat()
            vto = f.get("valid_to", "").strip()
            try:
                date.fromisoformat(vfrom)
                date.fromisoformat(vto)
            except ValueError:
                flash("Dates must be in YYYY-MM-DD format, e.g. 2027-01-01.")
                return redirect(url_for("admin_certificates"))
            if not (name and org and "@" in email) or vto < vfrom:
                flash("Name, business, a valid email and a valid date range are required. The rest is optional.")
                return redirect(url_for("admin_certificates"))
            c = {"cert_id": "ISS-TC-" + secrets.token_hex(4).upper(), "name": name, "org": org, "email": email,
                 "country": f.get("country", "").strip()[:40], "phone": f.get("phone", "").strip()[:30],
                 "discord": f.get("discord", "").strip()[:40], "role": f.get("role", "").strip()[:40] or "Authorized ISS Seller",
                 "valid_from": vfrom, "valid_to": vto}
            try:
                png = make_certificate(c)
                db.execute("INSERT INTO certificates(cert_id,name,email,org,country,phone,discord,role,valid_from,valid_to,pixel_hash,png,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (c["cert_id"], name, email, org, c["country"], c["phone"], c["discord"], c["role"], vfrom, vto, pixel_hash(png), png, now()))
                db.commit()
                flash("Certificate %s created. Download it below and send it as a file." % c["cert_id"])
            except Exception as e:
                # Never crash the page: show the real reason so it can be fixed.
                print(f"Certificate creation error: {e!r}")
                flash("Could not create the certificate (%s). Please try again or tell ISS support this message." % e)
        elif act == "revoke":
            db.execute("UPDATE certificates SET status='revoked' WHERE id=?", (f.get("id", ""),))
            db.commit()
            flash("Certificate revoked.")
        elif act == "delete_cert":
            db.execute("DELETE FROM certificates WHERE id=?", (f.get("id", ""),))
            db.commit()
            flash("Certificate deleted.")
        elif act == "add_agent":
            un, em, pw = f.get("username", "").strip()[:40], f.get("email", "").strip().lower()[:120], f.get("password", "")
            if not un or "@" not in em or len(pw) < 8:
                flash("Username, valid email and a password of at least 8 characters are required.")
            else:
                try:
                    db.execute("INSERT INTO agents(username,email,password_hash,created) VALUES(?,?,?,?)", (un, em, generate_password_hash(pw), now()))
                    db.commit()
                    flash("Agent created. They can log in at /login with their email and password.")
                except sqlite3.IntegrityError:
                    flash("That username or email already exists.")
        elif act == "delete_agent":
            db.execute("DELETE FROM agents WHERE id=?", (f.get("id", ""),))
            db.commit()
        return redirect(url_for("admin_certificates"))
    certs = [dict(c, state=cert_state(c)) for c in db.execute(
        "SELECT id,cert_id,name,email,org,valid_from,valid_to,status,verified_count FROM certificates ORDER BY id DESC").fetchall()]
    agents = db.execute("SELECT * FROM agents ORDER BY id DESC").fetchall()
    _, my_email = admin_key_owner(db)
    mine = best_certificate(db, my_email) if my_email else None
    my_cert = {k: (mine[k] or "-") for k in CERT_FIELDS} if mine else None
    return page("Verify", CERTS_TPL, shell=admin_shell("certs", "Verify"), certs=certs, agents=agents, keys=admin_keys(db),
                my_cert=my_cert, my_email=my_email)


@app.route("/admin/certificates/<int:cid>.png")
@admin_required
def admin_cert_png(cid):
    c = get_db().execute("SELECT cert_id, png FROM certificates WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    headers = {} if request.args.get("view") else {"Content-Disposition": 'attachment; filename="%s.png"' % c["cert_id"]}
    return Response(c["png"], mimetype="image/png", headers=headers)


def admin_key_owner(db):
    """Admin keys are stored under a negative number made from the admin's email, so every admin only sees and uses their own."""
    email = session.get("admin_email", "")
    return -(int(hashlib.sha256(email.lower().encode()).hexdigest()[:12], 16) + 1), email


def admin_keys(db):
    """History of the keys created by the logged-in admin. Agents' keys stay private to them."""
    out, nowts = [], int(time.time())
    owner, _ = admin_key_owner(db)
    for k in db.execute("""SELECT k.*, c.cert_id AS cid, c.name AS cname FROM id_keys k
            LEFT JOIN certificates c ON c.id=k.cert_pk WHERE k.agent_id=? ORDER BY k.id DESC LIMIT 200""", (owner,)).fetchall():
        if k["used_ts"]:
            state, left = "used", 0
        elif nowts > k["expires_ts"]:
            state, left = "expired", 0
        else:
            state, left = "active", k["expires_ts"] - nowts
        out.append({"key": fmt_key(k["key"]), "cert": k["cid"] or "deleted certificate", "name": k["cname"] or "", "created": ts_text(k["created_ts"]),
                    "used": ts_text(k["used_ts"]) if k["used_ts"] else "-", "state": state, "left": "%d:%02d" % divmod(left, 60)})
    return out


@app.route("/admin/keys/create", methods=["POST"])
@admin_required
def admin_key_create():
    db = get_db()
    owner, email = admin_key_owner(db)
    c = best_certificate(db, email) if email else None
    if not c:
        flash("No valid trade certificate is linked to your email (%s), so a key cannot be created. Issue one with this exact email first." % email)
        return redirect(url_for("admin_certificates"))
    nowts = int(time.time())
    db.execute("UPDATE id_keys SET expires_ts=? WHERE agent_id=? AND used_ts IS NULL AND expires_ts>?", (nowts, owner, nowts))
    key = "".join(secrets.choice(KEY_ALPHABET) for _ in range(20))
    snap = json.dumps({k: (c[k] or "-") for k in CERT_FIELDS})
    db.execute("INSERT INTO id_keys(key,agent_id,cert_pk,snapshot,created_ts,expires_ts) VALUES(?,?,?,?,?,?)",
               (key, owner, c["id"], snap, nowts, nowts + KEY_TTL))
    db.commit()
    send_discord_alert("🔐 Identification key created by admin `%s` for certificate **%s**" % (email, c["cert_id"]))
    flash("Identification key: %s  (valid 15 minutes, works once). Give it to the buyer now." % fmt_key(key))
    return redirect(url_for("admin_certificates"))


KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
KEY_TTL = 15 * 60
CERT_FIELDS = ("name", "email", "org", "country", "discord", "role", "cert_id", "valid_from", "valid_to")


def fmt_key(k):
    return "-".join(k[i:i + 5] for i in range(0, 20, 5))


def norm_key(text):
    return "".join(ch for ch in (text or "").upper() if ch.isalnum())


def ts_text(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def best_certificate(db, email):
    for c in db.execute("SELECT * FROM certificates WHERE lower(email)=? ORDER BY id DESC", (email.lower(),)).fetchall():
        if cert_state(c) == "valid":
            return c
    return None


def check_key(db, row, nowts):
    """SSA: a key works once, only while unexpired, only if the certificate is valid."""
    if not row:
        return {"ok": False, "reason": "Invalid verification key. Check it and try again."}
    cert = db.execute("SELECT * FROM certificates WHERE id=?", (row["cert_pk"],)).fetchone()
    state = cert_state(cert) if cert else "missing"
    if row["used_ts"]:
        return {"ok": False, "reason": "This key was already used. Each key works only once. Ask the seller for a new key."}
    if nowts > row["expires_ts"]:
        return {"ok": False, "reason": "This key has expired. Keys are valid for 15 minutes. Ask the seller for a new key."}
    if state != "valid":
        return {"ok": False, "reason": "The seller's certificate is %s." % state}
    cur = db.execute("UPDATE id_keys SET used_ts=? WHERE id=? AND used_ts IS NULL AND expires_ts>=?", (nowts, row["id"], nowts))
    db.commit()
    if cur.rowcount != 1:
        return {"ok": False, "reason": "This key was already used."}
    return {"ok": True, "created": ts_text(row["created_ts"]),
            "remaining": "%d:%02d" % divmod(max(0, row["expires_ts"] - nowts), 60),
            "details": json.loads(row["snapshot"])}


def history_key(row, nowts):
    if not row:
        return {"ok": False, "reason": "Key not found."}
    if not row["used_ts"] and nowts <= row["expires_ts"]:
        return {"ok": False, "reason": "This key is still active and unused. Use the SSA box above to verify the seller. The history box only shows used or expired keys."}
    status = ("Used at " + ts_text(row["used_ts"])) if row["used_ts"] else ("Expired at " + ts_text(row["expires_ts"]))
    return {"ok": True, "created": ts_text(row["created_ts"]), "status": status, "details": json.loads(row["snapshot"])}


VERIFY_TPL = r"""
{% macro details(d) %}<table style="text-align:left;margin-top:10px">
{% for label, k in [('Name','name'),('Email','email'),('Business','org'),('Country','country'),('Discord','discord'),('Role','role'),('Certificate ID','cert_id'),('Valid from','valid_from'),('Valid until','valid_to')] %}<tr><th>{{ label }}</th><td>{{ d[k] }}</td></tr>{% endfor %}</table>{% endmacro %}
<div class="top"><h2>Verify Seller</h2><a class="btn btn2" href="/">&larr; Home</a></div>
<p class="m">Buy only after BOTH steps pass. FSA checks the certificate. SSA proves the seller is in control of their account right now.</p>

<div class="card"><h3>Step 1 &middot; FSA <span class="m">(Fast Sector Authentication)</span></h3>
  <p class="m">Upload the Trade Certificate image the seller gave you. It must be the original file. It is compared pixel by pixel with the certificate we issued, so any edit, crop or screenshot fails.</p>
  <form method="POST" enctype="multipart/form-data"><input type="hidden" name="csrf" value="{{ csrf() }}"><input type="hidden" name="action" value="fsa">
    <input type="file" name="image" accept="image/png,image/*" required><button type="submit">Verify certificate</button></form>
  {% if fsa %}<div class="res {{ 'okc' if fsa.ok else 'bad' }}"><div class="mark">{{ '&#10004;' if fsa.ok else '&#10008;' }}</div>
    <h2>{{ 'CERTIFICATE VERIFIED' if fsa.ok else 'NOT VERIFIED' }}</h2>
    {% if fsa.ok %}{{ details(fsa.details) }}<p class="m">Now continue with Step 2. A copied certificate image alone is not enough.</p>
    {% else %}<p>{{ fsa.reason }}</p><p class="m">Do not buy from this seller. Report them on our Discord.</p>{% endif %}</div>{% endif %}</div>

<div class="card"><h3>Step 2 &middot; SSA <span class="m">(Second Sector Authentication)</span></h3>
  <p class="m">Ask the seller to log in and create an identification key right now. Enter the key yourself. It works once and expires after 15 minutes.</p>
  <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}"><input type="hidden" name="action" value="ssa">
    <input name="key" placeholder="Enter verification key (XXXXX-XXXXX-XXXXX-XXXXX)" autocomplete="off" required><button type="submit">Verify key</button></form>
  {% if ssa %}<div class="res {{ 'okc' if ssa.ok else 'bad' }}"><div class="mark">{{ '&#10004;' if ssa.ok else '&#10008;' }}</div>
    <h2>{{ 'SELLER VERIFIED' if ssa.ok else 'NOT VERIFIED' }}</h2>
    {% if ssa.ok %}<p class="m">Key created: {{ ssa.created }}<br>Still valid for: {{ ssa.remaining }} (minutes:seconds)</p>{{ details(ssa.details) }}
      <p>Check that the person you are chatting with uses the Discord account shown above, and that the details match the certificate image.</p>
      <p class="m">This key has now been used and cannot be used again.</p>
    {% else %}<p>{{ ssa.reason }}</p><p class="m">Do not buy until the seller passes this step.</p>{% endif %}</div>{% endif %}</div>

<div class="card"><h3>History key</h3>
  <p class="m">Look up the details of an old key that was already used or has expired. History records cannot verify a seller.</p>
  <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}"><input type="hidden" name="action" value="history">
    <input name="key" placeholder="Enter old key" autocomplete="off" required><button class="btn2" type="submit">Show history</button></form>
  {% if hist %}<div style="margin-top:14px">{% if hist.ok %}<h3>History record</h3><p class="m">Created: {{ hist.created }}<br>{{ hist.status }}</p>{{ details(hist.details) }}
    <p class="err">HISTORY ONLY. This key can no longer verify a seller.</p>
    {% else %}<p class="err">{{ hist.reason }}</p>{% endif %}</div>{% endif %}</div>
"""


@app.route("/verify", methods=["GET", "POST"])
@limiter.limit("30 per hour", methods=["POST"])
def verify():
    fsa = ssa = hist = None
    if request.method == "POST":
        db = get_db()
        act = request.form.get("action", "fsa")
        if act == "fsa":
            f = request.files.get("image")
            data = f.read() if f else b""
            h = pixel_hash(data) if data else None
            c = db.execute("SELECT * FROM certificates WHERE pixel_hash=?", (h,)).fetchone() if h else None
            if not c:
                fsa = {"ok": False, "reason": "This image does not exactly match any certificate issued by ISS. It is fake, edited or not the original file."}
            elif cert_state(c) != "valid":
                fsa = {"ok": False, "reason": "This certificate is %s." % cert_state(c)}
            else:
                db.execute("UPDATE certificates SET verified_count = verified_count + 1 WHERE id=?", (c["id"],))
                db.commit()
                fsa = {"ok": True, "details": {k: (c[k] or "-") for k in CERT_FIELDS}}
        elif act in ("ssa", "history"):
            key = norm_key(request.form.get("key", ""))
            row = db.execute("SELECT * FROM id_keys WHERE key=?", (key,)).fetchone() if len(key) == 20 else None
            nowts = int(time.time())
            if act == "ssa":
                ssa = check_key(db, row, nowts)
            else:
                hist = history_key(row, nowts)
    return page("Verify Seller", VERIFY_TPL, fsa=fsa, ssa=ssa, hist=hist)


# ------------------------------------------------------------------
# Agent (seller) dashboard
# ------------------------------------------------------------------
AGENT_TPL = r"""
<div class="top"><h2>Agent Dashboard</h2><div>
  <a class="btn" href="/admin">Admin Portal</a>
  <form method="POST" action="/logout" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf() }}"><button class="btn2">Logout</button></form></div></div>
<div class="card"><h3>{{ ag.username }}</h3><p class="m">{{ ag.email }}</p>
  <p class="m">Open the Admin Portal to create licenses for clients. You only see the licenses you created.</p></div>
<div class="card"><h3>Identification key</h3>
  <p class="m">Create a key while you chat with a buyer. It works once and expires in 15 minutes. The buyer enters it on the Verify Seller page (SSA). A new key cancels your older unused keys.</p>
  <form method="POST" action="/agent/keys/create"><input type="hidden" name="csrf" value="{{ csrf() }}"><button type="submit">Create identification key</button></form>
  {% if keys %}<table style="margin-top:14px"><tr><th>Key</th><th>Created</th><th>Status</th></tr>
  {% for k in keys %}<tr><td><code>{{ k.key }}</code></td><td>{{ k.created }}</td><td>{% if k.state == 'active' %}<span class="pill g">active {{ k.left }}</span>{% elif k.state == 'used' %}<span class="pill">used</span>{% else %}<span class="pill r">expired</span>{% endif %}</td></tr>{% endfor %}</table>{% endif %}</div>
{% for c in rows %}<div class="card"><h3>{{ c.cert_id }} {% if c.state == 'valid' %}<span class="pill g">valid</span>{% else %}<span class="pill r">{{ c.state }}</span>{% endif %}</h3>
  <p>{{ c.role }} &middot; {{ c.org }}</p>
  <p class="m">Valid {{ c.valid_from }} to {{ c.valid_to }} &middot; {% if c.left >= 0 %}{{ c.left }} days left{% else %}expired {{ -c.left }} days ago{% endif %}</p>
  <p class="m">Buyers have verified this certificate {{ c.verified_count }} time(s).</p>
  {% if c.state != 'valid' %}<p class="err">There is a problem with this certificate. Please contact ISS support.</p>{% endif %}</div>
{% else %}<div class="card"><p class="m">No certificate is linked to your email yet. Contact ISS support.</p></div>{% endfor %}
"""


@app.route("/agent")
def agent_dashboard():
    ag = current_agent()
    if not ag:
        session.pop("agent_id", None)
        return redirect(url_for("login"))
    db = get_db()
    rows = []
    for c in db.execute("SELECT * FROM certificates WHERE lower(email)=? ORDER BY id DESC", (ag["email"].lower(),)).fetchall():
        try:
            left = (date.fromisoformat(c["valid_to"]) - date.today()).days
        except ValueError:
            left = 0
        rows.append(dict(c, state=cert_state(c), left=left))
    keys, nowts = [], int(time.time())
    for k in db.execute("SELECT * FROM id_keys WHERE agent_id=? ORDER BY id DESC LIMIT 8", (ag["id"],)).fetchall():
        if k["used_ts"]:
            state, left = "used", 0
        elif nowts > k["expires_ts"]:
            state, left = "expired", 0
        else:
            state, left = "active", k["expires_ts"] - nowts
        keys.append({"key": fmt_key(k["key"]), "created": ts_text(k["created_ts"]), "state": state, "left": "%d:%02d" % divmod(left, 60)})
    return page("Agent Dashboard", AGENT_TPL, ag=ag, rows=rows, keys=keys)


@app.route("/agent/keys/create", methods=["POST"])
def agent_key_create():
    ag = current_agent()
    if not ag:
        return redirect(url_for("login"))
    db = get_db()
    cert = best_certificate(db, ag["email"])
    if not cert:
        flash("You have no valid trade certificate linked to your email, so a key cannot be created. Contact ISS support.")
        return redirect(url_for("agent_dashboard"))
    nowts = int(time.time())
    db.execute("UPDATE id_keys SET expires_ts=? WHERE agent_id=? AND used_ts IS NULL AND expires_ts>?", (nowts, ag["id"], nowts))
    key = "".join(secrets.choice(KEY_ALPHABET) for _ in range(20))
    snap = json.dumps({k: (cert[k] or "-") for k in CERT_FIELDS})
    db.execute("INSERT INTO id_keys(key,agent_id,cert_pk,snapshot,created_ts,expires_ts) VALUES(?,?,?,?,?,?)",
               (key, ag["id"], cert["id"], snap, nowts, nowts + KEY_TTL))
    db.commit()
    send_discord_alert(f"🔐 Identification key created by agent **{ag['username']}**")
    flash("Identification key: %s  (valid 15 minutes, works once). Give it to the buyer now." % fmt_key(key))
    return redirect(url_for("agent_dashboard"))


# ------------------------------------------------------------------
# Client portal: activate this device, test, account
# ------------------------------------------------------------------
def ua_name(ua):
    ua = ua or ""
    os_ = next((n for k, n in (("Windows", "Windows"), ("Android", "Android"), ("iPhone", "iPhone"), ("iPad", "iPad"), ("Mac OS", "macOS"), ("Linux", "Linux")) if k in ua), "Unknown OS")
    br = next((n for k, n in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Chrome/", "Chrome"), ("Firefox/", "Firefox"), ("Safari/", "Safari")) if k in ua), "Browser")
    return f"{br} on {os_} (web)"


@app.route("/client/activate-device", methods=["POST"])
@client_required
def client_activate_device():
    dev = request.cookies.get("iss_dev") or secrets.token_hex(12)
    name = ua_name(request.headers.get("User-Agent", ""))
    info, err = api_authorize({"license_key": g.lic["key"], "device_id": "web-" + dev, "device_name": name})
    note = ""
    if not err:
        db = get_db()
        if not db.execute("SELECT 1 FROM devices WHERE license_key=? AND is_admin=1", (g.lic["key"],)).fetchone():
            db.execute("UPDATE devices SET is_admin=1 WHERE license_key=? AND device_id=?", (g.lic["key"], "web-" + dev))
            db.commit()
            note = " (admin device)"
    flash(err[0]["message"] if err else f"This device is now active: {name}{note}")
    resp = redirect(url_for("client_dashboard"))
    resp.set_cookie("iss_dev", dev, max_age=31536000, httponly=True, samesite="Lax")
    return resp


@app.route("/client/test", methods=["POST"])
@client_required
def client_test():
    db = get_db()
    key = g.lic["key"]
    if db.execute("SELECT COUNT(*) FROM devices WHERE license_key=?", (key,)).fetchone()[0] == 0:
        flash("Activate at least one device before running a test.")
    else:
        db.execute("INSERT INTO commands(license_key,type,created) VALUES(?,?,?)", (key, "eicar_test", now()))
        db.commit()
        session["just_tested"] = True
        flash("Test started. Every device running the ISS agent will show a pop-up within about 30 seconds.")
    return redirect(url_for("client_scan"))


@app.route("/client/account", methods=["GET", "POST"])
@client_required
def client_account():
    has_admin, is_admin = device_admin_state(get_db(), g.lic["key"])
    allowed = is_admin or not has_admin
    if request.method == "POST":
        if not allowed:
            flash("Only the admin device can change the username and password.")
            return redirect(url_for("client_account"))
        new_user = request.form.get("username", "").strip()[:40]
        cur_pw = request.form.get("current", "")
        new_pw = request.form.get("new_password", "")
        if not check_password_hash(g.lic["client_pwd_hash"], cur_pw):
            flash("Current password is wrong.")
        elif len(new_user) < 3 or len(new_pw) < 8 or new_pw.lower() == "admin":
            flash("Username needs 3+ characters and the new password needs 8+ characters.")
        else:
            db = get_db()
            db.execute("UPDATE licenses SET client_user=?, client_pwd_hash=?, must_change=0 WHERE key=?",
                       (new_user, generate_password_hash(new_pw), g.lic["key"]))
            db.commit()
            flash("Login details updated.")
            return redirect(url_for("client_dashboard"))
    return page("Users", r"""
    <h2>Users</h2>
    {% if first %}<p class="m">You are using the default password. Please set your own before continuing.</p>{% endif %}
    {% if allowed %}<div class="card"><h3>Change username and password</h3>
      <p class="m">Current username: <code>{{ u }}</code></p>
      <form method="POST"><input type="hidden" name="csrf" value="{{ csrf() }}">
        <input name="username" placeholder="New username" required>
        <input name="current" type="password" placeholder="Current password (default: admin)" required>
        <input name="new_password" type="password" placeholder="New password (min 8 characters)" required>
        <button type="submit">Save</button></form></div>
    {% else %}<div class="card"><h3>Admin device only</h3><p class="m">Only the admin device can change the username and password. Open this page from the admin device.</p></div>{% endif %}
    """, shell=client_shell("account", "Users"), u=g.lic["client_user"], first=bool(g.lic["must_change"]), allowed=allowed)

CLIENT_AUTH_TPL = r"""
<h2>Auth</h2>
<div class="card"><h3>License</h3>
  <div class="big">{{ days if days > 0 else 0 }} <small>days left</small></div>
  {% if days > 0 %}<div class="meter"><i style="width:{{ pct }}%"></i></div>{% endif %}
  <p class="m">{% if days < 0 %}Expired {{ -days }} day(s) ago.{% elif days <= 30 %}Expires soon. Open a support ticket to renew.{% else %}Your license is active.{% endif %}</p>
  <table><tr><th>Expires</th><td>{{ v.expiry }}</td></tr><tr><th>Plan</th><td>{{ v.plan }}</td></tr>
    <tr><th>Organization</th><td>{{ v.org }}</td></tr><tr><th>License key</th><td><code>{{ v.key }}</code></td></tr></table>
</div>
"""


@app.route("/client/auth")
@client_required
def client_auth():
    try:
        days = (date.fromisoformat(g.lic["expiry"]) - date.today()).days
    except ValueError:
        days = 0
    return page("Auth", CLIENT_AUTH_TPL, shell=client_shell("auth", "Auth"), v=g.lic, days=days, pct=min(100, int(days * 100 / 365)))


SCAN_TPL = r"""
<h2>Scan</h2>
<div class="card"><h3>Scan again</h3>
  <p class="m">Runs the industry-standard EICAR test file through the exact same detection pipeline as a real threat. Every active device shows a pop-up and the file is quarantined.</p>
  {% if used == 0 %}<button disabled style="opacity:.4;cursor:not-allowed">Scan now</button> <span class="m">Add a device first.</span>
  {% else %}<form method="POST" action="/client/test" id="testForm"><input type="hidden" name="csrf" value="{{ csrf() }}"><button type="submit" id="testBtn">Scan now</button></form>
  <div class="scan6" id="scan6" {% if not just_tested %}style="display:none"{% endif %}>
    <div class="s6" data-s="0"><i></i><span>Scan your device</span></div>
    <div class="s6" data-s="1"><i></i><span>Check license and devices</span></div>
    <div class="s6" data-s="2"><i></i><span>Create test file</span></div>
    <div class="s6" data-s="3"><i></i><span>Match against threat engine</span></div>
    <div class="s6" data-s="4"><i></i><span>Quarantine and notify device</span></div>
    <div class="s6" data-s="5"><i></i><span>Report result</span></div>
  </div>{% endif %}
  {% if events %}<table style="margin-top:14px"><tr><th>Time (UTC)</th><th>Device</th><th>Result</th></tr>
  {% for e in events %}<tr><td>{{ e.created }}</td><td>{{ e.dname or 'Unknown' }}</td><td>
    {% if e.type == 'test_blocked' %}<span class="pill g">Test virus blocked</span>{% elif e.type == 'test_missed' %}<span class="pill r">Test virus NOT blocked</span>{% elif e.type == 'ransomware_pattern_blocked' %}<span class="pill r">Mass-encryption pattern blocked</span> {{ e.detail }}{% else %}<span class="pill g">Threat blocked</span> {{ e.detail }}{% endif %}</td></tr>{% endfor %}</table>{% endif %}</div>
<script>
(function(){
var panel=document.getElementById('scan6');if(!panel)return;
var steps=panel.querySelectorAll('.s6');
async function run(){
for(var i=0;i<steps.length;i++){
  steps[i].classList.add('go');
  await new Promise(function(r){setTimeout(r,550+Math.random()*450)});
  steps[i].classList.remove('go');steps[i].classList.add('done');
}
}
run();
})();
</script>
"""


@app.route("/client/scan")
@client_required
def client_scan():
    db, key, devices, events, limit, used, pct = client_common()
    just_tested = session.pop("just_tested", False)
    return page("Scan", SCAN_TPL, shell=client_shell("scan", "Scan"), used=used, events=events, just_tested=just_tested)


@app.route("/client/download")
@client_required
def client_download():
    return page("Download", DOWNLOAD_TPL, shell=client_shell("download", "Download"),
                app_name="ISS Client Portal", scope="/client")


# ------------------------------------------------------------------
# Agent API: commands, events, threat hashes
# ------------------------------------------------------------------
@app.route("/api/agent/poll", methods=["POST"])
@limiter.limit("120 per minute")
def api_agent_poll():
    data = request.get_json(silent=True) or {}
    info, err = api_authorize(data)
    if err:
        return err
    try:
        since = int(data.get("since_id", 0))
    except (TypeError, ValueError):
        since = 0
    cutoff = (datetime.utcnow() - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M")
    conn = connect()
    rows = conn.execute("SELECT id,type FROM commands WHERE license_key=? AND id>? AND created>=? ORDER BY id",
                        (info["lic"]["key"], since, cutoff)).fetchall()
    last = conn.execute("SELECT COALESCE(MAX(id),0) FROM commands WHERE license_key=?", (info["lic"]["key"],)).fetchone()[0]
    conn.close()
    return {"status": "ok", "commands": [dict(r) for r in rows], "last_id": last}


@app.route("/api/agent/threats", methods=["POST"])
@limiter.limit("30 per hour")
def api_agent_threats():
    info, err = api_authorize(request.get_json(silent=True) or {})
    if err:
        return err
    conn = connect()
    hashes = [r[0] for r in conn.execute("SELECT hash FROM threats").fetchall()]
    conn.close()
    return {"status": "ok", "hashes": hashes}


@app.route("/api/agent/event", methods=["POST"])
@limiter.limit("120 per minute")
def api_agent_event():
    data = request.get_json(silent=True) or {}
    info, err = api_authorize(data)
    if err:
        return err
    etype = str(data.get("type", ""))
    if etype not in ("threat_blocked", "test_blocked", "test_missed", "ransomware_pattern_blocked"):
        return {"status": "error", "message": "unknown event"}, 400
    detail = str(data.get("detail", ""))[:200]
    conn = connect()
    conn.execute("INSERT INTO events(license_key,device_id,command_id,type,detail,created) VALUES(?,?,?,?,?,?)",
                 (info["lic"]["key"], str(data.get("device_id", ""))[:64], int(data.get("command_id") or 0), etype, detail, now()))
    conn.commit()
    conn.close()
    if etype == "threat_blocked":
        send_discord_alert(f"🚨 Threat blocked on {info['device']} ({info['lic']['org']}): {detail}")
    return {"status": "ok"}


# ------------------------------------------------------------------
# Health check (UptimeRobot pings this to keep the server awake)
# ------------------------------------------------------------------
@app.route("/health")
@limiter.exempt
def health():
    return "OK"


# ------------------------------------------------------------------
# Discord bot - slash (/) commands, administrators only
# ------------------------------------------------------------------
intents = discord.Intents.default()
bot = commands.Bot(command_prefix=commands.when_mentioned, intents=intents)
GUILD_ID = os.environ.get("DISCORD_GUILD_ID")  # optional: makes commands appear instantly


async def _setup_hook():
    if GUILD_ID:
        guild = discord.Object(id=int(GUILD_ID))
        bot.tree.copy_global_to(guild=guild)
        await bot.tree.sync(guild=guild)
    else:
        await bot.tree.sync()


bot.setup_hook = _setup_hook


def q_one(sql, args=()):
    conn = connect()
    v = conn.execute(sql, args).fetchone()[0]
    conn.close()
    return v


def q_all(sql, args=()):
    conn = connect()
    rows = conn.execute(sql, args).fetchall()
    conn.close()
    return rows


def slash(name, desc):
    def deco(fn):
        fn = app_commands.checks.has_permissions(administrator=True)(fn)
        fn = app_commands.default_permissions(administrator=True)(fn)
        fn = app_commands.guild_only()(fn)
        return bot.tree.command(name=name, description=desc)(fn)
    return deco


@bot.event
async def on_ready():
    print(f"Discord Bot logged in as {bot.user.name}")


@bot.tree.error
async def on_app_error(interaction: discord.Interaction, error):
    if isinstance(error, app_commands.MissingPermissions):
        msg = "⛔ Only server administrators can use this command."
    else:
        print(f"Command error: {error!r}")
        msg = "⚠️ Something went wrong. Please try again in a moment."
    try:
        if interaction.response.is_done():
            await interaction.followup.send(msg, ephemeral=True)
        else:
            await interaction.response.send_message(msg, ephemeral=True)
    except discord.HTTPException:
        pass


async def run_db(fn, *args):
    """Run a blocking sqlite call off the event loop, so Discord always
    gets a response within its time limit even if the database is briefly
    busy (the website and the bot share the same database file)."""
    return await asyncio.to_thread(fn, *args)


async def safe_reply(interaction, fn, *args, ephemeral=True):
    """Defer immediately (this is what fixes 'The application did not
    respond'), do the real work in a thread, then send the result."""
    await interaction.response.defer(ephemeral=ephemeral)
    try:
        text = await run_db(fn, *args)
    except Exception as e:
        print(f"Command error: {e!r}")
        text = "⚠️ Something went wrong on our end. Please try again."
    await interaction.followup.send(text, ephemeral=ephemeral)


def _client_report_text(key, days=None):
    """Anonymous report for ONE license: no client name or organization is
    shown, so this is safe to run from any channel. Only someone who
    already has the license key (the same key the agent uses) can see it."""
    conn = connect()
    try:
        lic = conn.execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
        if not lic:
            return "⚠️ That license key was not recognized."
        used = conn.execute("SELECT COUNT(*) FROM devices WHERE license_key=?", (key,)).fetchone()[0]
        limit = plan_devices(lic["plan"]) if lic["max_devices"] is None else lic["max_devices"]
        since_clause, label = "", "all time"
        params = [key]
        if days:
            since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M")
            since_clause, label = " AND created>=?", f"last {days} days"
            params.append(since)
        attacks = conn.execute(
            "SELECT COUNT(*) FROM events WHERE license_key=? AND type IN ('threat_blocked','test_blocked')" + since_clause,
            params).fetchone()[0]
        recent = conn.execute(
            "SELECT created, type, detail FROM events WHERE license_key=? AND type IN ('threat_blocked','test_blocked')"
            + since_clause + " ORDER BY id DESC LIMIT 5", params).fetchall()
        open_t = conn.execute("SELECT COUNT(*) FROM tickets WHERE license_key=? AND status='open'", (key,)).fetchone()[0]
        try:
            days_left = (date.fromisoformat(lic["expiry"]) - date.today()).days
        except ValueError:
            days_left = "?"
        lines = [f"🛡️ **ISS Report** ({label})",
                 f"Plan: {lic['plan']} | Devices: {used} of {limit_text(limit)} | Expires in {days_left} day(s)",
                 f"Attacks blocked: {attacks} | Open support tickets: {open_t}"]
        if recent:
            lines.append("Most recent:")
            lines += [f"  • {r['created']} UTC — {'test' if r['type']=='test_blocked' else 'real'}: {r['detail']}" for r in recent]
        return "\n".join(lines)
    finally:
        conn.close()


@bot.tree.command(name="report", description="Check a license's security report using its license key")
@app_commands.describe(key="The license key (same key the ISS agent uses)")
@app_commands.guild_only()
async def report(interaction: discord.Interaction, key: str):
    await safe_reply(interaction, _client_report_text, key.strip(), None)


@bot.tree.command(name="weekly_report", description="Check a license's report for the last 7 days using its license key")
@app_commands.describe(key="The license key (same key the ISS agent uses)")
@app_commands.guild_only()
async def weekly_report(interaction: discord.Interaction, key: str):
    await safe_reply(interaction, _client_report_text, key.strip(), 7)


@slash("setalert", "Send ISS alerts to this channel")
async def setalert(interaction: discord.Interaction):
    def work():
        conn = connect()
        conn.execute("INSERT OR REPLACE INTO settings VALUES('alert_channel', ?)", (str(interaction.channel_id),))
        conn.commit()
        conn.close()
        return "✅ ISS alerts will now be posted in this channel."
    await safe_reply(interaction, work, ephemeral=False)


@slash("licenses", "Show the 15 most recent licenses")
async def licenses_cmd(interaction: discord.Interaction):
    def work():
        rows = q_all("SELECT key,name,org,plan,expiry FROM licenses ORDER BY created DESC LIMIT 15")
        if not rows:
            return "No licenses yet."
        lines = [f"`{r['key']}` | {r['name']} ({r['org']}) | {r['plan']} | {r['expiry']}" for r in rows]
        return "🔑 **Licenses**\n" + "\n".join(lines)
    await safe_reply(interaction, work)


@slash("newlicense", "Create a new client license")
@app_commands.describe(name="Client name", org="Organization name",
                       plan="Plan", days="Validity in days (default 365)")
async def newlicense(interaction: discord.Interaction, name: str, org: str,
                     plan: Literal["1-Day Plan", "Basic Plan", "Standard Plan", "Pro Plan", "Enterprise Plan"] = "Basic Plan",
                     days: app_commands.Range[int, 1, 3650] = 365):
    def work():
        key = "KEY-" + secrets.token_hex(6).upper()
        expiry = (date.today() + timedelta(days=days)).isoformat()
        conn = connect()
        conn.execute("INSERT INTO licenses(key,name,org,expiry,max_devices,plan,client_user,client_pwd_hash,created,must_change) VALUES(?,?,?,?,?,?,?,?,?,?)",
                     (key, name, org, expiry, plan_devices(plan), plan, "admin", generate_password_hash("admin"), now(), 1))
        conn.commit()
        conn.close()
        send_discord_alert(f"🔑 New license `{key}` | **{name}** ({org}) | {plan}")
        return (f"🔑 **New license** (only you can see this)\nClient: {name} ({org}) | {plan}\n"
                f"License Key: `{key}`\nUsername: `admin`\nPassword: `admin`\nExpiry: {expiry}\n"
                f"⚠️ Give these details to the client now. They must change the default password at first login.")
    await safe_reply(interaction, work)


@slash("deletelicense", "Delete a license")
@app_commands.describe(key="License key, e.g. KEY-ABC123")
async def deletelicense(interaction: discord.Interaction, key: str):
    def work():
        conn = connect()
        cur = conn.execute("DELETE FROM licenses WHERE key=?", (key.strip(),))
        conn.commit()
        conn.close()
        return "🗑️ License deleted." if cur.rowcount else "⚠️ License key not found."
    await safe_reply(interaction, work)


@slash("addthreat", "Add a file hash to the threat list")
@app_commands.describe(sha256="SHA256 hash of the file", name="Threat name")
async def addthreat(interaction: discord.Interaction, sha256: str, name: str):
    def work():
        h = sha256.strip().lower()
        if len(h) != 64 or any(ch not in "0123456789abcdef" for ch in h):
            return "⚠️ Please enter a valid 64-character SHA256 hash."
        conn = connect()
        conn.execute("INSERT OR REPLACE INTO threats VALUES(?,?,?)", (h, name[:80], now()))
        conn.commit()
        conn.close()
        return "✅ Added to the threat list."
    await safe_reply(interaction, work)


@slash("tickets", "List open support tickets")
async def tickets_cmd(interaction: discord.Interaction):
    def work():
        rows = q_all("""SELECT t.id,t.subject,t.created,l.org FROM tickets t
            LEFT JOIN licenses l ON l.key=t.license_key WHERE t.status='open' ORDER BY t.id DESC LIMIT 15""")
        if not rows:
            return "✅ No open tickets."
        lines = [f"#{r['id']} | {r['org']} | {r['subject']} | {r['created']}" for r in rows]
        return "🎫 **Open tickets**\n" + "\n".join(lines)
    await safe_reply(interaction, work, ephemeral=False)


def run_discord_bot():
    """Keep retrying forever. Before this fix, one failed login (a Discord hiccup,
    a brief network block, a restart race) killed the bot thread permanently while
    the website kept answering UptimeRobot, so the site looked fine but the bot
    looked "separate" and stayed offline until the next manual deploy."""
    if not BOT_TOKEN:
        print("DISCORD_BOT_TOKEN not set - bot disabled.")
        return
    delay = 15
    while True:
        try:
            print("Discord bot: connecting...")
            asyncio.run(bot.start(BOT_TOKEN))
            print("Discord bot: start() returned, reconnecting shortly.")
        except discord.LoginFailure:
            print("Discord bot: DISCORD_BOT_TOKEN is invalid or was reset. Not retrying; fix the token and redeploy.")
            return
        except Exception as e:
            print(f"Discord bot error: {e!r}. Retrying in {delay}s.")
        time.sleep(delay)
        delay = min(delay * 2, 300)  # back off up to 5 minutes between retries


init_db()

if __name__ == "__main__":
    threading.Thread(target=run_discord_bot, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG", "0") == "1", use_reloader=False)

# === END OF server.py (v10) - if you can see this line, the file is complete ===
