from flask import Flask, jsonify, request, session, Response, redirect
import sqlite3
import os
import secrets
import time
import json
import urllib.parse
import urllib.request
import urllib.error
import html
import threading
from datetime import datetime, timedelta
from eth_account import Account
from eth_account.messages import encode_defunct

app = Flask(__name__)
app.secret_key = os.environ.get("BL3_SECRET_KEY") or secrets.token_hex(32)

DB = os.environ.get("BL3_DB_PATH", "bl3.db")

REWARDS = {
    "checkin": 10,
    "share": 25,
    "invite": 50
}


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            wallet TEXT DEFAULT '',
            xp INTEGER DEFAULT 0,
            streak INTEGER DEFAULT 0
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS quests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            quest TEXT,
            date TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS referrals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            inviter TEXT,
            invited TEXT UNIQUE,
            date TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS share_claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            cast_hash TEXT NOT NULL UNIQUE,
            cast_url TEXT,
            date TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS streak_rewards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            milestone INTEGER NOT NULL,
            claimed_at TEXT NOT NULL,
            UNIQUE(username, milestone)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS arenas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            creator TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT DEFAULT 'Alpha',
            bounty_amount REAL DEFAULT 0,
            bounty_asset TEXT DEFAULT 'USDC',
            status TEXT DEFAULT 'live',
            deadline TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS arena_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            arena_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            proof_url TEXT DEFAULT '',
            pitch TEXT NOT NULL,
            status TEXT DEFAULT 'submitted',
            created_at TEXT NOT NULL,
            UNIQUE(arena_id, username)
        )
    """)

    # Forward-compatible Arena V6.1 migrations for existing SQLite volumes.
    arena_cols = {row["name"] for row in conn.execute("PRAGMA table_info(arenas)").fetchall()}
    if "winner_username" not in arena_cols:
        conn.execute("ALTER TABLE arenas ADD COLUMN winner_username TEXT DEFAULT ''")
    if "paid" not in arena_cols:
        conn.execute("ALTER TABLE arenas ADD COLUMN paid INTEGER DEFAULT 0")
    if "paid_at" not in arena_cols:
        conn.execute("ALTER TABLE arenas ADD COLUMN paid_at TEXT DEFAULT ''")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS reputation_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            points INTEGER NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS creature_battles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            challenger TEXT NOT NULL,
            opponent TEXT NOT NULL,
            winner TEXT NOT NULL,
            challenger_power INTEGER NOT NULL,
            opponent_power INTEGER NOT NULL,
            commentary TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # V6.7: track direct attacks on the current seasonal Crown.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS crown_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            battle_id INTEGER NOT NULL UNIQUE,
            season_key TEXT NOT NULL,
            defender TEXT NOT NULL,
            challenger TEXT NOT NULL,
            winner TEXT NOT NULL,
            successful_defense INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    # V6.9: direct hunter-to-hunter challenge requests and inbox state.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS challenge_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            challenger TEXT NOT NULL,
            opponent TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            responded_at TEXT DEFAULT '',
            battle_id INTEGER DEFAULT 0
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_challenge_opponent_status ON challenge_requests(opponent, status, id DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_challenge_challenger_status ON challenge_requests(challenger, status, id DESC)")

    # V7.0: private notification stream for signed-in hunters.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'signal',
            title TEXT NOT NULL,
            detail TEXT DEFAULT '',
            link TEXT DEFAULT '',
            is_read INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(username, is_read, id DESC)")

    # V7.3: lightweight social graph for follows and rivalries.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hunter_connections (
            owner TEXT NOT NULL,
            target TEXT NOT NULL,
            kind TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (owner, target, kind)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hunter_connections_target_kind ON hunter_connections(target, kind)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hunter_connections_owner_kind ON hunter_connections(owner, kind)")

    # V8.1: one optional equipped public title per Hunter.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hunter_title_choices (
            username TEXT PRIMARY KEY,
            title_key TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # V8.2: optional featured Trophy pinned to the public Hunter identity.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hunter_showcase_choices (
            username TEXT PRIMARY KEY,
            trophy_key TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # V8.4: optional visual skin for the public Hunter Loadout.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hunter_loadout_skins (
            username TEXT PRIMARY KEY,
            skin_key TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # V10.6: one optional public Featured Nemesis per Hunter.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hunter_featured_nemesis (
            username TEXT PRIMARY KEY,
            rival TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # V12.4: immutable public Feud escalation events. One milestone event max per Clash.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS feud_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            battle_id INTEGER NOT NULL UNIQUE,
            hunter_a TEXT NOT NULL,
            hunter_b TEXT NOT NULL,
            winner TEXT NOT NULL,
            old_tier_key TEXT NOT NULL,
            new_tier_key TEXT NOT NULL,
            tier_level INTEGER NOT NULL,
            icon TEXT NOT NULL,
            label TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_feud_events_id_desc ON feud_events(id DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_feud_events_pair ON feud_events(hunter_a, hunter_b, id DESC)")

    # V12.6: story-grade moments detected from real completed direct Clashes.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS feud_moments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            battle_id INTEGER NOT NULL UNIQUE,
            hunter_a TEXT NOT NULL,
            hunter_b TEXT NOT NULL,
            winner TEXT NOT NULL,
            loser TEXT NOT NULL,
            moment_key TEXT NOT NULL,
            icon TEXT NOT NULL,
            label TEXT NOT NULL,
            detail TEXT NOT NULL,
            intensity INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_feud_moments_id_desc ON feud_moments(id DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_feud_moments_pair ON feud_moments(hunter_a, hunter_b, id DESC)")

    # V12.8: lightweight viral-loop attribution. No IP, wallet, or personal identifier is stored.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS feud_viral_clicks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            moment_id INTEGER NOT NULL,
            action_key TEXT NOT NULL,
            target TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_feud_viral_clicks_moment ON feud_viral_clicks(moment_id, id DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_feud_viral_clicks_action ON feud_viral_clicks(action_key, id DESC)")

    # V8.8: baseline of already-known unlocks + feed of newly discovered unlock events.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hunter_unlock_state (
            username TEXT NOT NULL,
            unlock_key TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            PRIMARY KEY (username, unlock_key)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hunter_unlock_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            unlock_key TEXT NOT NULL,
            kind TEXT NOT NULL,
            icon TEXT NOT NULL,
            title TEXT NOT NULL,
            detail TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_seen INTEGER NOT NULL DEFAULT 0,
            UNIQUE(username, unlock_key)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_unlock_events_user_seen ON hunter_unlock_events(username, is_seen, id DESC)")

    # Reputation events get an optional event_key so future signals can be idempotent.
    rep_cols = {row["name"] for row in conn.execute("PRAGMA table_info(reputation_events)").fetchall()}
    if "event_key" not in rep_cols:
        conn.execute("ALTER TABLE reputation_events ADD COLUMN event_key TEXT DEFAULT ''")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_rep_event_key ON reputation_events(event_key) WHERE event_key <> ''")

    # V6.6: seasons are non-destructive; old battles are assigned from their UTC month.
    battle_cols = {row["name"] for row in conn.execute("PRAGMA table_info(creature_battles)").fetchall()}
    if "season_key" not in battle_cols:
        conn.execute("ALTER TABLE creature_battles ADD COLUMN season_key TEXT DEFAULT ''")
    conn.execute("""UPDATE creature_battles
                    SET season_key = substr(created_at, 1, 7)
                    WHERE COALESCE(season_key, '') = ''""")

    conn.commit()
    conn.close()


def _notify(conn, username, kind, title, detail="", link=""):
    if not username:
        return
    conn.execute(
        """INSERT INTO notifications (username, kind, title, detail, link, is_read, created_at)
           VALUES (?, ?, ?, ?, ?, 0, ?)""",
        (username, kind, title[:160], detail[:500], link[:500], datetime.utcnow().isoformat())
    )


def _add_rep(conn, username, points, reason, event_key="", daily_cap=None, daily_prefix=None):
    """Add REP without minting XP. Optional daily cap limits farmable event families."""
    if not username or not points:
        return False
    if event_key:
        exists = conn.execute("SELECT 1 FROM reputation_events WHERE event_key = ?", (event_key,)).fetchone()
        if exists:
            return False
    if daily_cap is not None and daily_prefix:
        today = datetime.utcnow().strftime("%Y-%m-%d")
        n = conn.execute(
            """SELECT COUNT(*) AS n FROM reputation_events
               WHERE username = ? AND reason LIKE ? AND substr(created_at,1,10) = ?""",
            (username, daily_prefix + "%", today)
        ).fetchone()["n"]
        if int(n or 0) >= int(daily_cap):
            return False
    conn.execute(
        """INSERT INTO reputation_events (username, points, reason, created_at, event_key)
           VALUES (?, ?, ?, ?, ?)""",
        (username, int(points), reason, datetime.utcnow().isoformat(), event_key or "")
    )
    return True


def get_user(username):
    conn = db()

    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if user is None:
        conn.execute(
            "INSERT INTO users (username) VALUES (?)",
            (username,)
        )
        conn.commit()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    conn.close()

    return user
# Initialize / migrate database when the app starts in production
init_db()

@app.route("/")
def home():

    return r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#050507">
<meta name="color-scheme" content="dark">
<meta name="description" content="BL3 is a live Human Alpha Network for Hunter identities, proof, rivalries, Clash moments, discovery and social competition.">
<meta name="robots" content="index,follow,max-image-preview:large">
<meta property="og:type" content="website">
<meta property="og:title" content="BL3 // Human Alpha Network">
<meta property="og:description" content="Enter the Human Alpha Network. Discover Hunters, rivalries, live Clash moments and the stories moving BL3.">
<meta name="twitter:card" content="summary_large_image">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<title>BL3 // Human Alpha Network</title>
<style>
:root{--bg:#050507;--panel:rgba(18,18,25,.72);--line:rgba(255,255,255,.09);--muted:#8f91a3;--text:#f7f7fb;--hot:#b8ff5a;--violet:#9d7bff}
*{box-sizing:border-box} body{margin:0;background:radial-gradient(circle at 50% -20%,#262044 0,#09090e 34%,var(--bg) 65%);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Arial;min-height:100vh}
body:before{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px);background-size:42px 42px;mask-image:linear-gradient(to bottom,black,transparent 80%)}
.shell{max-width:1180px;margin:auto;padding:22px}.nav{display:flex;align-items:center;justify-content:space-between;gap:14px;position:sticky;top:0;z-index:10;padding:10px 0;background:linear-gradient(var(--bg),transparent)}
.brand{font-weight:900;letter-spacing:-1px;font-size:23px}.brand span{color:var(--hot)}.pill,.btn,input,textarea,select{border:1px solid var(--line);background:rgba(255,255,255,.045);color:white;border-radius:14px}
.pill{padding:8px 12px;color:#c9cad3;font-size:12px}.hero{padding:78px 0 42px;text-align:center}.eyebrow{font-size:12px;letter-spacing:3px;color:var(--hot);font-weight:800}
h1{font-size:clamp(45px,8vw,96px);line-height:.88;letter-spacing:-5px;margin:18px auto;max-width:950px}.grad{background:linear-gradient(100deg,#fff,#b9a7ff 45%,#b8ff5a);-webkit-background-clip:text;color:transparent}
.lead{max-width:680px;margin:24px auto;color:#a9a9b6;font-size:17px;line-height:1.6}.ticker{display:flex;justify-content:center;gap:10px;flex-wrap:wrap}
.grid{display:grid;grid-template-columns:1.55fr .75fr;gap:16px}.card{background:var(--panel);border:1px solid var(--line);border-radius:24px;padding:20px;backdrop-filter:blur(18px);box-shadow:0 25px 80px rgba(0,0,0,.28)}
.card h2,.card h3{margin-top:0}.arena{position:relative;overflow:hidden;margin-top:12px;transition:.2s transform,.2s border-color}.arena:hover{transform:translateY(-2px);border-color:rgba(184,255,90,.35)}
.live{color:var(--hot);font-size:11px;font-weight:900;letter-spacing:2px}.bounty{font-size:25px;font-weight:900;margin:10px 0}.meta{color:var(--muted);font-size:13px;line-height:1.5}.btn{cursor:pointer;padding:13px 16px;font-weight:800;width:100%;margin-top:10px}.btn:hover{background:#fff;color:#08080a}.btn.hot{background:var(--hot);color:#090b06;border:0}.btn.violet{background:var(--violet);border:0}
input,textarea,select{width:100%;padding:13px;margin:6px 0;outline:none}textarea{min-height:100px;resize:vertical}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(74px,1fr));gap:8px}.stat{padding:14px;border:1px solid var(--line);border-radius:16px;text-align:center}.num{font-size:21px;font-weight:900}.small{font-size:11px;color:var(--muted)}
.section-title{display:flex;justify-content:space-between;align-items:end;margin:38px 0 12px}.section-title h2{margin:0;font-size:30px}.leader{display:flex;justify-content:space-between;padding:11px 0;border-bottom:1px solid var(--line)}
.tabs{display:flex;gap:8px;flex-wrap:wrap}.tab{width:auto;padding:9px 13px}.message{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#181821;border:1px solid var(--line);padding:12px 18px;border-radius:999px;z-index:30;max-width:90%;text-align:center}
.hidden{display:none}.season-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:12px}.season-tile{padding:12px;border:1px solid var(--line);border-radius:14px;background:rgba(255,255,255,.025)}.crown-holder{font-size:19px;font-weight:900;color:var(--hot);margin-top:4px}.mission{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:11px 0;border-bottom:1px solid var(--line)}.mission:last-child{border-bottom:0}.mission-ok{color:var(--hot);font-weight:900}.mission-wait{color:var(--muted);font-weight:800}.proof{padding:10px;border:1px solid var(--line);border-radius:14px;margin-top:8px}.footer{text-align:center;color:#656675;padding:55px 0 30px}
.creature-card{position:relative;overflow:hidden;background:radial-gradient(circle at 50% 18%,rgba(184,255,90,.12),transparent 38%),var(--panel)}
.creature-card:after{content:"";position:absolute;width:150px;height:150px;border-radius:50%;background:rgba(157,123,255,.09);filter:blur(28px);right:-45px;top:-45px;pointer-events:none}
.creature-head{display:flex;align-items:center;gap:14px;margin:14px 0}.creature-avatar{width:76px;height:76px;border:1px solid rgba(184,255,90,.35);border-radius:22px;display:grid;place-items:center;font-size:42px;background:rgba(184,255,90,.06);box-shadow:0 0 28px rgba(184,255,90,.08)}
.creature-name{font-size:20px;font-weight:900}.creature-stage{color:var(--hot);font-size:12px;font-weight:800;letter-spacing:1.5px;text-transform:uppercase}.progress{height:9px;background:#24242d;border-radius:999px;overflow:hidden;margin:8px 0 6px}.progress>div{height:100%;width:0;background:linear-gradient(90deg,var(--violet),var(--hot));border-radius:999px;transition:width .45s ease}.passport-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:12px}.passport-grid .stat{padding:11px 6px}.empire{display:flex;justify-content:space-between;align-items:center;padding:12px 0 2px;border-top:1px solid var(--line);margin-top:13px}.empire b{color:var(--hot)}.battle-result{margin-top:12px;padding:14px;border:1px solid rgba(184,255,90,.25);border-radius:16px;background:rgba(184,255,90,.04)}.battle-vs{font-size:24px;font-weight:950;text-align:center;margin:8px 0}.battle-log{font-size:13px;color:var(--muted);line-height:1.5}.battle-actions{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px}@media(max-width:520px){.battle-actions{grid-template-columns:1fr}}
.inbox-item{padding:12px;border:1px solid var(--line);border-radius:16px;margin-top:9px;background:rgba(255,255,255,.025)}.inbox-top{display:flex;justify-content:space-between;gap:10px;align-items:center}.inbox-title{font-weight:900}.inbox-actions{display:grid;grid-template-columns:1fr 1fr;gap:8px}.inbox-badge{color:var(--hot);font-weight:900}.btn.danger:hover{background:#ff6b7a;color:#09090c}.nav-right{display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end}.signal-item{padding:12px;border:1px solid var(--line);border-radius:16px;margin-top:9px;background:rgba(255,255,255,.022)}.signal-item.unread{border-color:rgba(184,255,90,.32);background:rgba(184,255,90,.045)}.signal-top{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.signal-title{font-weight:900}.signal-link{color:var(--hot);text-decoration:none;font-size:12px;font-weight:900}.rep-positive{color:var(--hot);font-weight:900}
@media(max-width:820px){.grid{grid-template-columns:1fr}.hero{padding-top:45px}h1{letter-spacing:-3px}.nav .pill:nth-child(2){display:none}.shell{padding:14px}}
.onboarding{margin:0 0 28px;background:linear-gradient(135deg,rgba(184,255,90,.07),rgba(157,123,255,.07)),var(--panel);border-color:rgba(184,255,90,.22)}
.onboarding-top{display:flex;justify-content:space-between;gap:18px;align-items:flex-start}.onboarding h2{margin:6px 0 8px}.onboarding-progress{font-size:28px;font-weight:950;color:var(--hot);white-space:nowrap}.onboarding-steps{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:16px}.onboarding-step{border:1px solid var(--line);border-radius:18px;padding:14px;background:rgba(255,255,255,.025);transition:.2s}.onboarding-step.done{border-color:rgba(184,255,90,.35);background:rgba(184,255,90,.05)}.onboarding-step .step-num{font-size:11px;letter-spacing:1.8px;color:var(--muted);font-weight:900}.onboarding-step.done .step-num{color:var(--hot)}.onboarding-step b{display:block;margin:7px 0 5px}.onboarding-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.onboarding-actions .btn{width:auto;margin-top:0}.onboarding-dismiss{width:auto;margin:0;padding:8px 11px;font-size:12px}.onboarding.hidden-by-user{display:none}@media(max-width:720px){.onboarding-steps{grid-template-columns:1fr}.onboarding-top{flex-direction:column}.onboarding-progress{font-size:22px}}

/* ===== V13.3 GLOBAL SEARCH ===== */
:root{--bg:#040406;--panel:rgba(13,13,19,.86);--line:rgba(255,255,255,.105);--muted:#858899;--text:#fbfbff;--hot:#baff5a;--violet:#a17cff;--cyan:#61f4ff;--gold:#ffd66b}
body{background:
radial-gradient(circle at 12% 0%,rgba(161,124,255,.19),transparent 29%),
radial-gradient(circle at 90% 11%,rgba(186,255,90,.11),transparent 27%),
radial-gradient(circle at 50% 105%,rgba(97,244,255,.055),transparent 32%),
#040406}
body:before{background-image:linear-gradient(rgba(255,255,255,.02) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.02) 1px,transparent 1px);background-size:54px 54px;opacity:.65}
.shell{max-width:1280px;padding:20px 28px 38px}
.nav{top:12px;padding:11px 14px;border:1px solid var(--line);border-radius:18px;background:rgba(7,7,11,.78);backdrop-filter:blur(22px);box-shadow:0 18px 55px rgba(0,0,0,.32)}
.brand{font-size:25px;letter-spacing:-1.2px}.brand:after{content:" / V13.3";font-size:9px;letter-spacing:1.5px;color:var(--muted);margin-left:8px;vertical-align:middle}
.nav .pill{background:#0d0d13;border-color:rgba(255,255,255,.1)}
.nav-right .pill:first-child{border-color:rgba(186,255,90,.2)}
.hero{padding:46px 0 28px;text-align:left}
.hero-v9{position:relative;display:grid;grid-template-columns:minmax(0,1.28fr) minmax(320px,.72fr);gap:18px;align-items:stretch}
.hero-copy,.hero-core{position:relative;overflow:hidden;border:1px solid var(--line);border-radius:34px;background:linear-gradient(145deg,rgba(20,20,29,.88),rgba(8,8,12,.88));box-shadow:0 35px 100px rgba(0,0,0,.36)}
.hero-copy{padding:54px 52px}.hero-copy:before{content:"";position:absolute;inset:auto auto -170px -110px;width:420px;height:420px;border-radius:50%;background:rgba(161,124,255,.16);filter:blur(50px)}
.hero-copy:after{content:"";position:absolute;right:-100px;top:-120px;width:300px;height:300px;border-radius:50%;background:rgba(186,255,90,.08);filter:blur(38px)}
.hero-copy>*{position:relative;z-index:1}.hero-kicker{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.hero-status{display:inline-flex;align-items:center;gap:7px;border:1px solid rgba(186,255,90,.22);background:rgba(186,255,90,.055);padding:8px 11px;border-radius:999px;font-size:10px;letter-spacing:1.4px;font-weight:900;color:var(--hot)}
.hero-status i{width:7px;height:7px;border-radius:50%;background:var(--hot);box-shadow:0 0 14px var(--hot)}
.hero h1{font-size:clamp(56px,7vw,104px);line-height:.86;letter-spacing:-6px;margin:21px 0 20px;max-width:780px}
.hero .lead{max-width:690px;margin:0;color:#a7a8b6;font-size:16px;line-height:1.7}
.hero-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:28px}.hero-actions .btn{width:auto;margin:0;padding:13px 18px}.btn.ghost{background:transparent;color:#fff}.btn.ghost:hover{background:#fff;color:#08080a}
.ticker{justify-content:flex-start;margin-top:30px;gap:8px}.ticker .pill{min-width:132px;padding:12px 14px;background:rgba(255,255,255,.035)}.ticker .pill b{display:block;font-size:20px;color:#fff;margin-bottom:2px}.ticker .pill{font-size:9px;letter-spacing:1.2px;color:var(--muted);font-weight:800}
.hero-core{padding:24px;display:flex;flex-direction:column;justify-content:space-between;background:radial-gradient(circle at 60% 20%,rgba(186,255,90,.11),transparent 33%),linear-gradient(160deg,#101018,#08080d)}
.core-top{display:flex;align-items:center;justify-content:space-between;gap:10px}.core-badge{font-size:9px;letter-spacing:1.8px;color:var(--muted);font-weight:900}.core-orb{width:178px;height:178px;border-radius:50%;margin:18px auto;display:grid;place-items:center;position:relative;background:radial-gradient(circle,rgba(186,255,90,.2),rgba(161,124,255,.08) 45%,transparent 68%);border:1px solid rgba(186,255,90,.22);box-shadow:inset 0 0 50px rgba(186,255,90,.06),0 0 65px rgba(161,124,255,.08)}
.core-orb:before,.core-orb:after{content:"";position:absolute;border-radius:50%;border:1px solid rgba(255,255,255,.09)}.core-orb:before{inset:-14px}.core-orb:after{inset:24px;border-style:dashed}.core-glyph{font-size:66px;filter:drop-shadow(0 0 18px rgba(186,255,90,.22))}
.core-title{text-align:center;font-size:22px;font-weight:950;letter-spacing:-.8px}.core-sub{text-align:center;color:var(--muted);font-size:11px;line-height:1.5;margin:6px auto 18px;max-width:250px}
.core-lines{display:grid;gap:8px}.core-line{display:flex;justify-content:space-between;gap:12px;padding:11px 12px;border:1px solid var(--line);border-radius:13px;background:rgba(255,255,255,.025);font-size:10px}.core-line span:first-child{color:var(--muted);font-weight:800}.core-line b{color:var(--hot);letter-spacing:.7px}
.command-deck{display:grid;grid-template-columns:1.15fr repeat(5,1fr);gap:9px;margin:0 0 20px}.command-label,.command-link{min-height:72px;border:1px solid var(--line);border-radius:18px;background:rgba(12,12,18,.72);padding:13px;text-decoration:none;color:#fff;display:flex;flex-direction:column;justify-content:center;transition:.2s}.command-label{background:linear-gradient(135deg,rgba(161,124,255,.12),rgba(186,255,90,.05))}.command-link:hover{transform:translateY(-2px);border-color:rgba(186,255,90,.35);background:rgba(186,255,90,.045)}.command-link b,.command-label b{font-size:12px}.command-link span,.command-label span{font-size:9px;color:var(--muted);margin-top:4px;letter-spacing:.8px}
.onboarding{border-radius:28px;padding:24px;background:linear-gradient(120deg,rgba(186,255,90,.055),rgba(161,124,255,.075)),rgba(12,12,18,.88);box-shadow:0 25px 80px rgba(0,0,0,.24)}
.grid{grid-template-columns:minmax(0,1.42fr) minmax(340px,.78fr);gap:20px}
.card{border-radius:22px;background:linear-gradient(145deg,rgba(17,17,24,.9),rgba(10,10,15,.86));box-shadow:0 18px 55px rgba(0,0,0,.22)}
#arenaSection{padding:4px 2px}.section-title{margin-top:26px}.section-title h2{font-size:36px;letter-spacing:-1.5px}
.arena{border-radius:22px!important;padding:22px!important}.arena:before{content:"LIVE";position:absolute;right:14px;top:14px;font-size:8px;letter-spacing:1.8px;color:var(--hot);border:1px solid rgba(186,255,90,.18);border-radius:999px;padding:5px 7px;background:rgba(186,255,90,.04)}
.creature-card{border-color:rgba(186,255,90,.18);box-shadow:0 22px 70px rgba(0,0,0,.25),0 0 0 1px rgba(186,255,90,.02)}
.creature-avatar{width:88px;height:88px;border-radius:28px;font-size:48px}.passport-grid .stat{background:rgba(255,255,255,.025)}
aside>.card:not(:first-child){transition:.2s transform,.2s border-color}aside>.card:not(:first-child):hover{transform:translateY(-2px);border-color:rgba(161,124,255,.26)}
.footer{padding-top:70px;font-size:10px;letter-spacing:1.3px}
@media(max-width:960px){.hero-v9{grid-template-columns:1fr}.hero-copy{padding:38px 30px}.hero-core{min-height:360px}.command-deck{grid-template-columns:repeat(2,1fr)}.command-label{grid-column:1/-1}.grid{grid-template-columns:1fr}}
@media(max-width:620px){.shell{padding:10px}.nav{top:7px;border-radius:15px}.nav-right{gap:5px}.nav-right .pill{padding:7px 8px;font-size:9px}.hero{padding-top:24px}.hero-copy{padding:30px 20px;border-radius:25px}.hero-core{border-radius:25px}.hero h1{font-size:50px;letter-spacing:-4px}.hero-actions .btn{width:100%}.ticker{display:grid;grid-template-columns:repeat(3,1fr)}.ticker .pill{min-width:0;text-align:center;padding:10px 5px}.ticker .pill b{font-size:17px}.command-deck{grid-template-columns:1fr 1fr}.onboarding{padding:18px}.section-title h2{font-size:30px}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.hud-strip{display:grid;grid-template-columns:1.15fr .85fr;gap:9px;margin-top:12px}
.hud-card{border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.026);padding:12px}
.hud-card .hud-label{font-size:8px;letter-spacing:1.4px;color:var(--muted);font-weight:900}
.hud-card .hud-value{font-size:17px;font-weight:950;margin-top:5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hud-card .hud-sub{font-size:9px;color:var(--muted);margin-top:3px}
.hud-title{display:flex;align-items:center;gap:7px;color:var(--hot)}
.hud-next{margin-top:10px;padding:12px;border:1px solid rgba(161,124,255,.22);border-radius:15px;background:linear-gradient(120deg,rgba(161,124,255,.07),rgba(186,255,90,.025))}
.hud-next-top{display:flex;align-items:center;justify-content:space-between;gap:12px}
.hud-next-top span{font-size:8px;letter-spacing:1.3px;color:var(--muted);font-weight:900}
.hud-next-top b{font-size:11px;color:var(--hot)}
.hud-next-title{font-size:13px;font-weight:950;margin:5px 0}
.hud-meter{height:6px;border-radius:999px;background:#08080c;border:1px solid var(--line);overflow:hidden}
.hud-meter i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--hot),var(--violet));transition:width .35s ease}
.hud-links{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;margin-top:10px}
.hud-link{border:1px solid var(--line);border-radius:12px;padding:9px 7px;text-align:center;text-decoration:none;color:#fff;font-size:9px;font-weight:900;background:rgba(255,255,255,.025)}
.hud-link:hover{border-color:rgba(186,255,90,.3);color:var(--hot)}
.hud-unlock-badge{display:inline-flex;align-items:center;gap:5px;padding:5px 7px;border:1px solid rgba(255,214,107,.25);border-radius:999px;color:var(--gold);font-size:8px;font-weight:900}
@media(max-width:620px){.hud-strip{grid-template-columns:1fr}.hud-links{grid-template-columns:1fr 1fr 1fr}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.network-pulse{position:relative;overflow:hidden;margin:0 0 20px;border:1px solid var(--line);border-radius:22px;background:linear-gradient(110deg,rgba(11,11,16,.92),rgba(19,14,27,.9));box-shadow:0 18px 52px rgba(0,0,0,.2)}
.network-pulse:before{content:"";position:absolute;left:-70px;top:-70px;width:180px;height:180px;border-radius:50%;background:rgba(186,255,90,.07);filter:blur(34px)}
.pulse-head{position:relative;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 16px;border-bottom:1px solid var(--line)}
.pulse-title{display:flex;align-items:center;gap:9px}.pulse-live-dot{width:8px;height:8px;border-radius:50%;background:var(--hot);box-shadow:0 0 15px var(--hot);animation:pulseDot 1.6s ease-in-out infinite}
.pulse-title b{font-size:11px;letter-spacing:1.5px}.pulse-title span{font-size:9px;color:var(--muted);letter-spacing:1px}
.pulse-meta{font-size:9px;color:var(--muted);font-weight:900;letter-spacing:1px}
.pulse-track-wrap{position:relative;overflow:hidden;padding:10px 0}
.pulse-track{display:flex;gap:9px;width:max-content;padding:0 12px;will-change:transform;animation:pulseScroll 45s linear infinite}
.network-pulse:hover .pulse-track{animation-play-state:paused}
.pulse-item{display:grid;grid-template-columns:34px minmax(200px,310px) auto;gap:10px;align-items:center;min-width:315px;max-width:390px;padding:10px 12px;border:1px solid var(--line);border-radius:15px;background:rgba(255,255,255,.025)}
.pulse-icon{width:34px;height:34px;border-radius:11px;display:grid;place-items:center;background:#0a0a0f;border:1px solid var(--line);font-size:18px}
.pulse-copy{min-width:0}.pulse-copy b{display:block;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.pulse-copy span{display:block;font-size:9px;color:var(--muted);margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pulse-time{font-size:8px;color:var(--muted);font-weight:900;white-space:nowrap}.pulse-kind{display:inline-flex;margin-left:5px;font-size:7px;color:var(--hot);border:1px solid rgba(186,255,90,.15);border-radius:999px;padding:2px 5px;letter-spacing:.8px}
.pulse-empty{padding:16px;color:var(--muted);font-size:11px}
@keyframes pulseDot{0%,100%{opacity:.55;transform:scale(.86)}50%{opacity:1;transform:scale(1.15)}}
@keyframes pulseScroll{from{transform:translateX(0)}to{transform:translateX(-50%)}}
@media(max-width:620px){.pulse-head{align-items:flex-start;flex-direction:column}.pulse-item{min-width:285px;grid-template-columns:32px minmax(170px,245px) auto}.pulse-meta{display:none}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.heat-zone{display:grid;grid-template-columns:1.1fr .9fr;gap:12px;margin:0 0 22px}
.heat-panel{border:1px solid var(--line);border-radius:24px;background:linear-gradient(145deg,rgba(17,17,24,.92),rgba(8,8,13,.9));padding:18px;overflow:hidden;position:relative}
.heat-panel:after{content:"";position:absolute;right:-70px;top:-80px;width:190px;height:190px;border-radius:50%;background:rgba(255,79,216,.07);filter:blur(40px);pointer-events:none}
.heat-top{display:flex;align-items:flex-end;justify-content:space-between;gap:12px;position:relative;z-index:1}
.heat-top h2{font-size:24px;margin:5px 0 0;letter-spacing:-1px}.heat-top .meta{font-size:9px;max-width:290px;text-align:right}
.hunter-heat-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:14px;position:relative;z-index:1}
.heat-hunter{border:1px solid var(--line);border-radius:16px;padding:11px;background:rgba(255,255,255,.022);text-decoration:none;color:#fff;transition:.18s}
.heat-hunter:hover{transform:translateY(-2px);border-color:rgba(186,255,90,.28)}
.heat-hunter-head{display:flex;align-items:center;justify-content:space-between;gap:8px}.heat-id{display:flex;align-items:center;gap:8px;min-width:0}.heat-avatar{width:34px;height:34px;border-radius:11px;display:grid;place-items:center;background:#09090e;border:1px solid var(--line);font-size:18px}.heat-name{min-width:0}.heat-name b{display:block;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.heat-name span{font-size:8px;color:var(--muted)}.heat-score{font-size:10px;color:var(--hot);font-weight:950}
.heat-bar{height:5px;margin-top:9px;border:1px solid var(--line);background:#07070b;border-radius:999px;overflow:hidden}.heat-bar i{display:block;height:100%;background:linear-gradient(90deg,var(--violet),#ff4fd8,var(--hot));border-radius:999px}
.heat-tags{display:flex;gap:5px;flex-wrap:wrap;margin-top:7px}.heat-tag{font-size:7px;color:var(--muted);border:1px solid var(--line);padding:3px 5px;border-radius:999px}
.rivalry-heat-list{display:grid;gap:9px;margin-top:14px;position:relative;z-index:1}
.hot-rivalry{display:block;text-decoration:none;color:#fff;border:1px solid var(--line);border-radius:16px;padding:12px;background:rgba(255,255,255,.022)}
.hot-rivalry:hover{border-color:rgba(255,79,216,.25)}.rivalry-line{display:flex;justify-content:space-between;align-items:center;gap:8px}.rivalry-line b{font-size:10px}.rivalry-line span{font-size:9px;color:var(--muted)}.rivalry-score{margin-top:6px;font-size:9px;color:#c8c8d2}
.heat-empty{color:var(--muted);border:1px dashed var(--line);padding:14px;border-radius:14px;margin-top:12px;font-size:10px}
@media(max-width:900px){.heat-zone{grid-template-columns:1fr}}@media(max-width:560px){.hunter-heat-grid{grid-template-columns:1fr}.heat-top{align-items:flex-start;flex-direction:column}.heat-top .meta{text-align:left}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.spotlight{margin:0 0 22px;border:1px solid var(--line);border-radius:26px;background:linear-gradient(140deg,rgba(18,18,25,.95),rgba(8,8,13,.93));overflow:hidden;position:relative}
.spotlight:before{content:"";position:absolute;inset:-90px auto auto -80px;width:250px;height:250px;border-radius:50%;background:rgba(161,124,255,.09);filter:blur(48px)}
.spotlight:after{content:"";position:absolute;right:-80px;bottom:-120px;width:280px;height:280px;border-radius:50%;background:rgba(186,255,90,.07);filter:blur(52px)}
.spot-head{position:relative;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:15px 18px;border-bottom:1px solid var(--line)}
.spot-title-wrap{display:flex;align-items:center;gap:10px}.spot-live{width:9px;height:9px;border-radius:50%;background:#ff4fd8;box-shadow:0 0 16px #ff4fd8}.spot-head b{font-size:11px;letter-spacing:1.5px}.spot-head span{font-size:9px;color:var(--muted);letter-spacing:1px}.spot-pager{display:flex;gap:6px}.spot-dot{width:7px;height:7px;border-radius:50%;border:1px solid var(--line);background:#121219;transition:.2s}.spot-dot.active{background:var(--hot);border-color:var(--hot);box-shadow:0 0 10px rgba(186,255,90,.5)}
.spot-body{position:relative;z-index:2;display:grid;grid-template-columns:1.1fr .9fr;gap:0;min-height:250px}
.spot-main{padding:28px}.spot-kicker{font-size:9px;letter-spacing:1.7px;color:var(--hot);font-weight:900}.spot-name{font-size:clamp(34px,5vw,58px);line-height:.95;letter-spacing:-2.8px;font-weight:950;margin:9px 0 12px}.spot-meta{color:var(--muted);font-size:11px;line-height:1.55}.spot-actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:20px}.spot-actions a{display:inline-flex;text-decoration:none;padding:10px 13px;border-radius:12px;border:1px solid var(--line);font-size:9px;font-weight:900;color:#fff}.spot-actions a.hot{background:var(--hot);color:#07070a;border-color:var(--hot)}.spot-actions a.alt{background:rgba(161,124,255,.11);border-color:rgba(161,124,255,.24)}
.spot-side{padding:24px;border-left:1px solid var(--line);display:flex;flex-direction:column;justify-content:center;align-items:center;text-align:center;background:radial-gradient(circle at 50% 35%,rgba(255,79,216,.09),transparent 46%)}.spot-avatar{width:118px;height:118px;border-radius:36px;display:grid;place-items:center;font-size:62px;background:#09090e;border:1px solid rgba(255,255,255,.12);box-shadow:0 18px 55px rgba(0,0,0,.34)}.spot-side b{font-size:18px;margin-top:13px}.spot-side span{font-size:9px;color:var(--muted);margin-top:5px}.spot-stat-row{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;width:100%;margin-top:15px}.spot-stat{border:1px solid var(--line);border-radius:12px;padding:8px;background:rgba(255,255,255,.02)}.spot-stat strong{display:block;font-size:15px}.spot-stat small{font-size:7px;color:var(--muted);letter-spacing:.8px}
.spot-fade{animation:spotIn .32s ease}.spot-empty{padding:30px;color:var(--muted);font-size:11px}
@keyframes spotIn{from{opacity:.2;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
@media(max-width:760px){.spot-body{grid-template-columns:1fr}.spot-side{border-left:none;border-top:1px solid var(--line)}.spot-main{padding:22px}.spot-name{font-size:38px}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.season-command{display:grid;grid-template-columns:1.05fr .95fr;gap:12px;margin:0 0 22px}
.season-command-main,.season-command-board{border:1px solid var(--line);border-radius:26px;background:linear-gradient(145deg,rgba(17,17,24,.94),rgba(8,8,13,.92));padding:20px;position:relative;overflow:hidden}
.season-command-main:before{content:"";position:absolute;left:-70px;top:-90px;width:220px;height:220px;border-radius:50%;background:rgba(255,214,107,.08);filter:blur(46px)}
.season-command-main>*{position:relative;z-index:1}
.season-command-top{display:flex;align-items:flex-end;justify-content:space-between;gap:12px}.season-command-top h2{margin:5px 0 0;font-size:28px;letter-spacing:-1.3px}.season-countdown{text-align:right}.season-countdown b{display:block;font-size:22px;color:var(--gold)}.season-countdown span{font-size:8px;color:var(--muted);letter-spacing:1.2px}
.crown-command{margin-top:16px;border:1px solid rgba(255,214,107,.22);background:linear-gradient(130deg,rgba(255,214,107,.055),rgba(161,124,255,.05));border-radius:20px;padding:16px;display:grid;grid-template-columns:auto 1fr auto;gap:13px;align-items:center}.crown-icon{width:58px;height:58px;border-radius:18px;display:grid;place-items:center;font-size:30px;background:#0a0906;border:1px solid rgba(255,214,107,.22)}.crown-name b{font-size:18px}.crown-name span{display:block;color:var(--muted);font-size:9px;margin-top:3px}.crown-record{text-align:right}.crown-record b{font-size:18px;color:var(--gold)}.crown-record span{display:block;font-size:8px;color:var(--muted)}
.season-stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:12px}.season-stat{border:1px solid var(--line);border-radius:15px;padding:11px;background:rgba(255,255,255,.022)}.season-stat b{display:block;font-size:18px}.season-stat span{font-size:8px;color:var(--muted);letter-spacing:1px}
.season-board-head{display:flex;justify-content:space-between;align-items:flex-end;gap:10px}.season-board-head h3{margin:5px 0 0;font-size:22px}.season-top3{display:grid;gap:8px;margin-top:14px}.season-leader-card{display:grid;grid-template-columns:34px 1fr auto;gap:10px;align-items:center;border:1px solid var(--line);border-radius:16px;padding:11px;background:rgba(255,255,255,.022);text-decoration:none;color:#fff}.season-rank{font-size:17px;font-weight:950;color:var(--hot)}.season-leader-main b{font-size:11px}.season-leader-main span{display:block;font-size:8px;color:var(--muted);margin-top:2px}.season-leader-record{text-align:right}.season-leader-record b{font-size:11px}.season-leader-record span{display:block;font-size:8px;color:var(--muted);margin-top:2px}
.season-empty{color:var(--muted);border:1px dashed var(--line);padding:14px;border-radius:14px;margin-top:12px;font-size:10px}
@media(max-width:900px){.season-command{grid-template-columns:1fr}}@media(max-width:560px){.season-command-top{align-items:flex-start;flex-direction:column}.season-countdown{text-align:left}.crown-command{grid-template-columns:auto 1fr}.crown-record{grid-column:1/-1;text-align:left}.season-stats-row{grid-template-columns:1fr 1fr}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.crown-war{margin:0 0 22px;border:1px solid rgba(255,94,94,.2);border-radius:26px;background:linear-gradient(140deg,rgba(31,10,14,.93),rgba(11,8,13,.95));overflow:hidden;position:relative;display:none}
.crown-war.active{display:block}.crown-war.stable{border-color:rgba(255,214,107,.2);background:linear-gradient(140deg,rgba(26,20,8,.9),rgba(10,9,12,.95))}
.crown-war:before{content:"";position:absolute;inset:-80px auto auto -80px;width:230px;height:230px;border-radius:50%;background:rgba(255,68,91,.12);filter:blur(48px)}.crown-war.stable:before{background:rgba(255,214,107,.09)}
.crown-war-head{position:relative;z-index:2;display:flex;justify-content:space-between;gap:14px;align-items:center;padding:15px 18px;border-bottom:1px solid rgba(255,255,255,.08)}
.war-status{display:flex;align-items:center;gap:9px}.war-dot{width:9px;height:9px;border-radius:50%;background:#ff445b;box-shadow:0 0 16px #ff445b;animation:warPulse 1.2s infinite}.crown-war.stable .war-dot{background:var(--gold);box-shadow:0 0 15px var(--gold)}
.war-status b{font-size:11px;letter-spacing:1.5px}.war-status span{display:block;font-size:8px;color:var(--muted);margin-top:2px;letter-spacing:1px}
.war-count{font-size:10px;color:#ff8394;font-weight:950}.crown-war.stable .war-count{color:var(--gold)}
.crown-war-body{position:relative;z-index:2;display:grid;grid-template-columns:.9fr 1.1fr;gap:0}
.war-crown{padding:24px;display:flex;align-items:center;gap:16px;border-right:1px solid rgba(255,255,255,.08)}
.war-avatar{width:76px;height:76px;border-radius:23px;display:grid;place-items:center;font-size:42px;background:#0a090d;border:1px solid rgba(255,255,255,.11);box-shadow:0 18px 50px rgba(0,0,0,.32)}
.war-copy h3{font-size:25px;margin:4px 0 6px;letter-spacing:-1px}.war-copy .meta{font-size:10px}.war-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:13px}.war-actions button,.war-actions a{border:1px solid rgba(255,255,255,.11);border-radius:11px;background:rgba(255,255,255,.03);color:#fff;padding:9px 11px;font-size:8px;font-weight:900;text-decoration:none;cursor:pointer}.war-actions .attack{background:#ff445b;color:#fff;border-color:#ff445b}.crown-war.stable .war-actions .attack{background:var(--gold);border-color:var(--gold);color:#080708}
.war-feed{padding:18px}.war-feed-title{font-size:9px;color:var(--muted);letter-spacing:1.4px;font-weight:900;margin-bottom:10px}.war-list{display:grid;gap:7px}.war-row{display:grid;grid-template-columns:28px 1fr auto;gap:9px;align-items:center;border:1px solid rgba(255,255,255,.08);border-radius:13px;padding:9px;background:rgba(255,255,255,.02)}.war-row .icon{width:28px;height:28px;border-radius:9px;display:grid;place-items:center;background:#09090d}.war-row b{font-size:9px}.war-row span{display:block;color:var(--muted);font-size:8px;margin-top:2px}.war-row em{font-size:8px;color:#ff8394;font-style:normal;font-weight:900}.war-empty{border:1px dashed rgba(255,255,255,.09);border-radius:12px;padding:12px;color:var(--muted);font-size:9px}
@keyframes warPulse{0%,100%{opacity:.55;transform:scale(.9)}50%{opacity:1;transform:scale(1.18)}}
@media(max-width:760px){.crown-war-body{grid-template-columns:1fr}.war-crown{border-right:none;border-bottom:1px solid rgba(255,255,255,.08)}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.war-alert-shell{position:fixed;inset:0;display:none;align-items:center;justify-content:center;z-index:9998;pointer-events:none;background:radial-gradient(circle at 50% 50%,rgba(255,68,91,.12),rgba(0,0,0,.28) 45%,rgba(0,0,0,.72));backdrop-filter:blur(3px)}
.war-alert-shell.show{display:flex;animation:warFlash .28s ease-out}
.war-alert-card{width:min(620px,calc(100vw - 30px));border:1px solid rgba(255,95,115,.4);border-radius:28px;background:linear-gradient(145deg,rgba(30,8,13,.98),rgba(9,8,12,.98));box-shadow:0 30px 120px rgba(0,0,0,.7),0 0 70px rgba(255,68,91,.12);padding:30px;text-align:center;position:relative;overflow:hidden}
.war-alert-card:before{content:"";position:absolute;inset:-90px auto auto -70px;width:240px;height:240px;border-radius:50%;background:rgba(255,68,91,.16);filter:blur(50px)}
.war-alert-card>*{position:relative;z-index:1}.war-alert-icon{font-size:64px;filter:drop-shadow(0 0 20px rgba(255,68,91,.34))}.war-alert-kicker{font-size:10px;letter-spacing:2.4px;color:#ff8394;font-weight:950;margin-top:10px}.war-alert-title{font-size:clamp(30px,6vw,52px);font-weight:950;letter-spacing:-2px;margin:8px 0}.war-alert-detail{font-size:12px;color:#aaaabd;line-height:1.55;max-width:500px;margin:0 auto}.war-alert-actions{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-top:18px;pointer-events:auto}.war-alert-actions button,.war-alert-actions a{border:1px solid rgba(255,255,255,.12);border-radius:12px;background:rgba(255,255,255,.04);color:#fff;padding:10px 13px;font-size:9px;font-weight:950;text-decoration:none;cursor:pointer}.war-alert-actions .danger{background:#ff445b;border-color:#ff445b}.war-alert-shell.defense .war-alert-card{border-color:rgba(255,214,107,.38);background:linear-gradient(145deg,rgba(27,21,8,.98),rgba(9,8,12,.98));box-shadow:0 30px 120px rgba(0,0,0,.7),0 0 70px rgba(255,214,107,.1)}.war-alert-shell.defense .war-alert-kicker{color:var(--gold)}
.war-mini-toast{position:fixed;right:18px;top:92px;z-index:9997;width:min(360px,calc(100vw - 36px));display:none;border:1px solid rgba(255,68,91,.3);border-radius:18px;background:rgba(18,8,12,.96);box-shadow:0 18px 60px rgba(0,0,0,.52);padding:14px;backdrop-filter:blur(16px)}.war-mini-toast.show{display:flex;gap:10px;align-items:flex-start;animation:warToastIn .25s ease-out}.war-mini-toast .ico{font-size:25px}.war-mini-toast b{display:block;font-size:11px}.war-mini-toast span{display:block;color:var(--muted);font-size:9px;margin-top:4px;line-height:1.45}
body.war-alarm .nav{box-shadow:0 0 0 1px rgba(255,68,91,.2),0 18px 55px rgba(0,0,0,.32),0 0 45px rgba(255,68,91,.08)}
@keyframes warFlash{from{opacity:0}to{opacity:1}}@keyframes warToastIn{from{opacity:0;transform:translateX(12px)}to{opacity:1;transform:translateX(0)}}
@media(max-width:620px){.war-alert-card{padding:24px 18px}.war-alert-icon{font-size:52px}.war-mini-toast{top:auto;bottom:16px}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.clash-replay-shell{position:fixed;inset:0;display:none;align-items:center;justify-content:center;z-index:10020;background:radial-gradient(circle at 50% 42%,rgba(161,124,255,.15),rgba(0,0,0,.45) 42%,rgba(0,0,0,.86));backdrop-filter:blur(8px);padding:18px}
.clash-replay-shell.show{display:flex;animation:replayFade .25s ease-out}
.clash-replay{width:min(900px,100%);border:1px solid rgba(255,255,255,.14);border-radius:30px;background:linear-gradient(145deg,rgba(18,18,26,.98),rgba(7,7,11,.99));box-shadow:0 40px 160px rgba(0,0,0,.76),0 0 80px rgba(161,124,255,.08);overflow:hidden;position:relative}
.clash-replay:before{content:"";position:absolute;inset:-150px auto auto -130px;width:340px;height:340px;border-radius:50%;background:rgba(161,124,255,.12);filter:blur(56px)}.clash-replay:after{content:"";position:absolute;right:-140px;bottom:-160px;width:360px;height:360px;border-radius:50%;background:rgba(186,255,90,.08);filter:blur(60px)}
.replay-top{position:relative;z-index:2;display:flex;justify-content:space-between;align-items:center;gap:12px;padding:15px 18px;border-bottom:1px solid rgba(255,255,255,.08)}.replay-top b{font-size:10px;letter-spacing:1.7px}.replay-top span{font-size:8px;color:var(--muted);letter-spacing:1px}.replay-close{pointer-events:auto;border:1px solid var(--line);border-radius:10px;background:rgba(255,255,255,.035);color:#fff;padding:8px 10px;cursor:pointer;font-size:9px;font-weight:900}
.replay-arena{position:relative;z-index:2;display:grid;grid-template-columns:1fr 140px 1fr;gap:14px;align-items:center;padding:34px 30px 22px}
.replay-fighter{text-align:center}.replay-avatar{width:128px;height:128px;margin:auto;border-radius:38px;display:grid;place-items:center;font-size:70px;background:#09090e;border:1px solid rgba(255,255,255,.12);box-shadow:0 20px 60px rgba(0,0,0,.38)}.replay-fighter.winner .replay-avatar{border-color:rgba(186,255,90,.38);box-shadow:0 20px 60px rgba(0,0,0,.38),0 0 38px rgba(186,255,90,.1)}.replay-fighter.loser{opacity:.68}
.replay-name{font-size:21px;font-weight:950;letter-spacing:-.7px;margin-top:12px}.replay-power{font-size:10px;color:var(--muted);margin-top:5px}.replay-power b{color:#fff;font-size:16px}
.replay-vs{text-align:center}.replay-vs .vs{font-size:44px;font-weight:950;letter-spacing:-2px;color:#fff}.replay-vs .battle-no{font-size:8px;color:var(--muted);letter-spacing:1.3px;margin-top:4px}.replay-slash{height:2px;background:linear-gradient(90deg,transparent,#ff4fd8,var(--hot),transparent);transform:rotate(-8deg);margin:14px -8px;box-shadow:0 0 18px rgba(255,79,216,.35)}
.replay-result{position:relative;z-index:2;text-align:center;padding:0 28px 28px}.replay-result .label{font-size:9px;letter-spacing:2px;color:var(--hot);font-weight:950}.replay-result h2{font-size:clamp(34px,7vw,62px);letter-spacing:-3px;margin:6px 0 8px}.replay-result p{max-width:650px;margin:0 auto;color:#a6a7b5;font-size:11px;line-height:1.6}
.replay-meter{display:grid;grid-template-columns:1fr 1fr;gap:8px;max-width:640px;margin:20px auto 0}.replay-meter-card{border:1px solid var(--line);border-radius:14px;padding:10px;background:rgba(255,255,255,.025)}.replay-meter-card span{font-size:8px;color:var(--muted);letter-spacing:1px}.replay-meter-card b{display:block;font-size:18px;margin-top:3px}
.replay-actions{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-top:18px;pointer-events:auto}.replay-actions button,.replay-actions a{border:1px solid var(--line);border-radius:11px;background:rgba(255,255,255,.035);color:#fff;padding:10px 12px;font-size:9px;font-weight:950;text-decoration:none;cursor:pointer}.replay-actions .hot{background:var(--hot);border-color:var(--hot);color:#07070a}.replay-actions .violet{background:rgba(161,124,255,.14);border-color:rgba(161,124,255,.28)}
.replay-step{opacity:0;transform:translateY(10px)}.clash-replay-shell.show .replay-step{animation:replayStep .45s ease forwards}.clash-replay-shell.show .replay-step.s2{animation-delay:.18s}.clash-replay-shell.show .replay-step.s3{animation-delay:.36s}.clash-replay-shell.show .replay-step.s4{animation-delay:.56s}
@keyframes replayFade{from{opacity:0}to{opacity:1}}@keyframes replayStep{to{opacity:1;transform:translateY(0)}}
@media(max-width:700px){.replay-arena{grid-template-columns:1fr 72px 1fr;padding:26px 14px 18px}.replay-avatar{width:86px;height:86px;border-radius:27px;font-size:48px}.replay-name{font-size:14px}.replay-vs .vs{font-size:30px}.replay-result{padding:0 16px 22px}.replay-meter{grid-template-columns:1fr 1fr}}

/* ===== V9.9 CLASH COMBO / WIN STREAK EFFECTS ===== */
.replay-combo{display:none;align-items:center;justify-content:center;gap:8px;margin:0 auto 12px;width:max-content;max-width:100%;padding:8px 12px;border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.03);font-size:9px;font-weight:950;letter-spacing:1.3px}
.replay-combo.show{display:flex}.replay-combo strong{font-size:12px;letter-spacing:.5px}.replay-combo.hot{color:#ffb34d;border-color:rgba(255,179,77,.32);box-shadow:0 0 28px rgba(255,122,50,.08)}.replay-combo.dominating{color:#ff63d7;border-color:rgba(255,79,216,.35);box-shadow:0 0 34px rgba(255,79,216,.10)}.replay-combo.unstoppable{color:var(--gold);border-color:rgba(255,214,107,.38);box-shadow:0 0 38px rgba(255,214,107,.11)}.replay-combo.mythic{color:#8ef7ff;border-color:rgba(97,244,255,.4);box-shadow:0 0 44px rgba(97,244,255,.12)}
.clash-replay.combo-hot{box-shadow:0 40px 160px rgba(0,0,0,.76),0 0 90px rgba(255,122,50,.11)}
.clash-replay.combo-dominating{box-shadow:0 40px 160px rgba(0,0,0,.76),0 0 110px rgba(255,79,216,.13)}
.clash-replay.combo-unstoppable{box-shadow:0 40px 160px rgba(0,0,0,.76),0 0 120px rgba(255,214,107,.14)}
.clash-replay.combo-mythic{box-shadow:0 40px 160px rgba(0,0,0,.76),0 0 135px rgba(97,244,255,.15)}
.combo-burst{position:absolute;inset:0;pointer-events:none;overflow:hidden;z-index:1;display:none}.combo-burst.show{display:block}.combo-burst i{position:absolute;left:50%;top:50%;width:6px;height:6px;border-radius:50%;background:currentColor;opacity:0;animation:comboBurst 1.1s ease-out forwards}.combo-burst i:nth-child(1){transform:translate(-50%,-50%) rotate(0deg) translateX(30px);animation-delay:.02s}.combo-burst i:nth-child(2){transform:translate(-50%,-50%) rotate(45deg) translateX(38px);animation-delay:.05s}.combo-burst i:nth-child(3){transform:translate(-50%,-50%) rotate(90deg) translateX(44px);animation-delay:.08s}.combo-burst i:nth-child(4){transform:translate(-50%,-50%) rotate(135deg) translateX(36px);animation-delay:.11s}.combo-burst i:nth-child(5){transform:translate(-50%,-50%) rotate(180deg) translateX(42px);animation-delay:.14s}.combo-burst i:nth-child(6){transform:translate(-50%,-50%) rotate(225deg) translateX(34px);animation-delay:.17s}.combo-burst i:nth-child(7){transform:translate(-50%,-50%) rotate(270deg) translateX(46px);animation-delay:.20s}.combo-burst i:nth-child(8){transform:translate(-50%,-50%) rotate(315deg) translateX(40px);animation-delay:.23s}
.combo-burst.hot{color:#ff9f43}.combo-burst.dominating{color:#ff4fd8}.combo-burst.unstoppable{color:#ffd66b}.combo-burst.mythic{color:#61f4ff}
.combo-toast{position:fixed;left:50%;top:86px;transform:translateX(-50%);z-index:10025;display:none;min-width:260px;max-width:calc(100vw - 32px);text-align:center;border:1px solid var(--line);border-radius:16px;background:rgba(10,10,15,.96);box-shadow:0 20px 70px rgba(0,0,0,.52);padding:11px 14px}.combo-toast.show{display:block;animation:comboToast .28s ease-out}.combo-toast b{font-size:12px}.combo-toast span{display:block;font-size:8px;color:var(--muted);margin-top:3px;letter-spacing:1px}
@keyframes comboBurst{0%{opacity:0;filter:blur(1px)}20%{opacity:1}100%{opacity:0;transform:translate(-50%,-50%) scale(1.6) rotate(360deg) translateX(150px)}}@keyframes comboToast{from{opacity:0;transform:translate(-50%,-8px)}to{opacity:1;transform:translate(-50%,0)}}
@media(prefers-reduced-motion:reduce){.combo-burst i,.combo-toast.show{animation:none!important}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.momentum-board{margin:0 0 22px;border:1px solid var(--line);border-radius:24px;background:linear-gradient(145deg,rgba(16,16,23,.94),rgba(8,8,13,.93));padding:18px;overflow:hidden;position:relative}
.momentum-board:before{content:"";position:absolute;right:-70px;top:-90px;width:230px;height:230px;border-radius:50%;background:rgba(255,79,216,.07);filter:blur(45px)}
.momentum-head{position:relative;z-index:1;display:flex;align-items:flex-end;justify-content:space-between;gap:12px}.momentum-head h2{margin:5px 0 0;font-size:24px;letter-spacing:-1px}.momentum-head .meta{text-align:right;font-size:9px}
.momentum-grid{position:relative;z-index:1;display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:14px}
.momentum-card{border:1px solid var(--line);border-radius:16px;padding:11px;background:rgba(255,255,255,.022);text-decoration:none;color:#fff;transition:.18s}.momentum-card:hover{transform:translateY(-2px);border-color:rgba(186,255,90,.26)}
.momentum-top{display:flex;align-items:center;justify-content:space-between;gap:8px}.momentum-id{display:flex;align-items:center;gap:8px;min-width:0}.momentum-avatar{width:34px;height:34px;border-radius:11px;display:grid;place-items:center;background:#09090e;border:1px solid var(--line);font-size:18px}.momentum-name{min-width:0}.momentum-name b{display:block;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.momentum-name span{display:block;font-size:8px;color:var(--muted);margin-top:2px}.momentum-count{font-size:13px;font-weight:950;color:var(--hot)}
.momentum-status{margin-top:9px;display:flex;align-items:center;justify-content:space-between;gap:8px;border-top:1px solid var(--line);padding-top:8px}.momentum-status b{font-size:8px;letter-spacing:.7px}.momentum-status span{font-size:8px;color:var(--muted)}
.momentum-status.hot b{color:#ffb34d}.momentum-status.dominating b{color:#ff63d7}.momentum-status.unstoppable b{color:var(--gold)}.momentum-status.mythic b{color:#8ef7ff}
.hud-momentum{margin-top:9px;border:1px solid var(--line);border-radius:14px;padding:10px;background:rgba(255,255,255,.025)}.hud-momentum-top{display:flex;justify-content:space-between;gap:8px;align-items:center}.hud-momentum-top span{font-size:8px;color:var(--muted);letter-spacing:1px}.hud-momentum-top b{font-size:10px}.hud-momentum-detail{margin-top:5px;font-size:9px;color:var(--muted)}
@media(max-width:980px){.momentum-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:560px){.momentum-grid{grid-template-columns:1fr}.momentum-head{align-items:flex-start;flex-direction:column}.momentum-head .meta{text-align:left}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.threat-radar{margin:0 0 22px;border:1px solid rgba(255,68,91,.16);border-radius:24px;background:linear-gradient(145deg,rgba(24,10,15,.9),rgba(8,8,13,.94));padding:18px;position:relative;overflow:hidden}
.threat-radar:before{content:"";position:absolute;left:-80px;bottom:-110px;width:250px;height:250px;border-radius:50%;background:rgba(255,68,91,.08);filter:blur(48px)}
.threat-head{position:relative;z-index:1;display:flex;align-items:flex-end;justify-content:space-between;gap:12px}.threat-head h2{margin:5px 0 0;font-size:24px;letter-spacing:-1px}.threat-head .meta{text-align:right;font-size:9px;max-width:430px}
.threat-grid{position:relative;z-index:1;display:grid;grid-template-columns:repeat(2,1fr);gap:9px;margin-top:14px}
.threat-card{border:1px solid var(--line);border-radius:17px;padding:12px;background:rgba(255,255,255,.022);display:grid;grid-template-columns:auto 1fr auto;gap:11px;align-items:center}
.threat-avatar{width:42px;height:42px;border-radius:13px;display:grid;place-items:center;background:#09090e;border:1px solid var(--line);font-size:23px}.threat-main{min-width:0}.threat-main b{display:block;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.threat-main span{display:block;font-size:8px;color:var(--muted);margin-top:3px}.threat-side{text-align:right}.threat-status{font-size:8px;font-weight:950;letter-spacing:.7px}.threat-record{font-size:9px;color:var(--muted);margin-top:4px}.threat-actions{grid-column:1/-1;display:flex;gap:7px;flex-wrap:wrap;border-top:1px solid var(--line);padding-top:9px}.threat-actions a,.threat-actions button{border:1px solid var(--line);border-radius:10px;background:rgba(255,255,255,.025);color:#fff;padding:7px 9px;text-decoration:none;font-size:8px;font-weight:900;cursor:pointer}.threat-actions .danger{background:rgba(255,68,91,.1);border-color:rgba(255,68,91,.22)}
.threat-nemesis .threat-status{color:#ff63d7}.threat-pressure .threat-status{color:#ff6278}.threat-hot .threat-status{color:#ffb34d}.threat-even .threat-status{color:#d7d7e4}.threat-ahead .threat-status{color:#9ef4be}.threat-empty{grid-column:1/-1;border:1px dashed var(--line);border-radius:14px;padding:14px;color:var(--muted);font-size:9px}
@media(max-width:780px){.threat-grid{grid-template-columns:1fr}}@media(max-width:560px){.threat-head{align-items:flex-start;flex-direction:column}.threat-head .meta{text-align:left}}

/* ===== V10.3 ACCESSIBILITY / REDUCED MOTION ===== */
@media (prefers-reduced-motion: reduce){
  .pulse-track,.pulse-live-dot,.spot-fade,.war-dot,.combo-burst i,.combo-toast.show,.war-alert-shell.show,.war-mini-toast.show,.replay-step,.clash-replay-shell.show{animation:none!important}
  *{scroll-behavior:auto!important}
}

/* ===== V13.3 GLOBAL SEARCH ===== */
.revenge-queue{margin:0 0 22px;border:1px solid rgba(255,99,215,.16);border-radius:24px;background:linear-gradient(145deg,rgba(25,10,24,.9),rgba(8,8,13,.94));padding:18px;position:relative;overflow:hidden}
.revenge-queue:before{content:"";position:absolute;right:-80px;bottom:-110px;width:250px;height:250px;border-radius:50%;background:rgba(255,79,216,.08);filter:blur(48px)}
.revenge-head{position:relative;z-index:1;display:flex;align-items:flex-end;justify-content:space-between;gap:12px}.revenge-head h2{margin:5px 0 0;font-size:24px;letter-spacing:-1px}.revenge-head .meta{text-align:right;font-size:9px;max-width:430px}
.revenge-grid{position:relative;z-index:1;display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin-top:14px}
.revenge-card{border:1px solid var(--line);border-radius:17px;padding:12px;background:rgba(255,255,255,.022)}
.revenge-top{display:flex;align-items:center;justify-content:space-between;gap:10px}.revenge-id{display:flex;gap:9px;align-items:center;min-width:0}.revenge-avatar{width:42px;height:42px;border-radius:13px;display:grid;place-items:center;background:#09090e;border:1px solid var(--line);font-size:23px}.revenge-name{min-width:0}.revenge-name b{display:block;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.revenge-name span{display:block;font-size:8px;color:var(--muted);margin-top:3px}
.revenge-state{text-align:right}.revenge-state b{display:block;font-size:8px;letter-spacing:.7px}.revenge-state span{display:block;font-size:8px;color:var(--muted);margin-top:3px}.revenge-open .revenge-state b{color:#e7e7f0}.revenge-urgent .revenge-state b{color:#ffb34d}.revenge-blood .revenge-state b{color:#ff63d7}
.revenge-actions{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-top:10px}.revenge-actions a,.revenge-actions button{border:1px solid var(--line);border-radius:10px;background:rgba(255,255,255,.025);color:#fff;padding:8px 9px;text-decoration:none;font-size:8px;font-weight:900;cursor:pointer}.revenge-actions .runback{grid-column:1/-1;background:linear-gradient(100deg,rgba(255,79,216,.15),rgba(255,68,91,.1));border-color:rgba(255,99,215,.28)}
.revenge-empty{grid-column:1/-1;border:1px dashed var(--line);border-radius:14px;padding:14px;color:var(--muted);font-size:9px}
@media(max-width:980px){.revenge-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:620px){.revenge-grid{grid-template-columns:1fr}.revenge-head{align-items:flex-start;flex-direction:column}.revenge-head .meta{text-align:left}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.nemesis-duel{margin:0 0 22px;border:1px solid rgba(255,99,215,.18);border-radius:26px;background:linear-gradient(135deg,rgba(29,9,28,.92),rgba(8,8,13,.96));padding:18px;position:relative;overflow:hidden}
.nemesis-duel:before{content:"";position:absolute;right:-100px;top:-100px;width:290px;height:290px;border-radius:50%;background:rgba(255,79,216,.08);filter:blur(50px)}
.nemesis-duel:after{content:"";position:absolute;left:-90px;bottom:-120px;width:260px;height:260px;border-radius:50%;background:rgba(97,244,255,.05);filter:blur(50px)}
.duel-head{position:relative;z-index:2;display:flex;justify-content:space-between;gap:12px;align-items:flex-end}.duel-head h2{margin:5px 0 0;font-size:26px;letter-spacing:-1px}.duel-head .meta{text-align:right;font-size:9px;max-width:430px}
.duel-stage{position:relative;z-index:2;display:grid;grid-template-columns:1fr auto 1fr;gap:14px;align-items:center;margin-top:16px}
.duel-fighter{border:1px solid var(--line);border-radius:20px;padding:15px;background:rgba(255,255,255,.025);display:flex;align-items:center;gap:12px;min-width:0}.duel-fighter.right{flex-direction:row-reverse;text-align:right}.duel-avatar{width:58px;height:58px;border-radius:18px;display:grid;place-items:center;background:#09090e;border:1px solid var(--line);font-size:32px}.duel-fighter-copy{min-width:0}.duel-fighter-copy b{display:block;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.duel-fighter-copy span{display:block;font-size:9px;color:var(--muted);margin-top:3px}.duel-score{font-size:34px;font-weight:950;color:#fff;margin-left:auto}.duel-fighter.right .duel-score{margin-left:0;margin-right:auto}
.duel-vs{width:76px;height:76px;border-radius:50%;display:grid;place-items:center;border:1px solid rgba(255,99,215,.28);background:radial-gradient(circle,rgba(255,79,216,.16),rgba(11,11,16,.9));font-size:17px;font-weight:950;box-shadow:0 0 35px rgba(255,79,216,.1)}
.duel-tier{position:relative;z-index:2;margin-top:12px;border:1px solid var(--line);border-radius:15px;padding:10px 12px;background:rgba(255,255,255,.02);display:flex;align-items:center;justify-content:space-between;gap:10px}.duel-tier b{font-size:10px;letter-spacing:1px}.duel-tier span{font-size:9px;color:var(--muted)}
.duel-actions{position:relative;z-index:2;display:flex;gap:8px;flex-wrap:wrap;justify-content:center;margin-top:12px}.duel-actions a,.duel-actions button{border:1px solid var(--line);border-radius:11px;background:rgba(255,255,255,.025);color:#fff;padding:9px 11px;text-decoration:none;font-size:8px;font-weight:900;cursor:pointer}.duel-actions .primary{background:linear-gradient(100deg,rgba(255,79,216,.16),rgba(255,68,91,.1));border-color:rgba(255,99,215,.3)}
.duel-empty{position:relative;z-index:2;border:1px dashed var(--line);border-radius:15px;padding:16px;color:var(--muted);font-size:9px;margin-top:14px}
@media(max-width:800px){.duel-stage{grid-template-columns:1fr}.duel-vs{margin:auto}.duel-fighter.right{flex-direction:row;text-align:left}.duel-fighter.right .duel-score{margin-left:auto;margin-right:0}}@media(max-width:560px){.duel-head{flex-direction:column;align-items:flex-start}.duel-head .meta{text-align:left}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.feud-pulse{position:relative;z-index:2;margin-top:12px;border:1px solid var(--line);border-radius:15px;padding:11px 12px;background:rgba(255,255,255,.018)}
.feud-pulse-top{display:flex;align-items:center;justify-content:space-between;gap:10px}.feud-pulse-top b{font-size:9px;letter-spacing:1px}.feud-pulse-top span{font-size:8px;color:var(--muted)}
.feud-pulse-row{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}.feud-chip{width:28px;height:28px;border-radius:9px;display:grid;place-items:center;border:1px solid var(--line);font-size:9px;font-weight:950;text-decoration:none}.feud-chip.win{color:#a7ffbf;background:rgba(85,255,145,.06);border-color:rgba(85,255,145,.18)}.feud-chip.loss{color:#ff8290;background:rgba(255,68,91,.06);border-color:rgba(255,68,91,.18)}
.feud-last{margin-top:8px;font-size:8px;color:var(--muted)}.feud-last b{color:#fff}

/* ===== V13.3 GLOBAL SEARCH ===== */
.duel-path{position:relative;z-index:2;margin-top:10px;display:grid;grid-template-columns:repeat(5,1fr);gap:6px}.duel-path-step{border:1px solid var(--line);border-radius:11px;padding:8px 6px;text-align:center;background:rgba(255,255,255,.018)}.duel-path-step b{display:block;font-size:14px}.duel-path-step span{display:block;font-size:7px;color:var(--muted);margin-top:3px}.duel-path-step.reached{border-color:rgba(186,255,90,.22)}.duel-path-step.next{border-color:rgba(255,99,215,.34);background:rgba(255,79,216,.055)}.duel-path-step.locked{opacity:.5}@media(max-width:650px){.duel-path{grid-template-columns:repeat(2,1fr)}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.duel-stakes{position:relative;z-index:2;margin-top:12px;border:1px solid rgba(255,214,107,.2);border-radius:18px;padding:14px;background:linear-gradient(120deg,rgba(255,214,107,.055),rgba(255,79,216,.035));overflow:hidden}
.duel-stakes:after{content:"";position:absolute;right:-55px;top:-70px;width:150px;height:150px;border-radius:50%;background:rgba(255,214,107,.07);filter:blur(34px);pointer-events:none}
.duel-stakes>*{position:relative;z-index:1}.duel-stakes-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.duel-stakes-kicker{font-size:8px;letter-spacing:1.5px;color:var(--gold);font-weight:950}.duel-stakes h3{font-size:20px;margin:5px 0 4px;letter-spacing:-.7px}.duel-stakes-tag{white-space:nowrap;border:1px solid rgba(255,214,107,.25);border-radius:999px;padding:6px 8px;color:var(--gold);font-size:8px;font-weight:950;letter-spacing:1px}.duel-stakes-copy{color:var(--muted);font-size:9px;line-height:1.5;max-width:700px}.duel-stakes-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;margin-top:11px}.duel-stake-card{border:1px solid var(--line);border-radius:13px;padding:10px;background:rgba(255,255,255,.02)}.duel-stake-card b{display:block;font-size:11px}.duel-stake-card span{display:block;color:var(--muted);font-size:8px;line-height:1.45;margin-top:4px}.duel-stake-card.hot{border-color:rgba(255,79,216,.22);background:rgba(255,79,216,.035)}.duel-stake-card.gold{border-color:rgba(255,214,107,.22);background:rgba(255,214,107,.035)}
@media(max-width:700px){.duel-stakes-top{flex-direction:column}.duel-stakes-grid{grid-template-columns:1fr}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.duel-chronicle{position:relative;z-index:2;margin-top:10px;display:grid;grid-template-columns:repeat(4,1fr);gap:6px}.duel-chron-stat{border:1px solid var(--line);border-radius:11px;padding:8px;text-align:center;background:rgba(255,255,255,.018)}.duel-chron-stat b{display:block;font-size:14px}.duel-chron-stat span{display:block;font-size:7px;color:var(--muted);margin-top:3px}@media(max-width:650px){.duel-chronicle{grid-template-columns:repeat(2,1fr)}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.feud-hall{margin:0 0 22px;border:1px solid rgba(186,255,90,.15);border-radius:26px;background:linear-gradient(145deg,rgba(10,18,12,.92),rgba(8,8,13,.96));padding:18px;position:relative;overflow:hidden}
.feud-hall:before{content:"";position:absolute;right:-90px;top:-100px;width:260px;height:260px;border-radius:50%;background:rgba(186,255,90,.06);filter:blur(48px)}
.feud-hall-head{position:relative;z-index:1;display:flex;align-items:flex-end;justify-content:space-between;gap:12px}.feud-hall-head h2{margin:5px 0 0;font-size:25px;letter-spacing:-1px}.feud-hall-head .meta{text-align:right;font-size:9px;max-width:420px}
.feud-hall-columns{position:relative;z-index:1;display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:14px}.feud-hall-col{border:1px solid var(--line);border-radius:17px;padding:11px;background:rgba(255,255,255,.018)}.feud-hall-col h3{margin:0 0 9px;font-size:10px;letter-spacing:1px}.feud-hall-list{display:grid;gap:7px}
.feud-record{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center;text-decoration:none;color:#fff;border:1px solid var(--line);border-radius:12px;padding:9px;background:rgba(255,255,255,.018)}.feud-record:hover{border-color:rgba(186,255,90,.28)}.feud-record-main{min-width:0}.feud-record-main b{display:block;font-size:9px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.feud-record-main span{display:block;font-size:7px;color:var(--muted);margin-top:3px}.feud-record-stat{text-align:right}.feud-record-stat b{display:block;font-size:13px;color:var(--hot)}.feud-record-stat span{display:block;font-size:7px;color:var(--muted)}
.feud-hall-empty{color:var(--muted);font-size:8px;border:1px dashed var(--line);border-radius:11px;padding:10px}
@media(max-width:950px){.feud-hall-columns{grid-template-columns:1fr}}@media(max-width:620px){.feud-hall-head{flex-direction:column;align-items:flex-start}.feud-hall-head .meta{text-align:left}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.feud-spotlight{margin:0 0 22px;border:1px solid rgba(255,214,107,.18);border-radius:26px;padding:18px;background:linear-gradient(135deg,rgba(26,20,8,.92),rgba(8,8,13,.96));position:relative;overflow:hidden}
.feud-spotlight:before{content:"";position:absolute;left:-90px;top:-110px;width:280px;height:280px;border-radius:50%;background:rgba(255,214,107,.07);filter:blur(48px)}
.feud-spotlight-head{position:relative;z-index:1;display:flex;justify-content:space-between;align-items:flex-end;gap:12px}.feud-spotlight-head h2{margin:5px 0 0;font-size:26px;letter-spacing:-1px}.feud-spotlight-head .meta{text-align:right;font-size:9px;max-width:430px}
.feud-spotlight-body{position:relative;z-index:1;margin-top:14px}
.spot-feud-card{display:grid;grid-template-columns:1fr auto 1fr;gap:14px;align-items:center;border:1px solid var(--line);border-radius:20px;padding:16px;background:rgba(255,255,255,.022)}
.spot-feud-side{min-width:0}.spot-feud-side.right{text-align:right}.spot-feud-side b{display:block;font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.spot-feud-side span{display:block;font-size:9px;color:var(--muted);margin-top:4px}.spot-feud-score{display:flex;align-items:center;gap:12px}.spot-feud-score strong{font-size:36px}.spot-feud-score i{font-style:normal;color:var(--muted);font-size:11px}
.spot-feud-meta{margin-top:10px;display:grid;grid-template-columns:repeat(4,1fr);gap:7px}.spot-feud-stat{border:1px solid var(--line);border-radius:12px;padding:9px;text-align:center;background:rgba(255,255,255,.018)}.spot-feud-stat b{display:block;font-size:12px}.spot-feud-stat span{display:block;font-size:7px;color:var(--muted);margin-top:3px}
.spot-feud-actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:center;margin-top:11px}.spot-feud-actions a{border:1px solid var(--line);border-radius:11px;padding:9px 11px;color:#fff;text-decoration:none;font-size:8px;font-weight:900;background:rgba(255,255,255,.025)}.spot-feud-actions a.primary{border-color:rgba(255,214,107,.3);background:rgba(255,214,107,.07)}
.spot-feud-empty{border:1px dashed var(--line);border-radius:14px;padding:15px;color:var(--muted);font-size:9px}
@media(max-width:760px){.spot-feud-card{grid-template-columns:1fr}.spot-feud-score{justify-content:center}.spot-feud-side,.spot-feud-side.right{text-align:center}.spot-feud-meta{grid-template-columns:repeat(2,1fr)}}@media(max-width:560px){.feud-spotlight-head{flex-direction:column;align-items:flex-start}.feud-spotlight-head .meta{text-align:left}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.mission-control{margin:0 0 22px;border:1px solid rgba(97,244,255,.16);border-radius:26px;padding:18px;background:linear-gradient(145deg,rgba(8,18,23,.94),rgba(8,8,13,.96));position:relative;overflow:hidden}
.mission-control:before{content:"";position:absolute;right:-90px;top:-100px;width:270px;height:270px;border-radius:50%;background:rgba(97,244,255,.06);filter:blur(48px)}
.mission-head{position:relative;z-index:1;display:flex;align-items:flex-end;justify-content:space-between;gap:12px}.mission-head h2{margin:5px 0 0;font-size:26px;letter-spacing:-1px}.mission-head .meta{text-align:right;font-size:9px;max-width:430px}
.mission-grid{position:relative;z-index:1;display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:14px}.mission-stat{border:1px solid var(--line);border-radius:14px;padding:11px;background:rgba(255,255,255,.02)}.mission-stat b{display:block;font-size:17px}.mission-stat span{display:block;font-size:7px;color:var(--muted);margin-top:4px;letter-spacing:.7px}
.mission-next{position:relative;z-index:1;margin-top:9px;border:1px solid rgba(97,244,255,.18);border-radius:16px;padding:12px;background:rgba(97,244,255,.035);display:flex;align-items:center;justify-content:space-between;gap:12px}.mission-next-copy{min-width:0}.mission-next-copy b{display:block;font-size:11px}.mission-next-copy span{display:block;font-size:8px;color:var(--muted);margin-top:4px}.mission-next a{border:1px solid var(--line);border-radius:10px;padding:8px 10px;color:#fff;text-decoration:none;font-size:8px;font-weight:900;white-space:nowrap}
.mission-empty{position:relative;z-index:1;border:1px dashed var(--line);border-radius:14px;padding:14px;color:var(--muted);font-size:9px;margin-top:12px}
@media(max-width:850px){.mission-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:560px){.mission-head{flex-direction:column;align-items:flex-start}.mission-head .meta{text-align:left}.mission-next{align-items:flex-start;flex-direction:column}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.mission-action-deck{position:relative;z-index:1;display:grid;grid-template-columns:repeat(3,1fr);gap:7px;margin-top:9px}
.mission-action-card{border:1px solid var(--line);border-radius:13px;padding:10px;background:rgba(255,255,255,.018);color:#fff;text-decoration:none;min-width:0}
.mission-action-card b{display:block;font-size:9px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.mission-action-card span{display:block;font-size:7px;color:var(--muted);margin-top:3px}.mission-action-card:hover{border-color:rgba(97,244,255,.25)}
@media(max-width:700px){.mission-action-deck{grid-template-columns:1fr}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.ops-pulse{position:relative;z-index:1;margin-top:10px;border:1px solid rgba(186,255,90,.14);border-radius:16px;padding:11px;background:rgba(186,255,90,.025)}
.ops-pulse-head{display:flex;align-items:center;justify-content:space-between;gap:10px}.ops-pulse-head b{font-size:9px;letter-spacing:1px}.ops-pulse-head span{font-size:8px;color:var(--muted)}
.ops-pulse-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:6px;margin-top:8px}.ops-pulse-stat{border:1px solid var(--line);border-radius:10px;padding:8px;text-align:center;background:rgba(255,255,255,.018)}.ops-pulse-stat b{display:block;font-size:13px}.ops-pulse-stat span{display:block;font-size:7px;color:var(--muted);margin-top:2px}
.ops-pulse-feed{display:grid;gap:6px;margin-top:8px}.ops-pulse-row{display:grid;grid-template-columns:auto 1fr auto;gap:8px;align-items:center;text-decoration:none;color:#fff;border-top:1px solid var(--line);padding-top:7px}.ops-pulse-row:first-child{border-top:none}.ops-pulse-row i{font-style:normal}.ops-pulse-row b{font-size:8px}.ops-pulse-row span{font-size:7px;color:var(--muted)}.ops-pulse-row em{font-size:7px;color:var(--muted);font-style:normal}
@media(max-width:780px){.ops-pulse-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:520px){.ops-pulse-grid{grid-template-columns:1fr 1fr}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.duel-actions .danger-clear{border-color:rgba(255,68,91,.28);background:rgba(255,68,91,.08);color:#ff9aa7}
.nemesis-control-note{position:relative;z-index:2;margin-top:8px;font-size:8px;color:var(--muted);text-align:right}
.feud-chip.neutral{color:var(--muted);background:rgba(255,255,255,.025);border-color:var(--line)}

/* ===== V13.3 GLOBAL SEARCH ===== */
.crown-war.private-intel .war-count{color:#9ea0b2;border:1px solid var(--line);border-radius:999px;padding:6px 9px;background:rgba(255,255,255,.025)}
.crown-war.private-intel .war-status span:after{content:" // PUBLIC VIEW";color:#8c8e9d}
.crown-war.private-intel .war-dot{background:#9ea0b2;box-shadow:0 0 14px rgba(158,160,178,.35)}
.crown-intel-note{font-size:8px;color:var(--muted);margin-top:7px;letter-spacing:.4px}

/* ===== V13.3 GLOBAL SEARCH ===== */
.feud-events{margin:0 0 22px;border:1px solid rgba(255,79,216,.18);border-radius:26px;padding:18px;background:linear-gradient(145deg,rgba(24,8,22,.94),rgba(8,8,13,.96));position:relative;overflow:hidden}
.feud-events:before{content:"";position:absolute;left:-90px;top:-100px;width:280px;height:280px;border-radius:50%;background:rgba(255,79,216,.07);filter:blur(52px)}
.feud-events-head{position:relative;z-index:1;display:flex;align-items:flex-end;justify-content:space-between;gap:12px}.feud-events-head h2{margin:5px 0 0;font-size:26px;letter-spacing:-1px}.feud-events-head .meta{text-align:right;font-size:9px;max-width:420px}
.feud-event-list{position:relative;z-index:1;display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:14px}.feud-event{display:grid;grid-template-columns:42px 1fr auto;gap:10px;align-items:center;border:1px solid var(--line);border-radius:16px;padding:11px;background:rgba(255,255,255,.022);text-decoration:none;color:#fff;transition:.18s}.feud-event:hover{transform:translateY(-2px);border-color:rgba(255,79,216,.28)}
.feud-event-icon{width:42px;height:42px;border-radius:13px;display:grid;place-items:center;background:#0a090e;border:1px solid rgba(255,79,216,.16);font-size:22px}.feud-event-copy b{display:block;font-size:10px}.feud-event-copy span{display:block;font-size:8px;color:var(--muted);margin-top:4px;line-height:1.4}.feud-event-side{text-align:right}.feud-event-side b{display:block;font-size:9px;color:#ff8ae4}.feud-event-side span{display:block;font-size:7px;color:var(--muted);margin-top:3px}.feud-events-empty{grid-column:1/-1;border:1px dashed var(--line);border-radius:14px;padding:15px;color:var(--muted);font-size:9px}
.feud-event-burst{position:fixed;left:50%;top:18%;transform:translateX(-50%);z-index:10040;display:none;width:min(520px,calc(100vw - 28px));border:1px solid rgba(255,79,216,.38);border-radius:24px;padding:22px;text-align:center;background:linear-gradient(145deg,rgba(36,8,31,.98),rgba(10,8,13,.98));box-shadow:0 30px 100px rgba(0,0,0,.68),0 0 65px rgba(255,79,216,.12);pointer-events:none}.feud-event-burst.show{display:block;animation:feudBurst .35s ease-out}.feud-event-burst .ico{font-size:48px}.feud-event-burst b{display:block;font-size:11px;letter-spacing:1.8px;color:#ff8ae4;margin-top:7px}.feud-event-burst strong{display:block;font-size:30px;letter-spacing:-1px;margin-top:6px}.feud-event-burst span{display:block;color:#aaaabd;font-size:10px;margin-top:6px}
@keyframes feudBurst{from{opacity:0;transform:translate(-50%,-10px) scale(.96)}to{opacity:1;transform:translate(-50%,0) scale(1)}}
@media(max-width:760px){.feud-event-list{grid-template-columns:1fr}.feud-events-head{flex-direction:column;align-items:flex-start}.feud-events-head .meta{text-align:left}}

/* ===== V13.3 GLOBAL SEARCH ===== */
.feud-moments{margin:0 0 22px;border:1px solid rgba(97,244,255,.18);border-radius:26px;padding:18px;background:linear-gradient(145deg,rgba(8,18,24,.94),rgba(8,8,13,.96));position:relative;overflow:hidden}
.feud-moments:before{content:"";position:absolute;right:-100px;top:-110px;width:290px;height:290px;border-radius:50%;background:rgba(97,244,255,.07);filter:blur(54px)}
.feud-moments-head{position:relative;z-index:1;display:flex;align-items:flex-end;justify-content:space-between;gap:12px}.feud-moments-head h2{margin:5px 0 0;font-size:26px;letter-spacing:-1px}.feud-moments-head .meta{text-align:right;font-size:9px;max-width:440px}
.feud-moment-list{position:relative;z-index:1;display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:14px}.feud-moment{display:grid;grid-template-columns:42px 1fr auto;gap:10px;align-items:center;border:1px solid var(--line);border-radius:16px;padding:11px;background:rgba(255,255,255,.022);text-decoration:none;color:#fff}.feud-moment:hover{border-color:rgba(97,244,255,.3);transform:translateY(-1px)}
.feud-moment-icon{width:42px;height:42px;border-radius:13px;display:grid;place-items:center;background:#080d10;border:1px solid rgba(97,244,255,.18);font-size:22px}.feud-moment-copy b{display:block;font-size:10px}.feud-moment-copy span{display:block;font-size:8px;color:var(--muted);margin-top:4px;line-height:1.4}.feud-moment-side{text-align:right}.feud-moment-side b{display:block;font-size:9px;color:var(--cyan)}.feud-moment-side span{display:block;font-size:7px;color:var(--muted);margin-top:3px}.feud-moments-empty{grid-column:1/-1;border:1px dashed var(--line);border-radius:14px;padding:15px;color:var(--muted);font-size:9px}
.moment-share{display:inline-flex;margin-top:5px;font-size:7px;color:var(--hot);letter-spacing:.7px}.moment-burst{position:fixed;left:50%;top:18%;transform:translateX(-50%) scale(.96);z-index:10040;display:none;min-width:min(520px,calc(100vw - 28px));border:1px solid rgba(97,244,255,.34);border-radius:22px;background:linear-gradient(145deg,rgba(8,22,28,.98),rgba(9,9,14,.98));box-shadow:0 30px 110px rgba(0,0,0,.62),0 0 55px rgba(97,244,255,.09);padding:20px;text-align:center}.moment-burst.show{display:block;animation:momentBurst .28s ease-out}.moment-burst .ico{font-size:42px}.moment-burst b{display:block;color:var(--cyan);font-size:9px;letter-spacing:2px;margin-top:6px}.moment-burst strong{display:block;font-size:25px;margin-top:5px}.moment-burst span{display:block;color:var(--muted);font-size:10px;margin-top:6px;line-height:1.45}
@keyframes momentBurst{from{opacity:0;transform:translateX(-50%) translateY(-8px) scale(.94)}to{opacity:1;transform:translateX(-50%) translateY(0) scale(1)}}
@media(max-width:760px){.feud-moment-list{grid-template-columns:1fr}.feud-moments-head{flex-direction:column;align-items:flex-start}.feud-moments-head .meta{text-align:left}}
.moment-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:7px}.moment-actions .moment-share,.moment-actions a{border:1px solid rgba(97,244,255,.22);border-radius:9px;background:rgba(97,244,255,.05);color:var(--cyan);padding:6px 8px;font-size:7px;font-weight:900;cursor:pointer;text-decoration:none}.moment-actions a{border-color:rgba(161,124,255,.24);color:#cbbcff;background:rgba(161,124,255,.055)}

/* ===== V13.3 GLOBAL SEARCH ===== */
.trending-feuds{margin:0 0 22px;border:1px solid rgba(255,214,107,.2);border-radius:26px;padding:18px;background:linear-gradient(145deg,rgba(26,19,8,.94),rgba(8,8,13,.96));position:relative;overflow:hidden}
.trending-feuds:before{content:"";position:absolute;left:-90px;top:-120px;width:300px;height:300px;border-radius:50%;background:rgba(255,214,107,.075);filter:blur(56px)}
.trending-feuds-head{position:relative;z-index:1;display:flex;align-items:flex-end;justify-content:space-between;gap:12px}.trending-feuds-head h2{margin:5px 0 0;font-size:28px;letter-spacing:-1.1px}.trending-feuds-head .meta{text-align:right;font-size:9px;max-width:470px}
.trending-feud-grid{position:relative;z-index:1;display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin-top:14px}.trend-feud-card{display:block;text-decoration:none;color:#fff;border:1px solid var(--line);border-radius:18px;padding:14px;background:rgba(255,255,255,.022);transition:.18s}.trend-feud-card:hover{transform:translateY(-2px);border-color:rgba(255,214,107,.34)}
.trend-rank{display:flex;align-items:center;justify-content:space-between;gap:10px}.trend-rank b{font-size:10px;color:var(--gold)}.trend-badge{font-size:7px;letter-spacing:1px;border:1px solid rgba(255,214,107,.22);border-radius:999px;padding:4px 6px;color:var(--gold);background:rgba(255,214,107,.05)}
.trend-pair{font-size:16px;font-weight:950;letter-spacing:-.4px;margin:9px 0 5px}.trend-score{font-size:32px;font-weight:950;color:var(--gold);line-height:1}.trend-score span{font-size:8px;color:var(--muted);letter-spacing:1px;margin-left:4px}.trend-meta{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-top:10px}.trend-stat{border:1px solid var(--line);border-radius:11px;padding:7px;text-align:center;background:rgba(255,255,255,.018)}.trend-stat b{display:block;font-size:11px}.trend-stat span{display:block;font-size:6px;color:var(--muted);margin-top:2px}.trending-empty{grid-column:1/-1;border:1px dashed var(--line);border-radius:14px;padding:15px;color:var(--muted);font-size:9px}
@media(max-width:900px){.trending-feud-grid{grid-template-columns:1fr 1fr}}@media(max-width:620px){.trending-feud-grid{grid-template-columns:1fr}.trending-feuds-head{flex-direction:column;align-items:flex-start}.trending-feuds-head .meta{text-align:left}}


/* ===== V13.3 GLOBAL SEARCH ===== */
.discovery-engine{margin:0 0 22px;border:1px solid rgba(97,244,255,.19);border-radius:28px;padding:19px;background:linear-gradient(145deg,rgba(7,18,24,.96),rgba(10,8,15,.97));position:relative;overflow:hidden}
.discovery-engine:before{content:"";position:absolute;right:-110px;top:-140px;width:330px;height:330px;border-radius:50%;background:rgba(97,244,255,.075);filter:blur(62px)}
.discovery-engine:after{content:"";position:absolute;left:-100px;bottom:-150px;width:300px;height:300px;border-radius:50%;background:rgba(161,124,255,.07);filter:blur(58px)}
.discovery-engine-head{position:relative;z-index:1;display:flex;align-items:flex-end;justify-content:space-between;gap:14px}.discovery-engine-head h2{margin:5px 0 0;font-size:30px;letter-spacing:-1.2px}.discovery-engine-head .meta{text-align:right;font-size:9px;max-width:500px}
.discovery-columns{position:relative;z-index:1;display:grid;grid-template-columns:1.08fr .92fr;gap:10px;margin-top:15px}.discovery-col{border:1px solid var(--line);border-radius:20px;padding:13px;background:rgba(255,255,255,.018)}.discovery-col-head{display:flex;justify-content:space-between;gap:10px;align-items:center;margin-bottom:9px}.discovery-col-head b{font-size:10px;letter-spacing:1.2px}.discovery-col-head span{font-size:7px;color:var(--muted)}
.discovery-feud-list,.discovery-hunter-list{display:grid;gap:8px}.discovery-feud{border:1px solid var(--line);border-radius:16px;padding:12px;background:rgba(255,255,255,.02)}.discovery-feud-top{display:flex;justify-content:space-between;gap:10px;align-items:center}.discovery-feud-rank{font-size:8px;color:var(--gold);font-weight:950;letter-spacing:1px}.discovery-feud-badge{font-size:7px;color:var(--gold);border:1px solid rgba(255,214,107,.22);border-radius:999px;padding:4px 6px}.discovery-feud h3{font-size:15px;margin:8px 0 5px}.discovery-reason{font-size:8px;color:var(--muted);line-height:1.45}.discovery-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}.discovery-actions a{border:1px solid var(--line);border-radius:10px;padding:7px 9px;color:#fff;text-decoration:none;font-size:7px;font-weight:900;background:rgba(255,255,255,.025)}.discovery-actions a.hot{background:rgba(186,255,90,.08);border-color:rgba(186,255,90,.24);color:var(--hot)}
.discovery-hunter{display:grid;grid-template-columns:40px 1fr auto;gap:10px;align-items:center;border:1px solid var(--line);border-radius:16px;padding:10px;background:rgba(255,255,255,.02)}.discovery-hunter-avatar{width:40px;height:40px;border-radius:13px;display:grid;place-items:center;background:#090d11;border:1px solid rgba(97,244,255,.18);font-size:21px}.discovery-hunter-main b{display:block;font-size:10px}.discovery-hunter-main span{display:block;font-size:8px;color:var(--muted);margin-top:3px;line-height:1.4}.discovery-hunter-score{text-align:right}.discovery-hunter-score b{display:block;color:var(--cyan);font-size:15px}.discovery-hunter-score span{display:block;font-size:6px;color:var(--muted)}.discovery-hunter .discovery-actions{grid-column:2/-1;margin-top:0}
.discovery-empty{border:1px dashed var(--line);border-radius:14px;padding:14px;color:var(--muted);font-size:9px}
.discovery-empty b{display:block;color:#fff;font-size:11px;margin-bottom:5px}.discovery-empty span{display:block;line-height:1.5}.discovery-empty a{display:inline-flex;margin-top:9px;border:1px solid rgba(97,244,255,.22);border-radius:10px;padding:8px 10px;color:var(--cyan);text-decoration:none;font-size:8px;font-weight:950;background:rgba(97,244,255,.045)}
.discovery-personal{display:inline-flex;align-items:center;gap:6px;border:1px solid rgba(97,244,255,.22);border-radius:999px;padding:5px 8px;color:var(--cyan);font-size:7px;font-weight:950;letter-spacing:.8px;margin-left:6px}.discovery-hunter-score small{display:block;font-size:6px;color:var(--hot);margin-top:3px}.discovery-match{font-size:7px;color:var(--hot);margin-top:4px}
@media(max-width:900px){.discovery-columns{grid-template-columns:1fr}}@media(max-width:620px){.discovery-engine-head{flex-direction:column;align-items:flex-start}.discovery-engine-head .meta{text-align:left}.discovery-hunter{grid-template-columns:36px 1fr}.discovery-hunter-score{grid-column:2;text-align:left}.discovery-hunter .discovery-actions{grid-column:1/-1}}

/* ===== V13.3 GLOBAL SEARCH ===== */
:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}
.skip-link{position:fixed;left:12px;top:12px;z-index:11000;transform:translateY(-160%);background:#fff;color:#050507;padding:10px 14px;border-radius:10px;font-weight:950;text-decoration:none;transition:.18s}
.skip-link:focus{transform:translateY(0)}
.quality-footer{display:flex;align-items:center;justify-content:center;gap:10px;flex-wrap:wrap;margin-top:8px}.quality-footer a{color:#8f91a3;text-decoration:none}.quality-footer a:hover,.quality-footer a:focus-visible{color:var(--cyan)}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important}}


/* ===== V13.3 GLOBAL SEARCH + COMMAND PALETTE ===== */
.command-search-trigger{cursor:pointer;font:inherit}.command-search-trigger kbd{font-size:8px;color:var(--muted);margin-left:6px;border:1px solid var(--line);padding:2px 5px;border-radius:6px;background:#07070b}
.command-palette-shell{position:fixed;inset:0;z-index:12000;display:none;align-items:flex-start;justify-content:center;padding:10vh 16px 24px;background:rgba(2,2,5,.68);backdrop-filter:blur(10px)}
.command-palette-shell.show{display:flex}
.command-palette{width:min(760px,100%);max-height:min(720px,80vh);display:flex;flex-direction:column;border:1px solid rgba(255,255,255,.14);border-radius:24px;background:linear-gradient(145deg,rgba(18,18,27,.99),rgba(7,7,11,.99));box-shadow:0 36px 140px rgba(0,0,0,.72);overflow:hidden}
.command-palette-head{display:flex;align-items:center;gap:10px;padding:14px;border-bottom:1px solid var(--line)}
.command-palette-icon{font-size:22px}.command-palette-input{margin:0!important;border:0!important;background:transparent!important;border-radius:0!important;font-size:17px;font-weight:800;box-shadow:none!important}.command-palette-input:focus{outline:none}
.command-palette-esc{border:1px solid var(--line);border-radius:8px;background:#0c0c12;color:var(--muted);padding:6px 8px;font-size:8px;font-weight:900;white-space:nowrap}
.command-palette-meta{display:flex;justify-content:space-between;gap:10px;padding:9px 15px;border-bottom:1px solid var(--line);font-size:8px;letter-spacing:1px;color:var(--muted)}
.command-results{overflow:auto;padding:8px}.command-group-label{padding:9px 9px 5px;font-size:8px;letter-spacing:1.4px;color:var(--muted);font-weight:950}
.command-result{width:100%;display:grid;grid-template-columns:36px 1fr auto;gap:10px;align-items:center;border:1px solid transparent;border-radius:14px;background:transparent;color:#fff;padding:10px;text-align:left;cursor:pointer}.command-result:hover,.command-result.active{background:rgba(186,255,90,.055);border-color:rgba(186,255,90,.2)}
.command-result-icon{width:34px;height:34px;border-radius:11px;display:grid;place-items:center;background:#09090e;border:1px solid var(--line);font-size:17px}.command-result-copy{min-width:0}.command-result-copy b{display:block;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.command-result-copy span{display:block;margin-top:3px;font-size:8px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.command-result-type{font-size:7px;color:var(--hot);border:1px solid rgba(186,255,90,.16);border-radius:999px;padding:4px 6px;letter-spacing:.8px;font-weight:900}.command-empty{padding:28px 18px;text-align:center;color:var(--muted);font-size:10px}.command-palette-foot{display:flex;gap:12px;flex-wrap:wrap;padding:10px 15px;border-top:1px solid var(--line);font-size:8px;color:var(--muted)}.command-palette-foot kbd{color:#fff;border:1px solid var(--line);padding:2px 5px;border-radius:5px;background:#09090e}
@media(max-width:620px){.command-palette-shell{padding:7vh 10px 12px}.command-palette{max-height:86vh;border-radius:19px}.command-search-trigger kbd{display:none}.command-result{grid-template-columns:34px 1fr}.command-result-type{display:none}}
</style>
</head>
<body>
<a class="skip-link" href="#mainContent">SKIP TO NETWORK</a>
<div class="command-palette-shell" id="commandPaletteShell" role="dialog" aria-modal="true" aria-label="BL3 global search" onclick="commandPaletteBackdrop(event)">
  <div class="command-palette" id="commandPalette">
    <div class="command-palette-head"><span class="command-palette-icon">⌘</span><input class="command-palette-input" id="commandPaletteInput" autocomplete="off" spellcheck="false" placeholder="Search Hunters, Feuds, Clashes, Arenas, Moments…"><span class="command-palette-esc">ESC</span></div>
    <div class="command-palette-meta"><span id="commandPaletteStatus">GLOBAL SEARCH // READY</span><span>BL3 V13.3</span></div>
    <div class="command-results" id="commandResults"><div class="command-empty">Start typing or pick a quick command.</div></div>
    <div class="command-palette-foot"><span><kbd>↑</kbd><kbd>↓</kbd> NAVIGATE</span><span><kbd>ENTER</kbd> OPEN</span><span><kbd>ESC</kbd> CLOSE</span></div>
  </div>
</div>
<div class="shell" id="mainContent" tabindex="-1">
  <nav class="nav">
    <div class="brand">BL3<span>●</span></div>
    <div class="pill">THE HUMAN ALPHA NETWORK</div>
    <div class="nav-right"><button class="pill command-search-trigger" type="button" onclick="openCommandPalette()" aria-label="Search BL3"><span>🔎 SEARCH</span><kbd>Ctrl K</kbd></button><div class="pill" id="signalBadge">SIGNALS 0</div><div class="pill" id="inboxBadge">INBOX 0</div><div class="pill" id="navAuth">WALLET OFFLINE</div></div>
  </nav>

  <section class="hero">
    <div class="hero-v9">
      <div class="hero-copy">
        <div class="hero-kicker">
          <div class="eyebrow">PROOF &gt; NOISE</div>
          <div class="hero-status"><i></i> HUMAN ALPHA NETWORK // LIVE</div>
        </div>
        <h1>HUNT ALPHA.<br><span class="grad">BUILD YOUR NAME.</span></h1>
        <div class="lead">Compete in live Arenas, evolve your Hunter identity, build reputation, clash with rivals and turn real proof into a public onchain-style reputation layer.</div>
        <div class="hero-actions">
          <button class="btn hot" onclick="jumpToAction()">⚡ ENTER LIVE ARENAS</button>
          <button class="btn violet" onclick="jumpToPassport()">👾 OPEN HUNTER PASSPORT</button>
          <button class="btn ghost" onclick="jumpToWallet()">🔐 VERIFY IDENTITY</button>
        </div>
        <div class="ticker">
          <div class="pill"><b id="liveArenas">0</b> LIVE ARENAS</div>
          <div class="pill"><b id="totalBounty">0</b> USDC LISTED</div>
          <div class="pill"><b id="totalHunters">0</b> HUNTERS</div>
        </div>
      </div>
      <div class="hero-core">
        <div class="core-top">
          <div class="eyebrow">BL3 // LIVE HUNTER HUD</div>
          <div style="display:flex;gap:6px;align-items:center">
            <div class="hud-unlock-badge" id="hudUnlockBadge">✨ 0 NEW</div>
            <div class="core-badge">V12.0</div>
          </div>
        </div>
        <div>
          <div class="core-orb"><div class="core-glyph" id="hudCreature">👾</div></div>
          <div class="core-title" id="hudHunterName">LOAD YOUR HUNTER ID</div>
          <div class="core-sub" id="hudCreatureMeta">Your live identity, title, reputation and next unlock will appear here.</div>

          <div class="hud-strip">
            <div class="hud-card">
              <div class="hud-label">PUBLIC TITLE</div>
              <div class="hud-value hud-title" id="hudTitle">🏷️ HUNTER</div>
              <div class="hud-sub" id="hudTitleTier">UNRANKED</div>
            </div>
            <div class="hud-card">
              <div class="hud-label">REPUTATION</div>
              <div class="hud-value" id="hudRep">0 REP</div>
              <div class="hud-sub" id="hudCombat">0 WINS // 0 NETWORK</div>
            </div>
          </div>

          <div class="hud-next">
            <div class="hud-next-top"><span>NEXT MEANINGFUL UNLOCK</span><b id="hudNextPercent">0%</b></div>
            <div class="hud-next-title" id="hudNextTitle">🧭 LOAD PROFILE TO SCAN</div>
            <div class="hud-meter"><i id="hudNextBar"></i></div>
            <div class="hud-sub" id="hudNextDetail">Progress radar is waiting for a Hunter ID.</div>
          </div>
          <div class="hud-momentum" id="hudMomentum">
            <div class="hud-momentum-top"><span>SEASON MOMENTUM</span><b id="hudMomentumLabel">⚔️ BUILDING MOMENTUM</b></div>
            <div class="hud-momentum-detail" id="hudMomentumDetail">0 straight wins · 3 wins to HOT STREAK</div>
          </div>

          <div class="hud-links">
            <a class="hud-link" id="hudProfileLink" href="#passportCard">PROFILE</a>
            <a class="hud-link" id="hudLoadoutLink" href="#passportCard">LOADOUT</a>
            <a class="hud-link" id="hudProgressLink" href="#passportCard">PROGRESS</a>
          </div>
        </div>
        <div class="core-lines">
          <div class="core-line"><span>IDENTITY</span><b id="hudIdentityLine">PASSPORT OFFLINE</b></div>
          <div class="core-line"><span>COMBAT</span><b id="hudCombatLine">SCAN HUNTER</b></div>
          <div class="core-line"><span>PROGRESSION</span><b id="hudProgressLine">WAITING FOR DATA</b></div>
        </div>
      </div>
    </div>
  </section>

  <section class="command-deck">
    <div class="command-label"><b>⚡ COMMAND DECK</b><span>Your main BL3 systems — one tap away.</span></div>
    <a class="command-link" href="#arenaSection"><b>🎯 LIVE ARENAS</b><span>Find proof opportunities</span></a>
    <a class="command-link" href="#passportCard"><b>👾 PASSPORT</b><span>Identity + evolution</span></a>
    <a class="command-link" href="#clashCard"><b>⚔️ ALPHA CLASH</b><span>Challenge Hunters</span></a>
    <a class="command-link" href="#walletCard"><b>🔐 WALLET PROOF</b><span>Own your Hunter ID</span></a>
    <a class="command-link" id="commandProgressLink" href="#passportCard"><b>📈 NEXT UNLOCKS</b><span>Progress radar</span></a>
    <a class="command-link" href="#momentumBoard"><b>🔥 MOMENTUM</b><span>Live streak status</span></a>
    <a class="command-link" href="#threatRadar"><b>😈 THREAT RADAR</b><span>Track your Nemeses</span></a>
    <a class="command-link" href="#revengeQueue"><b>🩸 REVENGE QUEUE</b><span>Run it back</span></a>
    <a class="command-link" href="#nemesisDuel"><b>⚔️ DUEL BANNER</b><span>Your featured feud</span></a>
    <a class="command-link" href="#hallOfFeuds"><b>🏛️ HALL OF FEUDS</b><span>Network rivalry records</span></a>
    <a class="command-link" href="#seasonFeudSpotlight"><b>🌟 FEUD SPOTLIGHT</b><span>Most active this season</span></a>
    <a class="command-link" href="#feudEvents"><b>💥 FEUD EVENTS</b><span>Escalation milestones</span></a>
    <a class="command-link" href="#feudMoments"><b>🎬 FEUD MOMENTS</b><span>Shareable story beats</span></a>
    <a class="command-link" href="#trendingFeuds"><b>📈 TRENDING FEUDS</b><span>Viral score leaderboard</span></a>
    <a class="command-link" href="#discoveryEngine"><b>📡 DISCOVERY</b><span>Find the live story</span></a>
    <a class="command-link" href="#missionControl"><b>🛰️ MISSION CONTROL</b><span>Your private next move</span></a>
  </section>

  <section class="mission-control" id="missionControl">
    <div class="mission-head">
      <div><div class="eyebrow">🛰️ MISSION CONTROL // PRIVATE VIEW</div><h2>Your Next Move</h2></div>
      <div class="meta" id="missionControlMeta">Verify your Hunter ID to load private priorities.</div>
    </div>
    <div id="missionControlBody"><div class="mission-empty">Mission Control is waiting for Hunter authentication.</div></div>
    <div id="opsPulseBody"><div class="mission-empty">24h Ops Pulse will load after Hunter authentication.</div></div>
  </section>

  <section class="feud-spotlight" id="seasonFeudSpotlight">
    <div class="feud-spotlight-head">
      <div><div class="eyebrow">🌟 SEASON FEUD SPOTLIGHT // LIVE RIVALRY</div><h2>Most Active Feud This Season</h2></div>
      <div class="meta" id="seasonFeudSpotlightMeta">Uses completed direct Clashes from the current season only.</div>
    </div>
    <div class="feud-spotlight-body" id="seasonFeudSpotlightBody"><div class="spot-feud-empty">Scanning current-season rivalry activity…</div></div>
  </section>

  <section class="feud-events" id="feudEvents">
    <div class="feud-events-head">
      <div><div class="eyebrow">💥 FEUD EVENTS // ESCALATION FEED</div><h2>When Rivalries Level Up</h2></div>
      <div class="meta" id="feudEventsMeta">Milestones are emitted only when a completed direct Clash crosses a Rivalry tier.</div>
    </div>
    <div class="feud-event-list" id="feudEventsBody"><div class="feud-events-empty">Waiting for the next Rivalry escalation…</div></div>
  </section>

  <div class="feud-event-burst" id="feudEventBurst"><div class="ico" id="feudEventBurstIcon">🔥</div><b>RIVALRY ESCALATED</b><strong id="feudEventBurstTitle">FEUD EVENT</strong><span id="feudEventBurstDetail"></span></div>

  <section class="feud-moments" id="feudMoments">
    <div class="feud-moments-head">
      <div><div class="eyebrow">🎬 FEUD MOMENTS // STORY ENGINE</div><h2>The Clashes People Share</h2></div>
      <div class="meta" id="feudMomentsMeta">Lead flips, streak breaks, revenge wins and power upsets detected from real Clash history.</div>
    </div>
    <div class="feud-moment-list" id="feudMomentsBody"><div class="feud-moments-empty">Waiting for a story-grade Clash…</div></div>
  </section>

  <section class="trending-feuds" id="trendingFeuds">
    <div class="trending-feuds-head">
      <div><div class="eyebrow">📈 TRENDING FEUDS // VIRAL SCORE</div><h2>What The Network Is Watching</h2></div>
      <div class="meta" id="trendingFeudsMeta">Trend Score combines story heat, CTA activity, challenge intent and freshness — no wallet size or paid boost.</div>
    </div>
    <div class="trending-feud-grid" id="trendingFeudsBody"><div class="trending-empty">Waiting for enough Feud activity to rank…</div></div>
  </section>


  <section class="discovery-engine" id="discoveryEngine">
    <div class="discovery-engine-head">
      <div><div class="eyebrow">📡 DISCOVERY ENGINE // START HERE</div><h2>Find The Live Story</h2></div>
      <div class="meta" id="discoveryEngineMeta">Public story momentum by default. Signed-in Hunters get relevance from real Clash history, tracked rivals and power proximity — never wallet value or paid placement.</div>
    </div>
    <div class="discovery-columns">
      <div class="discovery-col">
        <div class="discovery-col-head"><b>⚔️ FEUDS TO WATCH</b><span>STORY + PERSONAL RELEVANCE</span></div>
        <div class="discovery-feud-list" id="discoveryFeuds"><div class="discovery-empty">Scanning the live story…</div></div>
      </div>
      <div class="discovery-col">
        <div class="discovery-col-head"><b>👾 HUNTERS TO CHALLENGE</b><span>SMART MATCHES + ACTIVE FEUDS</span></div>
        <div class="discovery-hunter-list" id="discoveryHunters"><div class="discovery-empty">Mapping Hunters around active Feuds…</div></div>
      </div>
    </div>
  </section>

  <div class="moment-burst" id="feudMomentBurst"><div class="ico" id="feudMomentBurstIcon">🎬</div><b>FEUD MOMENT</b><strong id="feudMomentBurstTitle">STORY BEAT</strong><span id="feudMomentBurstDetail"></span></div>

  <section class="feud-hall" id="hallOfFeuds">
    <div class="feud-hall-head">
      <div><div class="eyebrow">🏛️ HALL OF FEUDS // NETWORK RECORDS</div><h2>Rivalries That Built a Story</h2></div>
      <div class="meta" id="hallOfFeudsMeta">Ranked only from real completed direct Clashes.</div>
    </div>
    <div class="feud-hall-columns">
      <div class="feud-hall-col"><h3>⚔️ MOST CLASHED</h3><div class="feud-hall-list" id="hallMostClashed"><div class="feud-hall-empty">Scanning rivalry history…</div></div></div>
      <div class="feud-hall-col"><h3>⚖️ CLOSEST FEUDS</h3><div class="feud-hall-list" id="hallClosest"><div class="feud-hall-empty">Scanning rivalry history…</div></div></div>
      <div class="feud-hall-col"><h3>🔄 WILDEST SWINGS</h3><div class="feud-hall-list" id="hallWildest"><div class="feud-hall-empty">Scanning rivalry history…</div></div></div>
    </div>
  </section>

  <section class="nemesis-duel" id="nemesisDuel">
    <div class="duel-head">
      <div><div class="eyebrow">⚔️ FEATURED NEMESIS // DUEL BANNER</div><h2>Your Main Feud</h2></div>
      <div class="meta" id="nemesisDuelMeta">Pin a real Rival from Threat Radar to activate your duel banner.</div>
    </div>
    <div id="nemesisDuelBody"><div class="duel-empty">No Featured Nemesis loaded yet.</div></div>
  </section>

  <section class="threat-radar" id="threatRadar">
    <div class="threat-head">
      <div><div class="eyebrow">😈 NEMESIS THREAT RADAR // PRIVATE VIEW</div><h2>Your Rival Pressure</h2></div>
      <div class="meta" id="threatRadarMeta">Uses only Hunters you marked as rivals and your real direct Clash history.</div>
    </div>
    <div class="threat-grid" id="threatRadarGrid"><div class="threat-empty">Verify your Hunter ID to scan tracked rivals.</div></div>
  </section>

  <section class="revenge-queue" id="revengeQueue">
    <div class="revenge-head">
      <div><div class="eyebrow">🩸 REVENGE QUEUE // PRIVATE VIEW</div><h2>Run It Back</h2></div>
      <div class="meta" id="revengeQueueMeta">Tracked rivals who won your latest direct Clash appear here.</div>
    </div>
    <div class="revenge-grid" id="revengeQueueGrid"><div class="revenge-empty">Verify your Hunter ID to scan revenge targets.</div></div>
  </section>

  <section class="momentum-board" id="momentumBoard">
    <div class="momentum-head">
      <div><div class="eyebrow">🔥 HUNTER MOMENTUM // CURRENT SEASON</div><h2>Who Is Heating Up?</h2></div>
      <div class="meta" id="momentumBoardMeta">Live win streaks from real Clash history</div>
    </div>
    <div class="momentum-grid" id="momentumGrid"><div class="season-empty">Scanning momentum…</div></div>
  </section>

  <section class="crown-war" id="crownWar">
    <div class="crown-war-head">
      <div class="war-status"><i class="war-dot"></i><div><b id="crownWarStatus">CROWN WAR</b><span>LIVE CHALLENGE STATE</span></div></div>
      <div class="war-count" id="crownWarCount">0 PENDING ATTACKS</div>
    </div>
    <div class="crown-war-body">
      <div class="war-crown">
        <div class="war-avatar" id="crownWarAvatar">👑</div>
        <div class="war-copy">
          <div class="eyebrow">CURRENT CROWN</div>
          <h3 id="crownWarHolder">Waiting for Crown</h3>
          <div class="meta" id="crownWarMeta">The battlefield will activate when a Hunter takes the Crown.</div>
          <div class="crown-intel-note">🔐 Pending attack details are visible only to the current Crown holder.</div>
          <div class="war-actions">
            <button class="attack" id="crownWarAttackBtn">⚔️ ATTACK THE CROWN</button>
            <a id="crownWarProfile" href="#clashCard">VIEW HOLDER</a>
          </div>
        </div>
      </div>
      <div class="war-feed">
        <div class="war-feed-title">LATEST CROWN WAR SIGNALS</div>
        <div class="war-list" id="crownWarFeed"><div class="war-empty">No Crown combat yet.</div></div>
      </div>
    </div>
  </section>

  <section class="season-command" id="seasonCommandCenter">
    <div class="season-command-main">
      <div class="season-command-top">
        <div><div class="eyebrow">👑 SEASON COMMAND CENTER</div><h2 id="seasonCommandTitle">Crown Race</h2></div>
        <div class="season-countdown"><b id="seasonCountdown">—</b><span>UNTIL UTC SEASON RESET</span></div>
      </div>
      <div id="seasonCrownCard" class="crown-command">
        <div class="crown-icon">👑</div>
        <div class="crown-name"><b>Waiting for the first Crown</b><span>Win a Clash to start the race.</span></div>
        <div class="crown-record"><b>0 WINS</b><span>NO HOLDER YET</span></div>
      </div>
      <div class="season-stats-row">
        <div class="season-stat"><b id="seasonCommandBattles">0</b><span>SEASON CLASHES</span></div>
        <div class="season-stat"><b id="seasonCommandHunters">0</b><span>ACTIVE HUNTERS</span></div>
        <div class="season-stat"><b id="seasonCommandLeader">—</b><span>CROWN HOLDER</span></div>
      </div>
    </div>
    <div class="season-command-board">
      <div class="season-board-head">
        <div><div class="eyebrow">🔥 TOP 3 // CURRENT SEASON</div><h3>Front Line</h3></div>
        <div class="meta" id="seasonCommandMeta">Live Crown standings</div>
      </div>
      <div class="season-top3" id="seasonCommandTop3"><div class="season-empty">Loading season leaders…</div></div>
    </div>
  </section>

  <section class="spotlight" id="networkSpotlight">
    <div class="spot-head">
      <div class="spot-title-wrap"><i class="spot-live"></i><div><b>NETWORK SPOTLIGHT</b><br><span>FEATURED HUNTER / FEATURED RIVALRY</span></div></div>
      <div class="spot-pager" id="spotPager"><i class="spot-dot active"></i><i class="spot-dot"></i><i class="spot-dot"></i><i class="spot-dot"></i></div>
    </div>
    <div id="spotlightBody"><div class="spot-empty">Scanning the hottest Hunter stories…</div></div>
  </section>

  <section class="network-pulse" id="networkPulse">
    <div class="pulse-head">
      <div class="pulse-title"><i class="pulse-live-dot"></i><div><b>LIVE NETWORK PULSE</b><br><span>CLASHES · CROWN · PROOF · UNLOCKS</span></div></div>
      <div class="pulse-meta"><span id="pulseCount">0</span> SIGNALS // AUTO REFRESH 12S</div>
    </div>
    <div class="pulse-track-wrap">
      <div class="pulse-track" id="pulseTrack"><div class="pulse-empty">Scanning the Human Alpha Network…</div></div>
    </div>
  </section>

  <section class="heat-zone" id="networkHeatmap">
    <div class="heat-panel">
      <div class="heat-top">
        <div><div class="eyebrow">🔥 NETWORK HEATMAP</div><h2>Trending Hunters</h2></div>
        <div class="meta">Heat is based only on recent BL3 activity — not a financial or quality score.</div>
      </div>
      <div class="hunter-heat-grid" id="hunterHeatGrid"><div class="heat-empty">Calculating Hunter heat…</div></div>
    </div>
    <div class="heat-panel">
      <div class="heat-top">
        <div><div class="eyebrow">⚔️ RIVALRY HEAT</div><h2>Hot Matchups</h2></div>
        <div class="meta">The most active direct Clash pairs in the recent battle stream.</div>
      </div>
      <div class="rivalry-heat-list" id="rivalryHeatList"><div class="heat-empty">Scanning rivalries…</div></div>
    </div>
  </section>

  <section class="card onboarding" id="firstHunt">
    <div class="onboarding-top">
      <div>
        <div class="eyebrow">NEW HUNTER // 30 SECOND START</div>
        <h2>Your First Hunt</h2>
        <div class="meta">BL3 makes sense after one real loop: claim an identity, prove the wallet behind it, then make one move in the network.</div>
      </div>
      <div style="text-align:right">
        <div class="onboarding-progress" id="onboardingProgress">0 / 3</div>
        <button class="btn onboarding-dismiss" onclick="dismissOnboarding()">Hide guide</button>
      </div>
    </div>
    <div class="onboarding-steps">
      <div class="onboarding-step" id="onboardProfile"><div class="step-num">STEP 01</div><b>Choose your Hunter ID</b><div class="meta" id="onboardProfileText">Replace demo_user with your name and load the Passport.</div></div>
      <div class="onboarding-step" id="onboardWallet"><div class="step-num">STEP 02</div><b>Verify your wallet</b><div class="meta" id="onboardWalletText">Connect + sign once so the Hunter ID belongs to you.</div></div>
      <div class="onboarding-step" id="onboardAction"><div class="step-num">STEP 03</div><b>Make your first move</b><div class="meta" id="onboardActionText">Enter an Arena or complete an Alpha Clash.</div></div>
    </div>
    <div class="onboarding-actions">
      <button class="btn hot" onclick="jumpToPassport()">01 Passport</button>
      <button class="btn violet" onclick="jumpToWallet()">02 Verify Wallet</button>
      <button class="btn" onclick="jumpToAction()">03 First Move</button>
    </div>
  </section>

  <div class="grid v9-main-grid">
    <main id="arenaSection">
      <div class="section-title"><div><div class="eyebrow">LIVE OPPORTUNITY LAYER</div><h2>Hunt the Network</h2><div class="meta">Enter active Arenas, submit proof, and build a record Hunters can actually inspect.</div></div><button class="btn tab" onclick="loadArenas()">↻ SCAN NETWORK</button></div>
      <div id="arenas"><div class="card">Scanning the network…</div></div>
    </main>

    <aside>
      <div class="card creature-card" id="passportCard">
        <div class="eyebrow">HUNTER ID // LIVING PASSPORT</div>
        <h2 style="margin-top:8px">Your Hunter Core</h2>
        <div class="meta" style="margin-bottom:10px">The persistent identity layer behind your Creature, REP, Crown rank and public Loadout.</div>
        <input id="username" value="demo_user" placeholder="BL3 username">
        <button class="btn" onclick="loadUser()">Load Profile</button>
        <button class="btn violet" onclick="openPublicProfile()">↗ View Public Hunter Profile</button>
        <div class="creature-head">
          <div class="creature-avatar" id="creatureAvatar">🥚</div>
          <div><div class="creature-stage" id="creatureStage">DORMANT</div><div class="creature-name" id="creatureName">BL3 Seed</div><div class="meta" id="creatureLevel">LEVEL 1</div></div>
        </div>
        <div class="small" style="display:flex;justify-content:space-between"><span>EVOLUTION</span><span id="evolutionText">0 / 100 XP</span></div>
        <div class="progress"><div id="evolutionBar"></div></div>
        <div class="passport-grid">
          <div class="stat"><div class="num" id="xp">0</div><div class="small">XP</div></div>
          <div class="stat"><div class="num" id="streak">0</div><div class="small">STREAK</div></div>
          <div class="stat"><div class="num" id="rank">-</div><div class="small">RANK</div></div>
          <div class="stat"><div class="num" id="wins">0</div><div class="small">WINS</div></div>
          <div class="stat"><div class="num" id="network">0</div><div class="small">NETWORK</div></div>
          <div class="stat"><div class="num" id="earned">0</div><div class="small">EARNED</div></div>
          <div class="stat"><div class="num" id="reputation">0</div><div class="small">REP</div></div>
        </div>
        <div class="empire"><span class="meta">👥 VERIFIED NETWORK</span><b id="empireLabel">0 HUNTERS</b></div>
        <div id="streakReward" class="meta" style="margin-top:12px">🔥 Next: 3-Day Flame</div>
        <button id="streakClaimButton" class="btn hot hidden" onclick="claimStreakReward()">🎁 Claim Streak Reward</button>
      </div>

      <div class="card" id="clashCard" style="margin-top:16px">
        <div class="eyebrow">ALPHA CLASH // CREATURE BATTLE</div>
        <h3 style="margin-top:8px">Challenge a Hunter</h3>
        <div class="meta">Pick any BL3 hunter. Creature power is based on real Passport progress, with a small chaos roll. No money, no XP farming — just wins, identity and shareable chaos.</div>
        <input id="battleOpponent" placeholder="Opponent username">
        <button class="btn hot" onclick="battleHunter()">⚔️ START CLASH</button>
        <button class="btn" onclick="sendChallengeRequest()">📨 SEND CHALLENGE REQUEST</button>
        <div id="battleResult" class="battle-result hidden"></div>
      </div>

      <div class="card" style="margin-top:16px">
        <div class="eyebrow">SEASON // CROWN RACE</div>
        <h3 style="margin-top:8px">Claim the BL3 Crown</h3>
        <div class="meta">Every UTC month is a fresh Clash season. Wins move you up the Crown Race; no token or cash reward is implied.</div>
        <div class="season-grid">
          <div class="season-tile"><div class="small">SEASON</div><div class="num" id="seasonKey">—</div></div>
          <div class="season-tile"><div class="small">YOUR RECORD</div><div class="num" id="seasonRecord">0-0</div></div>
          <div class="season-tile"><div class="small">WIN STREAK</div><div class="num" id="seasonStreak">0</div></div>
          <div class="season-tile"><div class="small">CROWN RANK</div><div class="num" id="seasonRank">—</div></div>
        </div>
        <div class="proof" style="margin-top:10px"><span class="small">CURRENT CROWN</span><div class="crown-holder" id="crownHolder">👑 Waiting for the first win</div></div>
        <button id="crownChallengeButton" class="btn hot hidden" onclick="challengeCrown()">⚔️ CHALLENGE THE CROWN</button>
        <div id="crownDefenseStats" class="meta" style="margin-top:10px">Crown defenses: —</div>
        <div id="seasonLeaders" style="margin-top:8px"></div>
      </div>

      <div class="card" style="margin-top:16px">
        <div class="eyebrow">DAILY MISSIONS // NO BONUS FARMING</div>
        <h3 style="margin-top:8px">Today's Hunt</h3>
        <div class="meta">Four daily actions that push the real BL3 loop. Mission completion is a status signal only — no extra XP is minted here.</div>
        <div class="proof" style="margin-top:12px"><span class="small">DAILY PROGRESS</span><div class="crown-holder" id="dailyProgress">0 / 4</div></div>
        <div id="dailyMissions" style="margin-top:8px"><div class="meta">Loading missions…</div></div>
      </div>

      <div class="card" style="margin-top:16px">
        <div class="eyebrow">CHALLENGE INBOX // HUNTER TO HUNTER</div>
        <h3 style="margin-top:8px">Incoming Challenges</h3>
        <div class="meta">Signed-in hunters can send a real challenge request. Accepting resolves the Alpha Clash and creates a public Battle Card.</div>
        <div id="challengeInbox" style="margin-top:10px"><div class="meta">Sign in to load your inbox.</div></div>
        <button class="btn" onclick="loadInbox()">↻ Refresh Inbox</button>
      </div>

      <div class="card" style="margin-top:16px">
        <div class="eyebrow">SIGNAL CENTER // PRIVATE NOTIFICATIONS</div>
        <h3 style="margin-top:8px">What Happened While You Were Away</h3>
        <div class="meta">Private Hunter signals for challenges, Clash results, Crown events and Arena outcomes. Wallet sign-in is required to read them.</div>
        <div id="signalCenter" style="margin-top:10px"><div class="meta">Sign in to load private signals.</div></div>
        <div class="battle-actions"><button class="btn" onclick="loadSignals()">↻ Refresh Signals</button><button class="btn violet" onclick="markSignalsRead()">✓ Mark All Read</button></div>
      </div>

      <div class="card" style="margin-top:16px">
        <div class="eyebrow"><span class="pulse"></span> LIVE NETWORK // ACTIVITY</div>
        <h3 style="margin-top:8px">The Network Is Moving</h3>
        <div class="meta">Recent battles, Crown attacks, Arena launches, proofs, referrals and verified casts. Auto-refreshes every 20 seconds.</div>
        <div id="activityFeed" class="feed"><div class="meta">Listening to the network…</div></div>
        <button class="btn" onclick="loadActivity()">↻ Refresh Activity</button>
      </div>

      <div class="card" style="margin-top:16px">
        <div class="eyebrow">🎯 RIVAL WATCH // PRIVATE FEED</div>
        <h3 style="margin-top:8px">Your Rivals Are Active</h3>
        <div class="meta">A focused feed for Hunters you marked as Rivals — clashes, challenges, Crown moves, Arena launches and proofs. Wallet sign-in is required.</div>
        <div id="rivalFeed" class="feed"><div class="meta">Sign in and mark a Hunter as Rival to start watching.</div></div>
        <div class="battle-actions"><button class="btn" onclick="loadRivalFeed()">↻ Refresh Rivals</button><button class="btn violet" onclick="openRivalDirectory()">🎯 View Rivals</button></div>
      </div>

      <div class="card" style="margin-top:16px">
        <div class="eyebrow">🧭 HUNTER DISCOVERY // MATCHMAKING</div>
        <h3 style="margin-top:8px">Suggested Rivals</h3>
        <div class="meta">Active Hunters near your current XP and reputation. Follow them, mark a Rival, or open their public profile.</div>
        <div id="hunterDiscovery" class="feed"><div class="meta">Sign in to discover Hunters.</div></div>
        <button class="btn" onclick="loadDiscovery()">↻ Find Hunters</button>
      </div>

      <div class="card" id="walletCard" style="margin-top:16px">
        <div class="eyebrow">IDENTITY</div><h3 style="margin-top:8px">Wallet Proof</h3>
        <input id="wallet" placeholder="Wallet address" readonly>
        <button class="btn" onclick="connectWallet()">Connect Wallet</button>
        <button class="btn violet" onclick="signInWallet()">Sign Message</button>
        <div id="authStatus" class="meta" style="margin-top:10px">Not signed in</div>
      </div>

      <div class="card" style="margin-top:16px">
        <div class="eyebrow">DAILY LOOP</div><h3 style="margin-top:8px">Build Reputation</h3>
        <button class="btn hot" onclick="quest('checkin')">🔥 Daily Check-in +10 XP</button>
        <button class="btn" onclick="share()">📢 Create BL3 Cast</button>
        <input id="castUrl" placeholder="Paste Farcaster cast URL">
        <button class="btn" onclick="verifyShare()">Verify Cast +25 XP</button>
        <button class="btn" onclick="invite()">👥 Copy Invite Link +50 XP</button>
      </div>
    </aside>
  </div>

  <div class="grid" style="margin-top:36px">
    <section class="card">
      <div class="eyebrow">PROJECT DESK</div>
      <h2 style="margin-top:8px">Launch an Arena</h2>
      <div class="meta">MVP mode: BL3 does not custody funds. The project is responsible for winner payment. Never send funds to BL3 through this form.</div>
      <input id="arenaTitle" placeholder="Arena title">
      <textarea id="arenaDescription" placeholder="What should hunters discover, test, create or prove?"></textarea>
      <select id="arenaCategory"><option>Alpha</option><option>Research</option><option>Product</option><option>Bug Hunt</option><option>Meme</option><option>Growth</option></select>
      <input id="arenaBounty" type="number" min="0" step="0.01" placeholder="Listed bounty amount (USDC)">
      <input id="arenaDeadline" placeholder="Deadline, e.g. 2026-10-05">
      <button class="btn hot" onclick="createArena()">Launch Arena →</button>
    </section>

    <section class="card">
      <div class="eyebrow">SIGNAL BOARD</div><h2 style="margin-top:8px">Top Hunters</h2>
      <div id="leaderboard">Loading…</div>
    </section>
  </div>

  <div class="footer">BL3 // BUILD. MEME. REPEAT. // V13.3 GLOBAL SEARCH<div class="quality-footer"><a href="/status">SYSTEM STATUS</a><span>•</span><a href="/transparency">TRANSPARENCY</a><span>•</span><a href="/api/meta">API META</a></div></div>
</div>

<div class="clash-replay-shell" id="clashReplayShell">
  <div class="clash-replay" id="clashReplayCard">
    <div class="combo-burst" id="comboBurst"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div>
    <div class="replay-top">
      <div><b>⚔️ BL3 // CINEMATIC CLASH REPLAY</b><br><span id="replayTopMeta">ALPHA CLASH RESULT</span></div>
      <button class="replay-close" onclick="closeClashReplay()">CLOSE ✕</button>
    </div>
    <div class="replay-arena replay-step">
      <div class="replay-fighter" id="replayChallenger">
        <div class="replay-avatar" id="replayChallengerAvatar">👾</div>
        <div class="replay-name" id="replayChallengerName">CHALLENGER</div>
        <div class="replay-power">POWER <b id="replayChallengerPower">0</b></div>
      </div>
      <div class="replay-vs replay-step s2">
        <div class="vs">VS</div>
        <div class="replay-slash"></div>
        <div class="battle-no" id="replayBattleNo">CLASH #—</div>
      </div>
      <div class="replay-fighter" id="replayOpponent">
        <div class="replay-avatar" id="replayOpponentAvatar">👾</div>
        <div class="replay-name" id="replayOpponentName">OPPONENT</div>
        <div class="replay-power">POWER <b id="replayOpponentPower">0</b></div>
      </div>
    </div>
    <div class="replay-result replay-step s3">
      <div class="replay-combo" id="replayCombo"><span id="replayComboIcon">🔥</span><strong id="replayComboLabel">HOT STREAK</strong><span id="replayComboCount">3 WINS</span></div>
      <div class="label" id="replayOutcomeLabel">WINNER</div>
      <h2 id="replayWinner">—</h2>
      <p id="replayCommentary">Battle commentary will appear here.</p>
      <div class="replay-meter">
        <div class="replay-meter-card"><span>POWER GAP</span><b id="replayPowerGap">0</b></div>
        <div class="replay-meter-card"><span>RESULT</span><b id="replayPersonalResult">—</b></div>
      </div>
      <div class="replay-actions replay-step s4">
        <a class="hot" id="replayOpenCard" href="#" target="_blank" rel="noopener">🃏 OPEN BATTLE CARD</a>
        <button class="violet" onclick="shareBattle()">📣 SHARE RESULT</button>
        <button onclick="copyChallengeLink()">🔗 COPY CHALLENGE</button>
        <button onclick="closeClashReplay()">BACK TO ARENA</button>
      </div>
    </div>
  </div>
</div>

<div class="combo-toast" id="comboToast"><b id="comboToastTitle">🔥 HOT STREAK</b><span id="comboToastMeta">3 STRAIGHT SEASON WINS</span></div>

<div class="war-alert-shell" id="warAlertShell">
  <div class="war-alert-card">
    <div class="war-alert-icon" id="warAlertIcon">🚨</div>
    <div class="war-alert-kicker" id="warAlertKicker">CROWN WAR ALERT</div>
    <div class="war-alert-title" id="warAlertTitle">CROWN UNDER ATTACK</div>
    <div class="war-alert-detail" id="warAlertDetail">A new Crown challenge has entered the network.</div>
    <div class="war-alert-actions">
      <button class="danger" id="warAlertAttackBtn">⚔️ OPEN CROWN TARGET</button>
      <a id="warAlertClashLink" href="#crownWar">OPEN WAR ROOM</a>
      <button id="warAlertDismissBtn">DISMISS</button>
    </div>
  </div>
</div>

<div class="war-mini-toast" id="warMiniToast">
  <div class="ico" id="warMiniIcon">🚨</div>
  <div><b id="warMiniTitle">Crown War Alert</b><span id="warMiniDetail">New Crown activity detected.</span></div>
</div>

<div id="message" class="message hidden"></div>

<script>
let username="demo_user";
let messageTimer=null;
let lastBattleShare=null;
let currentCrown=null;
let onboardingDismissed=false;
try{onboardingDismissed=localStorage.getItem("bl3_onboarding_hidden")==="1"}catch(e){}
function dismissOnboarding(){
 const el=document.getElementById("firstHunt");if(el)el.classList.add("hidden-by-user");
 try{localStorage.setItem("bl3_onboarding_hidden","1")}catch(e){}
 show("First Hunt guide hidden. You can still use BL3 normally.");
}
function jumpToPassport(){document.getElementById("passportCard")?.scrollIntoView({behavior:motionBehavior(),block:"center"});document.getElementById("username")?.focus()}
function jumpToWallet(){document.getElementById("walletCard")?.scrollIntoView({behavior:motionBehavior(),block:"center"})}
function jumpToAction(){document.getElementById("arenaSection")?.scrollIntoView({behavior:motionBehavior(),block:"start"})}
function openPublicProfile(){currentUser();window.open("/hunter/"+encodeURIComponent(username),"_blank","noopener")}
async function loadOnboarding(){
 currentUser();
 const d=await jsonFetch("/api/onboarding/"+encodeURIComponent(username));
 if(!d.success)return;
 const p=document.getElementById("onboardingProgress");if(p)p.innerText=d.completed+" / 3"+(d.completed===3?" • READY ✓":" ");
 [["onboardProfile",d.profile],["onboardWallet",d.wallet],["onboardAction",d.first_action]].forEach(([id,done])=>{const el=document.getElementById(id);if(el)el.classList.toggle("done",!!done)});
 const a=document.getElementById("onboardProfileText"),b=document.getElementById("onboardWalletText"),c=document.getElementById("onboardActionText");
 if(a)a.innerText=d.profile?"Hunter ID active ✓":"Replace demo_user with your name and load the Passport.";
 if(b)b.innerText=d.wallet?"Wallet verified ✓":"Connect + sign once so the Hunter ID belongs to you.";
 if(c)c.innerText=d.first_action?"First network move complete ✓":"Enter an Arena or complete an Alpha Clash.";
 const guide=document.getElementById("firstHunt");
 if(guide&&onboardingDismissed)guide.classList.add("hidden-by-user");
}
function currentUser(){username=document.getElementById("username").value.trim()||"demo_user";return username}
function show(text){const el=document.getElementById("message");el.innerText=text;el.classList.remove("hidden");clearTimeout(messageTimer);messageTimer=setTimeout(()=>el.classList.add("hidden"),4500)}
async function jsonFetch(url,options){const r=await fetch(url,options);let d={};try{d=await r.json()}catch(e){d={success:false,message:"Invalid server response"}}return d}

function targetRevengeRival(name){
 const opponent=document.getElementById("battleOpponent");
 if(opponent)opponent.value=name;
 document.getElementById("clashCard")?.scrollIntoView({behavior:motionBehavior(),block:"center"});
 show("🩸 Revenge target locked: "+name);
}

async function loadRevengeQueue(){
 currentUser();
 const d=await jsonFetch("/api/revenge-queue/"+encodeURIComponent(username));
 const grid=document.getElementById("revengeQueueGrid");
 const meta=document.getElementById("revengeQueueMeta");
 if(!grid)return;

 if(!d?.success){
   grid.innerHTML='<div class="revenge-empty">'+escapeHtml(d?.message||"Verify your Hunter ID to scan revenge targets.")+'</div>';
   return;
 }

 const rows=Array.isArray(d.targets)?d.targets:[];
 if(meta)meta.textContent=Number(d.count||0)+" open revenge target"+(Number(d.count||0)===1?"":"s")+" · tracked rivals only";

 if(!rows.length){
   grid.innerHTML='<div class="revenge-empty">Queue clear. None of your tracked rivals currently owns the last direct Clash against you.</div>';
   return;
 }

 grid.innerHTML=rows.map(r=>{
   const s=r.state||{};
   return '<div class="revenge-card revenge-'+escapeHtml(s.key||"open")+'">'
     +'<div class="revenge-top"><div class="revenge-id"><div class="revenge-avatar">'+escapeHtml(r.avatar||"👾")+'</div>'
     +'<div class="revenge-name"><b>'+escapeHtml(r.username)+'</b><span>'+escapeHtml(r.creature||"Hunter")+' · LVL '+Number(r.level||1)+'</span></div></div>'
     +'<div class="revenge-state"><b>'+escapeHtml((s.icon||"⚔️")+" "+(s.label||"RUN IT BACK"))+'</b><span>'+Number(r.loss_streak||0)+' straight direct loss'+(Number(r.loss_streak||0)===1?"":"es")+'</span></div></div>'
     +'<div class="revenge-actions">'
     +'<a href="/clash/'+Number(r.last_battle_id||0)+'">LAST CLASH</a>'
     +'<a href="/rivalry/'+encodeURIComponent(username)+'/'+encodeURIComponent(r.username)+'">RIVALRY</a>'
     +'<button class="runback js-revenge-target" data-rival="'+escapeHtml(r.username)+'">🩸 RUN IT BACK</button>'
     +'</div></div>';
 }).join("");
}

function targetFeaturedNemesis(name){
 const opponent=document.getElementById("battleOpponent");
 if(opponent)opponent.value=name;
 document.getElementById("clashCard")?.scrollIntoView({behavior:motionBehavior(),block:"center"});
 show("⚔️ Featured Nemesis locked: "+name);
}

async function shareFeaturedNemesis(owner,rival){
 const path="/rivalry/"+encodeURIComponent(owner)+"/"+encodeURIComponent(rival);
 const url=location.origin+path;
 try{
   await navigator.clipboard.writeText(url);
   show("📣 Rivalry link copied.");
 }catch(e){
   show(url);
 }
}

function motionBehavior(){
 return window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth";
}

function pulseAgo(value){
 if(!value)return "NOW";
 const t=new Date(value);if(Number.isNaN(t.getTime()))return "";
 const s=Math.max(0,Math.floor((Date.now()-t.getTime())/1000));
 if(s<60)return s+"s";
 if(s<3600)return Math.floor(s/60)+"m";
 return Math.floor(s/3600)+"h";
}

async function loadOpsPulse(){
 currentUser();
 const body=document.getElementById("opsPulseBody");
 if(!body)return;

 const d=await jsonFetch("/api/ops-pulse/"+encodeURIComponent(username));
 if(!d?.success){
   body.innerHTML='<div class="mission-empty">'+escapeHtml(d?.message||"Verify your Hunter ID to open Ops Pulse.")+'</div>';
   return;
 }

 const latest=Array.isArray(d.latest)?d.latest:[];
 body.innerHTML=''
   +'<div class="ops-pulse">'
   +'<div class="ops-pulse-head"><b>⚡ OPS PULSE // LAST '+Number(d.window_hours||24)+'H</b><span>Private Hunter activity</span></div>'
   +'<div class="ops-pulse-grid">'
   +'<div class="ops-pulse-stat"><b>'+Number(d.clashes||0)+'</b><span>CLASHES</span></div>'
   +'<div class="ops-pulse-stat"><b>'+Number(d.wins||0)+'</b><span>WINS</span></div>'
   +'<div class="ops-pulse-stat"><b>'+Number(d.losses||0)+'</b><span>LOSSES</span></div>'
   +'<div class="ops-pulse-stat"><b>'+Number(d.unlocks||0)+'</b><span>UNLOCKS</span></div>'
   +'<div class="ops-pulse-stat"><b>'+Number(d.pending_challenges||0)+'</b><span>PENDING</span></div>'
   +'</div>'
   +(latest.length?'<div class="ops-pulse-feed">'+latest.map(e=>'<a class="ops-pulse-row" href="'+escapeHtml(e.target||"#")+'"><i>'+escapeHtml(e.icon||"⚡")+'</i><div><b>'+escapeHtml(e.title||"Signal")+'</b><span>'+escapeHtml(e.detail||"")+'</span></div><em>'+escapeHtml(pulseAgo(e.created_at))+'</em></a>').join("")+'</div>':'')
   +'</div>';
}

async function loadMissionControl(){
 currentUser();
 const body=document.getElementById("missionControlBody");
 const meta=document.getElementById("missionControlMeta");
 if(!body)return;

 const d=await jsonFetch("/api/mission-control/"+encodeURIComponent(username));
 if(!d?.success){
   body.innerHTML='<div class="mission-empty">'+escapeHtml(d?.message||"Verify your Hunter ID to open Mission Control.")+'</div>';
   return;
 }

 const revenge=d.top_revenge||{};
 const closest=d.closest||{};
 const action=d.next_action||{};
 const deck=Array.isArray(d.action_deck)?d.action_deck:[];
 if(meta)meta.textContent=(d.season_key||"CURRENT SEASON")+" · private Hunter priorities";

 body.innerHTML=''
   +'<div class="mission-grid">'
   +'<div class="mission-stat"><b>🔥 '+Number(d.season_streak||0)+'</b><span>SEASON WIN STREAK</span></div>'
   +'<div class="mission-stat"><b>📨 '+Number(d.pending_inbox||0)+'</b><span>PENDING CHALLENGES</span></div>'
   +'<div class="mission-stat"><b>✨ '+Number(d.unseen_unlocks||0)+'</b><span>UNSEEN UNLOCKS</span></div>'
   +'<div class="mission-stat"><b>'+(d.is_crown?'👑 CROWN':'😈 '+escapeHtml(d.featured_nemesis||"NOT PINNED"))+'</b><span>'+(d.is_crown?'CURRENT SEASON HOLDER':'FEATURED NEMESIS')+'</span></div>'
   +'</div>'
   +'<div class="mission-next"><div class="mission-next-copy"><b>'+escapeHtml((action.icon||"🧭")+" "+(action.title||"NEXT MOVE"))+'</b><span>'+escapeHtml(action.detail||closest.detail||"Keep hunting.")+'</span></div>'
   +'<a href="'+escapeHtml(action.target||("#passportCard"))+'">OPEN</a></div>'
   +(deck.length?'<div class="mission-action-deck">'+deck.map(item=>'<a class="mission-action-card" href="'+escapeHtml(item.target||"#")+'"><b>'+escapeHtml((item.icon||"⚡")+" "+(item.title||"ACTION"))+'</b><span>'+escapeHtml(item.detail||"")+'</span></a>').join("")+'</div>':'');
}

let feudLiveVersion=null;
let feudLiveLatestBattle=0;
let feudLiveBusy=false;

async function refreshFeudLive(force=false){
 if(feudLiveBusy)return false;
 if(document.hidden&&!force)return false;
 feudLiveBusy=true;
 try{
   const d=await jsonFetch("/api/feud-live-state");
   if(!d?.success)return false;
   const next=String(d.version||"");
   const changed=feudLiveVersion!==null&&next!==feudLiveVersion;
   feudLiveVersion=next;
   feudLiveLatestBattle=Number(d.latest_battle_id||0);
   const nextEvent=Number(d.latest_feud_event_id||0);
   const eventChanged=feudLiveLatestEvent!==0&&nextEvent!==feudLiveLatestEvent;
   feudLiveLatestEvent=nextEvent;
   const nextMoment=Number(d.latest_feud_moment_id||0);
   const momentChanged=feudLiveLatestMoment!==0&&nextMoment!==feudLiveLatestMoment;
   feudLiveLatestMoment=nextMoment;
   if(force||changed||eventChanged||momentChanged){
     await Promise.allSettled([loadHallOfFeuds(),loadSeasonFeudSpotlight(),loadFeudEvents(),loadFeudMoments(),loadTrendingFeuds(),loadDiscoveryEngine()]);
   }
   return changed;
 }finally{
   feudLiveBusy=false;
 }
}

let feudLiveLatestEvent=0;
let feudLiveLatestMoment=0;
let feudEventBurstTimer=null;
let feudMomentBurstTimer=null;

function showFeudEventBurst(e){
 if(!e)return;
 const shell=document.getElementById("feudEventBurst");
 if(!shell)return;
 document.getElementById("feudEventBurstIcon").textContent=e.icon||"🔥";
 document.getElementById("feudEventBurstTitle").textContent=e.label||"RIVALRY ESCALATED";
 document.getElementById("feudEventBurstDetail").textContent=(e.hunter_a||"Hunter A")+" vs "+(e.hunter_b||"Hunter B")+" · Clash #"+Number(e.battle_id||0);
 shell.classList.remove("show"); void shell.offsetWidth; shell.classList.add("show");
 clearTimeout(feudEventBurstTimer);
 feudEventBurstTimer=setTimeout(()=>shell.classList.remove("show"),3600);
}

async function loadFeudEvents(){
 const d=await jsonFetch("/api/feud-events?limit=10");
 const body=document.getElementById("feudEventsBody");
 const meta=document.getElementById("feudEventsMeta");
 if(!body)return;
 if(!d?.success){body.innerHTML='<div class="feud-events-empty">Could not load Feud Events.</div>';return;}
 const rows=Array.isArray(d.events)?d.events:[];
 if(meta)meta.textContent=Number(d.total_events||0)+" escalation event"+(Number(d.total_events||0)===1?"":"s")+" · one event max per Clash · ⚙️ "+(d.engine||"standard");
 body.innerHTML=rows.length?rows.map(e=>'<a class="feud-event" href="/rivalry/'+encodeURIComponent(e.hunter_a||"")+'/'+encodeURIComponent(e.hunter_b||"")+'"><div class="feud-event-icon">'+escapeHtml(e.icon||"🔥")+'</div><div class="feud-event-copy"><b>'+escapeHtml((e.hunter_a||"Hunter A")+" VS "+(e.hunter_b||"Hunter B"))+'</b><span>'+escapeHtml(e.label||"RIVALRY ESCALATED")+' · Winner: '+escapeHtml(e.winner||"—")+'</span></div><div class="feud-event-side"><b>CLASH #'+Number(e.battle_id||0)+'</b><span>TIER '+Number(e.tier_level||0)+'</span></div></a>').join(""):'<div class="feud-events-empty">No tier-crossing Feud Events yet. The next completed direct Clash can start the feed.</div>';
}

function showFeudMomentBurst(m){
 if(!m)return;
 const shell=document.getElementById("feudMomentBurst");
 if(!shell)return;
 document.getElementById("feudMomentBurstIcon").textContent=m.icon||"🎬";
 document.getElementById("feudMomentBurstTitle").textContent=m.label||"FEUD MOMENT";
 document.getElementById("feudMomentBurstDetail").textContent=m.detail||((m.winner||"A Hunter")+" changed the story.");
 shell.classList.remove("show"); void shell.offsetWidth; shell.classList.add("show");
 clearTimeout(feudMomentBurstTimer);
 feudMomentBurstTimer=setTimeout(()=>shell.classList.remove("show"),4200);
}

async function shareFeudMoment(momentId){
 const d=await jsonFetch("/api/feud-moment/"+Number(momentId||0)+"/cast-kit");
 if(!d?.success){show(d?.message||"Could not build Cast Kit.");return;}
 const kit=d.cast_kit||{};
 const text=(kit.cast_text||"BL3 Feud Moment")+"\n"+(kit.page_url||"");
 try{
   if(navigator.share){await navigator.share({title:kit.title||"BL3 Feud Moment",text:kit.cast_text||"",url:kit.page_url||location.href});return;}
   await navigator.clipboard.writeText(text); show("📣 Cast Kit copied — paste it into Farcaster.");
 }catch(e){try{await navigator.clipboard.writeText(text);show("📣 Cast Kit copied — paste it into Farcaster.");}catch(_){show(kit.page_url||location.href);}}
}
async function copyFeudCast(momentId){
 const d=await jsonFetch("/api/feud-moment/"+Number(momentId||0)+"/cast-kit");
 if(!d?.success){show(d?.message||"Could not build Cast Kit.");return;}
 const kit=d.cast_kit||{}; const text=(kit.cast_text||"")+"\n"+(kit.page_url||"");
 try{await navigator.clipboard.writeText(text);show("📋 Farcaster cast copied.");}catch(e){show(text);}
}

async function loadFeudMoments(){
 const d=await jsonFetch("/api/feud-moments?limit=10");
 const body=document.getElementById("feudMomentsBody");
 const meta=document.getElementById("feudMomentsMeta");
 if(!body)return;
 if(!d?.success){body.innerHTML='<div class="feud-moments-empty">Could not load Feud Moments.</div>';return;}
 const rows=Array.isArray(d.moments)?d.moments:[];
 if(meta)meta.textContent=Number(d.total_moments||0)+" story moment"+(Number(d.total_moments||0)===1?"":"s")+" · detected from completed direct Clashes · ⚙️ "+(d.engine||"standard");
 body.innerHTML=rows.length?rows.map(m=>'<div class="feud-moment"><a class="feud-moment-icon" href="/feud-moment/'+Number(m.id||0)+'">'+escapeHtml(m.icon||"🎬")+'</a><div class="feud-moment-copy"><b>'+escapeHtml(m.label||"FEUD MOMENT")+' · '+escapeHtml(m.winner||"Hunter")+'</b><span>'+escapeHtml(m.detail||"")+'</span><div class="moment-actions"><button class="moment-share" onclick="shareFeudMoment('+Number(m.id||0)+')">SHARE / CAST ↗</button><button class="moment-share" onclick="copyFeudCast('+Number(m.id||0)+')">COPY CAST</button><a href="/feud-moment/'+Number(m.id||0)+'/card.svg" target="_blank" rel="noopener">OPEN CARD</a><a href="/feud-moment/'+Number(m.id||0)+'/go/challenge-winner">CHALLENGE WINNER</a></div></div><div class="feud-moment-side"><b>CLASH #'+Number(m.battle_id||0)+'</b><span>HEAT '+Number(m.intensity||1)+'/5 · 🔁 '+Number(m.viral_clicks||0)+'</span></div></div>').join(""):'<div class="feud-moments-empty">No story-grade moments yet. A lead flip, streak break, revenge win or power upset can trigger one.</div>';
}

async function loadTrendingFeuds(){
 const d=await jsonFetch("/api/trending-feuds?limit=6&window_hours=168");
 const body=document.getElementById("trendingFeudsBody");
 const meta=document.getElementById("trendingFeudsMeta");
 if(!body)return;
 if(!d?.success){body.innerHTML='<div class="trending-empty">Could not load Trending Feuds.</div>';return;}
 const rows=Array.isArray(d.feuds)?d.feuds:[];
 if(meta)meta.textContent=(d.window_hours||168)+"h window · heat + CTA + challenge intent + freshness · ⚙️ "+(d.engine||"standard");
 body.innerHTML=rows.length?rows.map((r,i)=>'<a class="trend-feud-card" href="'+escapeHtml(r.rivalry_url||"#")+'"><div class="trend-rank"><b>#'+(i+1)+' TRENDING</b><span class="trend-badge">'+escapeHtml(r.trend_label||"RISING")+'</span></div><div class="trend-pair">'+escapeHtml(r.hunter_a||"Hunter A")+' ⚔️ '+escapeHtml(r.hunter_b||"Hunter B")+'</div><div class="trend-score">'+Number(r.trend_score||0)+'<span>TREND SCORE</span></div><div class="trend-meta"><div class="trend-stat"><b>'+Number(r.moments||0)+'</b><span>MOMENTS</span></div><div class="trend-stat"><b>'+Number(r.viral_clicks||0)+'</b><span>CTA CLICKS</span></div><div class="trend-stat"><b>'+Number(r.challenge_intent||0)+'</b><span>CHALLENGE INTENT</span></div></div></a>').join(""):'<div class="trending-empty">No Feud has enough recent story + viral activity yet. Create a Moment, share it, then let the network react.</div>';
}

async function loadDiscoveryEngine(){
 currentUser();
 let d=await jsonFetch("/api/personalized-discovery/"+encodeURIComponent(username)+"?feuds=4&hunters=6&window_hours=168");
 if(!d?.success){
   d=await jsonFetch("/api/discovery-engine?feuds=4&hunters=6&window_hours=168");
 }
 const feudBody=document.getElementById("discoveryFeuds");
 const hunterBody=document.getElementById("discoveryHunters");
 const meta=document.getElementById("discoveryEngineMeta");
 if(!feudBody||!hunterBody)return;
 if(!d?.success){
   feudBody.innerHTML='<div class="discovery-empty"><b>Discovery is offline.</b><span>The network story could not be loaded right now.</span><a href="#arenaSection">OPEN LIVE ARENAS</a></div>';
   hunterBody.innerHTML='<div class="discovery-empty"><b>No match data yet.</b><span>Load your Hunter identity or try again in a moment.</span><a href="#passportCard">OPEN PASSPORT</a></div>';
   return;
 }
 const feuds=Array.isArray(d.feuds)?d.feuds:[];
 const hunters=Array.isArray(d.hunters)?d.hunters:[];
 const personalized=!!d.personalized;
 if(meta)meta.innerHTML=(d.window_hours||168)+"h discovery window · "+(personalized?'<span class="discovery-personal">✦ PERSONALIZED</span>':'PUBLIC STORY')+" · ⚙️ "+escapeHtml(d.engine||"standard");
 const empty=d.empty_state||{};
 feudBody.innerHTML=feuds.length?feuds.map((r,i)=>
   '<div class="discovery-feud"><div class="discovery-feud-top"><span class="discovery-feud-rank">#'+(i+1)+' '+(personalized?'FOR YOU':'DISCOVER')+'</span><span class="discovery-feud-badge">'+escapeHtml(r.trend_label||"WATCHING")+'</span></div>'+ 
   '<h3>'+escapeHtml(r.hunter_a||"Hunter A")+' ⚔️ '+escapeHtml(r.hunter_b||"Hunter B")+'</h3>'+ 
   '<div class="discovery-reason">'+escapeHtml(r.discovery_reason||"Recent Feud activity is pulling network attention.")+'</div>'+ 
   (r.personal_reason?'<div class="discovery-match">✦ '+escapeHtml(r.personal_reason)+'</div>':'')+
   '<div class="discovery-actions"><a href="'+escapeHtml(r.rivalry_url||"#")+'">OPEN RIVALRY</a><a class="hot" href="'+escapeHtml(r.challenge_a_url||"#")+'">CHALLENGE '+escapeHtml(r.hunter_a||"HUNTER")+'</a><a class="hot" href="'+escapeHtml(r.challenge_b_url||"#")+'">CHALLENGE '+escapeHtml(r.hunter_b||"HUNTER")+'</a></div></div>'
 ).join(""):'<div class="discovery-empty"><b>'+escapeHtml(empty.feud_title||"No live Feud story yet.")+'</b><span>'+escapeHtml(empty.feud_detail||"The first shareable Clash Moment will seed Discovery.")+'</span><a href="'+escapeHtml(empty.feud_action_url||"#clashCard")+'">'+escapeHtml(empty.feud_action_label||"START A CLASH")+'</a></div>';
 hunterBody.innerHTML=hunters.length?hunters.map(h=>
   '<div class="discovery-hunter"><div class="discovery-hunter-avatar">'+escapeHtml(h.avatar||"👾")+'</div><div class="discovery-hunter-main"><b>'+escapeHtml(h.username||"Hunter")+' · LVL '+Number(h.level||1)+'</b><span>'+escapeHtml(h.why_now||"Active in the live story")+'</span>'+(h.personal_reason?'<div class="discovery-match">✦ '+escapeHtml(h.personal_reason)+'</div>':'')+'</div><div class="discovery-hunter-score"><b>'+Number(h.personal_score??h.discovery_score??0)+'</b><span>'+(personalized?'MATCH':'DISCOVERY')+'</span>'+(h.power_gap!=null?'<small>Δ '+Number(h.power_gap)+' XP</small>':'')+'</div><div class="discovery-actions"><a href="'+escapeHtml(h.profile_url||"#")+'">PROFILE</a><a class="hot" href="'+escapeHtml(h.challenge_url||"#")+'">⚔️ CHALLENGE</a></div></div>'
 ).join(""):'<div class="discovery-empty"><b>'+escapeHtml(empty.hunter_title||"No Hunter candidates yet.")+'</b><span>'+escapeHtml(empty.hunter_detail||"As Feuds generate Moments, Hunters will surface here.")+'</span><a href="'+escapeHtml(empty.hunter_action_url||"#networkHeatmap")+'">'+escapeHtml(empty.hunter_action_label||"SCAN THE NETWORK")+'</a></div>';
}

async function loadSeasonFeudSpotlight(){
 const d=await jsonFetch("/api/season-feud-spotlight");
 const body=document.getElementById("seasonFeudSpotlightBody");
 const meta=document.getElementById("seasonFeudSpotlightMeta");
 if(!body)return;

 if(!d?.success){
   body.innerHTML='<div class="spot-feud-empty">Could not load the current-season feud spotlight.</div>';
   return;
 }

 const r=d.spotlight;
 if(meta)meta.textContent=(d.season_key||"CURRENT SEASON")+" · completed direct Clashes only · ⚙️ "+(d.engine||"standard")+(feudLiveLatestBattle?" · 🔴 LIVE #"+feudLiveLatestBattle:"");
 if(!r){
   body.innerHTML='<div class="spot-feud-empty">No completed direct rivalries in this season yet.</div>';
   return;
 }

 const tier=r.tier||{};
 body.innerHTML=''
   +'<div class="spot-feud-card">'
   +'<div class="spot-feud-side"><b>'+escapeHtml(r.hunter_a||"Hunter A")+'</b><span>'+escapeHtml((tier.icon||"⚔️")+" "+(tier.label||"RIVALRY"))+'</span></div>'
   +'<div class="spot-feud-score"><strong>'+Number(r.season_score_a||0)+'</strong><i>SEASON</i><strong>'+Number(r.season_score_b||0)+'</strong></div>'
   +'<div class="spot-feud-side right"><b>'+escapeHtml(r.hunter_b||"Hunter B")+'</b><span>LAST: '+escapeHtml(r.last_winner||"—")+'</span></div>'
   +'</div>'
   +'<div class="spot-feud-meta">'
   +'<div class="spot-feud-stat"><b>'+Number(r.clashes||0)+'</b><span>SEASON CLASHES</span></div>'
   +'<div class="spot-feud-stat"><b>'+Number(r.all_time_clashes||0)+'</b><span>ALL-TIME CLASHES</span></div>'
   +'<div class="spot-feud-stat"><b>'+Number(r.lead_changes_all_time||0)+'</b><span>LEAD CHANGES</span></div>'
   +'<div class="spot-feud-stat"><b>#'+Number(r.last_battle_id||0)+'</b><span>LATEST CLASH</span></div>'
   +'</div>'
   +'<div class="spot-feud-actions">'
   +'<a class="primary" href="'+escapeHtml(r.rivalry_url||"#")+'">🔥 OPEN RIVALRY</a>'
   +'<a href="'+escapeHtml(r.chronicle_card||"#")+'">📜 CHRONICLE CARD</a>'
   +'<a href="/clash/'+Number(r.last_battle_id||0)+'">⚔️ LAST CLASH</a>'
   +'</div>';
}

function renderFeudRecord(r,mode){
 const a=r.hunter_a||"Hunter A", b=r.hunter_b||"Hunter B";
 const tier=r.tier||{};
 let stat="";
 if(mode==="clashes")stat=Number(r.clashes||0)+" CLASHES";
 else if(mode==="closest")stat=Number(r.gap||0)+" GAP";
 else stat=Number(r.lead_changes||0)+" LEAD CHANGES";
 return '<a class="feud-record" href="/rivalry/'+encodeURIComponent(a)+'/'+encodeURIComponent(b)+'">'
   +'<div class="feud-record-main"><b>'+escapeHtml(a)+' VS '+escapeHtml(b)+'</b>'
   +'<span>'+escapeHtml((tier.icon||"⚔️")+" "+(tier.label||"RIVALRY"))+' · '+Number(r.score_a||0)+'-'+Number(r.score_b||0)+'</span></div>'
   +'<div class="feud-record-stat"><b>'+escapeHtml(stat)+'</b><span>LAST: '+escapeHtml(r.last_winner||"—")+'</span></div></a>';
}

async function loadHallOfFeuds(){
 const d=await jsonFetch("/api/rivalry-records");
 const meta=document.getElementById("hallOfFeudsMeta");
 const most=document.getElementById("hallMostClashed");
 const close=document.getElementById("hallClosest");
 const wild=document.getElementById("hallWildest");
 if(!most||!close||!wild)return;

 if(!d?.success){
   const msg='<div class="feud-hall-empty">Could not load rivalry records.</div>';
   most.innerHTML=msg;close.innerHTML=msg;wild.innerHTML=msg;
   return;
 }

 if(meta)meta.textContent=Number(d.total_rivalries||0)+" recorded rivalry"+(Number(d.total_rivalries||0)===1?"":"ies")+" · completed direct Clashes only · ⚙️ "+(d.engine||"standard")+(feudLiveLatestBattle?" · 🔴 LIVE #"+feudLiveLatestBattle:"");

 const fill=(el,rows,mode,empty)=>{
   const list=Array.isArray(rows)?rows:[];
   el.innerHTML=list.length?list.map(r=>renderFeudRecord(r,mode)).join(""):'<div class="feud-hall-empty">'+empty+'</div>';
 };
 fill(most,d.most_clashes,"clashes","No rivalry records yet.");
 fill(close,d.closest,"closest","Need at least two direct Clashes.");
 fill(wild,d.wildest,"wildest","No lead changes recorded yet.");
}

async function loadNemesisDuel(){
 currentUser();
 const d=await jsonFetch("/api/featured-nemesis/"+encodeURIComponent(username));
 const body=document.getElementById("nemesisDuelBody");
 const meta=document.getElementById("nemesisDuelMeta");
 if(!body)return;

 if(!d?.success){
   body.innerHTML='<div class="duel-empty">'+escapeHtml(d?.message||"Verify your Hunter ID to load the duel banner.")+'</div>';
   return;
 }

 const f=d.featured;
 if(!f){
   body.innerHTML='<div class="duel-empty">No Featured Nemesis yet. Open Threat Radar, choose a tracked rival with at least one direct Clash, and press ⭐ FEATURE NEMESIS.</div>';
   if(meta)meta.textContent="Your public feud banner activates after you pin a real Rival.";
   return;
 }

 const e=f.escalation||{};
 const t=e.tier||{};
 const feudPath=[
   {at:1,icon:"⚔️",label:"FIRST BLOOD"},
   {at:3,icon:"🔥",label:"IGNITED"},
   {at:5,icon:"😈",label:"NEMESIS"},
   {at:8,icon:"🩸",label:"BLOOD FEUD"},
   {at:12,icon:"🌠",label:"LEGENDARY"}
 ];
 const pulse=Array.isArray(f.pulse)?f.pulse:[];
 const rs=f.current_rivalry_streak||{};
 const chron=f.chronicle||{};
 const ownerAvatar=document.getElementById("hunterAvatar")?.textContent||document.getElementById("hudCreature")?.textContent||"👾";
 const ownerName=username||"Hunter";
 const rival=f.rival||"Rival";
 if(meta)meta.textContent=(t.icon||"⚔️")+" "+(t.label||"RIVALRY")+" · "+Number(e.total||0)+" direct clashes · ⚙️ "+(f.engine||"discovery-v13.2");

 body.innerHTML=''
   +'<div class="duel-stage">'
   +'<div class="duel-fighter"><div class="duel-avatar">'+escapeHtml(ownerAvatar)+'</div><div class="duel-fighter-copy"><b>'+escapeHtml(ownerName)+'</b><span>YOUR HUNTER ID</span></div><div class="duel-score">'+Number(e.a_wins||0)+'</div></div>'
   +'<div class="duel-vs">VS</div>'
   +'<div class="duel-fighter right"><div class="duel-avatar">'+escapeHtml(f.avatar||"👾")+'</div><div class="duel-fighter-copy"><b>'+escapeHtml(rival)+'</b><span>'+escapeHtml(f.creature||"Hunter")+' · LVL '+Number(f.level||1)+'</span></div><div class="duel-score">'+Number(e.b_wins||0)+'</div></div>'
   +'</div>'
   +'<div class="duel-tier"><b>'+escapeHtml((t.icon||"⚔️")+" "+(t.label||"RIVALRY DORMANT"))+' · LEVEL '+Number(t.level||0)+'/5</b><span>'+(t.next_at==null?'MAX RIVALRY TIER':Number(e.clashes_to_next||0)+' clashes to next tier')+'</span></div>'
   +'<div class="duel-path">'+feudPath.map(step=>{const total=Number(e.total||0);const cls=total>=step.at?"reached":Number(t.next_at||0)===step.at?"next":"locked";const note=total>=step.at?"✓":(Math.max(0,step.at-total)+" TO GO");return '<div class="duel-path-step '+cls+'"><b>'+escapeHtml(step.icon)+'</b><span>'+escapeHtml(step.label)+' · '+escapeHtml(note)+'</span></div>';}).join("")+'</div>'
   +(()=>{const s=f.stakes||{};const win=s.owner_if_win||{};const loss=s.owner_if_loss||{};const next=s.next_tier||{};return '<div class="duel-stakes"><div class="duel-stakes-top"><div><div class="duel-stakes-kicker">'+escapeHtml((s.icon||"⚔️")+" FEUD STAKES // NEXT CLASH")+'</div><h3>'+escapeHtml(s.headline||"NEXT CLASH")+'</h3><div class="duel-stakes-copy">'+escapeHtml(((s.detail||"")+" "+(s.tone||"")).trim())+'</div></div><div class="duel-stakes-tag">'+escapeHtml(s.label||"RIVALRY STAKES")+'</div></div><div class="duel-stakes-grid"><div class="duel-stake-card gold"><b>PRESSURE</b><span>'+escapeHtml(s.pressure||"The record is live.")+'</span></div><div class="duel-stake-card hot"><b>IF YOU WIN · '+Number(win.owner||0)+'-'+Number(win.rival||0)+'</b><span>'+(s.crosses_tier?escapeHtml((next.icon||"🔥")+" UNLOCK "+(next.label||"NEXT TIER")):"Push your side of the rivalry forward.")+'</span></div><div class="duel-stake-card"><b>IF YOU LOSE · '+Number(loss.owner||0)+'-'+Number(loss.rival||0)+'</b><span>'+escapeHtml((s.streak_holder===rival&&Number(s.streak_count||0)>=2)?"The rival streak extends.":"The pressure swings toward your rival.")+'</span></div></div></div>';})()
   +'<div class="duel-chronicle">'
   +'<div class="duel-chron-stat"><b>'+Number(chron.lead_changes||0)+'</b><span>LEAD CHANGES</span></div>'
   +'<div class="duel-chron-stat"><b>'+Number(chron.biggest_lead||0)+'</b><span>BIGGEST LEAD</span></div>'
   +'<div class="duel-chron-stat"><b>'+Number((chron.longest_streaks||{})[ownerName]||0)+'</b><span>YOUR BEST STREAK</span></div>'
   +'<div class="duel-chron-stat"><b>'+Number((chron.longest_streaks||{})[rival]||0)+'</b><span>RIVAL BEST STREAK</span></div>'
   +'</div>'
   +'<div class="feud-pulse"><div class="feud-pulse-top"><b>⚡ FEUD PULSE // LAST '+Math.min(6,pulse.length)+' CLASHES</b><span>'+escapeHtml(rs.holder?((rs.holder===ownerName?"YOU":rs.holder)+" · "+Number(rs.count||0)+" STRAIGHT"):"NO ACTIVE RIVALRY STREAK")+'</span></div>'
   +'<div class="feud-pulse-row">'+(pulse.length?pulse.map(p=>'<a class="feud-chip '+(p.owner_result==="W"?"win":(p.owner_result==="L"?"loss":"neutral"))+'" href="/clash/'+Number(p.battle_id||0)+'">'+escapeHtml(p.owner_result||"—")+'</a>').join(""):'<span style="font-size:8px;color:var(--muted)">No recent direct clashes.</span>')+'</div>'
   +'<div class="feud-last">LAST BLOOD: <b>'+escapeHtml(f.last_winner||"—")+'</b></div></div>'
   +'<div class="duel-actions">'
   +'<a href="/rivalry/'+encodeURIComponent(ownerName)+'/'+encodeURIComponent(rival)+'">🔥 OPEN RIVALRY</a>'
   +'<a href="/rivalry/'+encodeURIComponent(ownerName)+'/'+encodeURIComponent(rival)+'/chronicle.svg">📜 CHRONICLE CARD</a>'
   +'<button class="js-share-nemesis" data-owner="'+escapeHtml(ownerName)+'" data-rival="'+escapeHtml(rival)+'">📣 COPY RIVALRY LINK</button>'
   +'<button class="primary js-featured-target" data-rival="'+escapeHtml(rival)+'">⚔️ RUN IT BACK</button>'
   +'<button class="danger-clear js-clear-nemesis">🧹 CLEAR FEATURED</button>'
   +'</div>'
   +'<div class="nemesis-control-note">Clearing Featured Nemesis changes your pinned profile feud only; rivalry history stays intact.</div>';
}

async function clearFeaturedNemesis(){
 currentUser();
 const d=await jsonFetch("/api/featured-nemesis/"+encodeURIComponent(username),{
   method:"DELETE"
 });
 show(d.message||"Featured Nemesis cleared.");
 if(d.success){
   await Promise.allSettled([
     loadThreatRadar(),
     loadNemesisDuel(),
     loadMissionControl()
   ]);
 }
}

async function featureNemesis(name){
 currentUser();
 const d=await jsonFetch("/api/featured-nemesis/"+encodeURIComponent(username),{
   method:"POST",
   headers:{"Content-Type":"application/json"},
   body:JSON.stringify({rival:name})
 });
 show(d.message||"Featured Nemesis updated.");
 if(d.success){
   await Promise.allSettled([
     loadThreatRadar(),
     loadNemesisDuel(),
     loadMissionControl()
   ]);
 }
}

function targetThreatRival(name){
 const opponent=document.getElementById("battleOpponent");
 if(opponent)opponent.value=name;
 document.getElementById("clashCard")?.scrollIntoView({behavior:motionBehavior(),block:"center"});
 show("😈 Rival target locked: "+name);
}

async function loadThreatRadar(){
 currentUser();
 const d=await jsonFetch("/api/threat-radar/"+encodeURIComponent(username));
 const grid=document.getElementById("threatRadarGrid");
 const meta=document.getElementById("threatRadarMeta");
 if(!grid)return;

 if(!d?.success){
   grid.innerHTML='<div class="threat-empty">'+escapeHtml(d?.message||"Verify your Hunter ID to scan tracked rivals.")+'</div>';
   return;
 }

 const rows=Array.isArray(d.rivals)?d.rivals:[];
 const featured=d.featured_nemesis||"";
 if(meta)meta.textContent=(d.season_key||"—")+" · "+Number(d.count||0)+" tracked rival"+(Number(d.count||0)===1?"":"s")+(featured?(" · 😈 "+featured+" FEATURED"):"");

 if(!rows.length){
   grid.innerHTML='<div class="threat-empty">No tracked rivals yet. Open a Hunter profile and use 🎯 MARK RIVAL to build your radar.</div>';
   return;
 }

 grid.innerHTML=rows.map(r=>{
   const s=r.status||{};
   const m=r.momentum||{};
   const clashes=Number(r.clashes||0);
   const eLevel=clashes>=12?5:clashes>=8?4:clashes>=5?3:clashes>=3?2:clashes>=1?1:0;
   const eLabel=eLevel===5?"🌠 LEGENDARY FEUD":eLevel===4?"🩸 BLOOD FEUD":eLevel===3?"😈 NEMESIS":eLevel===2?"🔥 IGNITED":eLevel===1?"⚔️ FIRST BLOOD":"🎯 DORMANT";
   return '<div class="threat-card threat-'+escapeHtml(s.key||"tracked")+'">'
     +'<div class="threat-avatar">'+escapeHtml(r.avatar||"👾")+'</div>'
     +'<div class="threat-main"><b>'+escapeHtml(r.username)+'</b><span>'+escapeHtml(r.creature||"Hunter")+' · LVL '+Number(r.level||1)+' · '+Number(r.clashes||0)+' direct clashes · '+escapeHtml(eLabel)+'</span></div>'
     +'<div class="threat-side"><div class="threat-status">'+escapeHtml((s.icon||"🎯")+" "+(s.label||"TRACKED RIVAL"))+'</div>'
     +'<div class="threat-record">'+Number(r.your_wins||0)+' — '+Number(r.rival_wins||0)+' H2H</div></div>'
     +'<div class="threat-actions">'
     +'<a href="/rivalry/'+encodeURIComponent(username)+'/'+encodeURIComponent(r.username)+'">⚔️ OPEN RIVALRY</a>'
     +'<a href="/hunter/'+encodeURIComponent(r.username)+'">👾 PROFILE</a>'
     +'<button class="js-feature-nemesis" data-rival="'+escapeHtml(r.username)+'">'+(featured===r.username?'⭐ FEATURED':'⭐ FEATURE NEMESIS')+'</button>'
     +'<button class="danger js-threat-target" data-rival="'+escapeHtml(r.username)+'">😈 TARGET</button>'
     +'<span style="margin-left:auto;font-size:8px;color:var(--muted);align-self:center">'+escapeHtml((m.icon||"⚔️")+" "+(m.label||"BUILDING MOMENTUM"))+' · '+Number(r.rival_streak||0)+' streak</span>'
     +'</div></div>';
 }).join("");
}

async function loadHunterMomentum(){
 currentUser();
 const d=await jsonFetch("/api/momentum/"+encodeURIComponent(username));
 if(!d?.success)return;
 const label=document.getElementById("hudMomentumLabel");
 const detail=document.getElementById("hudMomentumDetail");
 const m=d.momentum||{};
 if(label)label.textContent=(m.icon||"⚔️")+" "+(m.label||"BUILDING MOMENTUM");
 if(detail){
   detail.textContent=Number(d.win_streak||0)+" straight win"+(Number(d.win_streak||0)===1?"":"s")
     +(m.next_at?(" · "+Number(d.wins_to_next||0)+" to next tier"):" · max tracked tier");
 }
}

async function loadMomentumBoard(){
 const d=await jsonFetch("/api/momentum-board");
 const grid=document.getElementById("momentumGrid");
 const meta=document.getElementById("momentumBoardMeta");
 if(!grid||!d?.success)return;
 const rows=Array.isArray(d.hunters)?d.hunters:[];
 if(meta)meta.textContent=(d.season_key||"—")+" · "+rows.length+" active streak"+(rows.length===1?"":"s");
 if(!rows.length){
   grid.innerHTML='<div class="season-empty">No active win streaks yet. One Clash can start the board.</div>';
   return;
 }
 grid.innerHTML=rows.map((h,i)=>{
   const m=h.momentum||{};
   return '<a class="momentum-card" href="/hunter/'+encodeURIComponent(h.username)+'">'
     +'<div class="momentum-top"><div class="momentum-id"><div class="momentum-avatar">'+escapeHtml(h.avatar||"👾")+'</div>'
     +'<div class="momentum-name"><b>#'+(i+1)+' '+escapeHtml(h.username)+'</b><span>'+escapeHtml(h.creature||"Hunter")+' · LVL '+Number(h.level||1)+'</span></div></div>'
     +'<div class="momentum-count">🔥 '+Number(h.win_streak||0)+'</div></div>'
     +'<div class="momentum-status '+escapeHtml(m.key||"building")+'"><b>'+escapeHtml((m.icon||"⚔️")+" "+(m.label||"BUILDING MOMENTUM"))+'</b><span>SEASON STREAK</span></div></a>';
 }).join("");
}

let crownWarTarget=null;
let lastCrownPendingId=0;
let lastCrownEventId=0;
let warAlertTimer=null;

function rememberWarSeen(key,value){
 try{sessionStorage.setItem(key,String(value||0))}catch(e){}
}
function readWarSeen(key){
 try{return Number(sessionStorage.getItem(key)||0)}catch(e){return 0}
}

function dismissWarAlert(){
 const shell=document.getElementById("warAlertShell");
 if(shell)shell.classList.remove("show","defense");
 document.body.classList.remove("war-alarm");
 if(warAlertTimer){clearTimeout(warAlertTimer);warAlertTimer=null}
}

function warAlertAttack(){
 dismissWarAlert();
 attackCurrentCrown();
}

function showWarMini(icon,title,detail){
 const toast=document.getElementById("warMiniToast");
 if(!toast)return;
 document.getElementById("warMiniIcon").textContent=icon||"🚨";
 document.getElementById("warMiniTitle").textContent=title||"Crown War Alert";
 document.getElementById("warMiniDetail").textContent=detail||"";
 toast.classList.add("show");
 setTimeout(()=>toast.classList.remove("show"),5000);
}

function showWarAlert({icon="🚨",kicker="CROWN WAR ALERT",title="CROWN UNDER ATTACK",detail="",defense=false,clashId=null}={}){
 const shell=document.getElementById("warAlertShell");
 if(!shell)return;
 document.getElementById("warAlertIcon").textContent=icon;
 document.getElementById("warAlertKicker").textContent=kicker;
 document.getElementById("warAlertTitle").textContent=title;
 document.getElementById("warAlertDetail").textContent=detail;
 const link=document.getElementById("warAlertClashLink");
 if(link)link.href=clashId?("/clash/"+encodeURIComponent(clashId)):"#crownWar";
 shell.classList.toggle("defense",!!defense);
 shell.classList.add("show");
 document.body.classList.add("war-alarm");
 if(warAlertTimer)clearTimeout(warAlertTimer);
 warAlertTimer=setTimeout(dismissWarAlert,7200);
}

function processCrownWarAlerts(d){
 const pending=Array.isArray(d?.pending)?d.pending:[];
 const recent=Array.isArray(d?.recent_attacks)?d.recent_attacks:[];

 const newestPending=pending.reduce((a,b)=>Number(b.id||0)>Number(a?.id||0)?b:a,null);
 const newestEvent=recent.reduce((a,b)=>Number(b.id||0)>Number(a?.id||0)?b:a,null);

 if(!lastCrownPendingId)lastCrownPendingId=readWarSeen("bl3_last_crown_pending");
 if(!lastCrownEventId)lastCrownEventId=readWarSeen("bl3_last_crown_event");

 if(newestPending&&Number(newestPending.id||0)>lastCrownPendingId){
   lastCrownPendingId=Number(newestPending.id||0);
   rememberWarSeen("bl3_last_crown_pending",lastCrownPendingId);
   const isHolder=username===newestPending.opponent;
   showWarAlert({
     icon:isHolder?"🚨":"⚔️",
     kicker:isHolder?"DEFEND THE CROWN":"CROWN WAR SIGNAL",
     title:isHolder?"YOUR CROWN IS UNDER ATTACK":"NEW CROWN ATTACK",
     detail:newestPending.challenger+" challenged "+newestPending.opponent+" for the Crown.",
     defense:isHolder
   });
   return;
 }

 if(newestEvent&&Number(newestEvent.id||0)>lastCrownEventId){
   lastCrownEventId=Number(newestEvent.id||0);
   rememberWarSeen("bl3_last_crown_event",lastCrownEventId);
   const defended=Number(newestEvent.successful_defense||0)===1;
   const title=defended?"CROWN DEFENDED":"CROWN DEFENSE BROKEN";
   const icon=defended?"🛡️":"💥";
   const detail=defended
     ? newestEvent.defender+" stopped "+newestEvent.challenger+" and held the Crown."
     : newestEvent.challenger+" broke "+newestEvent.defender+"'s Crown defense.";
   showWarMini(icon,title,detail);
   showWarAlert({
     icon,
     kicker:defended?"CROWN WAR RESULT":"CROWN TAKEOVER",
     title,
     detail,
     defense:defended,
     clashId:newestEvent.battle_id
   });
 }
}


function attackCurrentCrown(){
 if(!crownWarTarget){show("No Crown holder yet.");return}
 currentUser();
 if(username===crownWarTarget){show("👑 You hold the Crown. Defend it.");return}
 const opponent=document.getElementById("battleOpponent");
 if(opponent)opponent.value=crownWarTarget;
 document.getElementById("clashCard")?.scrollIntoView({behavior:motionBehavior(),block:"center"});
 show("⚔️ Crown target locked: "+crownWarTarget);
}

async function loadCrownWar(){
 const d=await jsonFetch("/api/crown-war");
 const root=document.getElementById("crownWar");
 if(!root||!d?.success)return;
 if(!readWarSeen("bl3_crown_alert_bootstrapped")){
   const p=Array.isArray(d.pending)?d.pending:[];
   const r=Array.isArray(d.recent_attacks)?d.recent_attacks:[];
   lastCrownPendingId=Math.max(0,...p.map(x=>Number(x.id||0)));
   lastCrownEventId=Math.max(0,...r.map(x=>Number(x.id||0)));
   rememberWarSeen("bl3_last_crown_pending",lastCrownPendingId);
   rememberWarSeen("bl3_last_crown_event",lastCrownEventId);
   rememberWarSeen("bl3_crown_alert_bootstrapped",1);
 }else{
   processCrownWarAlerts(d);
 }

 if(!d.active){
   root.classList.remove("active","stable");
   crownWarTarget=null;
   return;
 }

 root.classList.add("active");
 const pendingVisible=!!d.pending_visible;
 const pendingCount=pendingVisible?Number(d.pending_attacks||0):null;
 root.classList.toggle("stable",pendingVisible&&pendingCount===0);
 root.classList.toggle("private-intel",!pendingVisible);
 crownWarTarget=d.crown?.username||null;

 const status=document.getElementById("crownWarStatus");
 const count=document.getElementById("crownWarCount");
 const avatar=document.getElementById("crownWarAvatar");
 const holder=document.getElementById("crownWarHolder");
 const meta=document.getElementById("crownWarMeta");
 const profile=document.getElementById("crownWarProfile");
 const feed=document.getElementById("crownWarFeed");

 if(status)status.textContent=d.status||"CROWN WAR";
 if(count){
   count.textContent=pendingVisible
     ? (pendingCount+" PENDING ATTACK"+(pendingCount===1?"":"S"))
     : "PRIVATE TO CROWN HOLDER";
 }
 if(avatar)avatar.textContent=d.crown?.avatar||"👑";
 if(holder)holder.textContent=d.crown?.username||"Crown Holder";
 if(meta){
   const base=(d.crown?.creature||"Hunter")+" · LEVEL "+Number(d.crown?.level||1);
   meta.textContent=pendingVisible
     ? base+" · "+(pendingCount?"CROWN UNDER PRESSURE":"NO PENDING ATTACKS")
     : base+" · PENDING ATTACK INTEL IS PRIVATE";
 }
 if(profile&&d.crown?.username)profile.href="/hunter/"+encodeURIComponent(d.crown.username);

 if(feed){
   const rows=[];
   (d.pending||[]).forEach(x=>rows.push(
     '<div class="war-row"><div class="icon">⚔️</div><div><b>'+escapeHtml(x.challenger)+' → '+escapeHtml(x.opponent)+'</b><span>Challenge request #'+Number(x.id||0)+'</span></div><em>PENDING</em></div>'
   ));
   (d.recent_attacks||[]).forEach(x=>{
     const defended=Number(x.successful_defense||0)===1;
     rows.push('<a class="war-row" style="text-decoration:none;color:#fff" href="/clash/'+Number(x.battle_id||0)+'"><div class="icon">'+(defended?'🛡️':'💥')+'</div><div><b>'+escapeHtml(x.challenger)+' vs '+escapeHtml(x.defender)+'</b><span>Winner: '+escapeHtml(x.winner||"—")+'</span></div><em>'+(defended?'DEFENDED':'BROKEN')+'</em></a>');
   });
   feed.innerHTML=rows.slice(0,8).join("")||'<div class="war-empty">Crown is quiet. No attack signals yet.</div>';
 }
}

async function loadSeasonCommandCenter(){
 const d=await jsonFetch("/api/season-command");
 if(!d||!d.success)return;

 const seasonTitle=document.getElementById("seasonCommandTitle");
 const countdown=document.getElementById("seasonCountdown");
 const battles=document.getElementById("seasonCommandBattles");
 const hunters=document.getElementById("seasonCommandHunters");
 const leader=document.getElementById("seasonCommandLeader");
 const crownCard=document.getElementById("seasonCrownCard");
 const top3=document.getElementById("seasonCommandTop3");
 const meta=document.getElementById("seasonCommandMeta");

 if(seasonTitle)seasonTitle.textContent="Crown Race // "+(d.season_key||"—");
 if(countdown)countdown.textContent=d.remaining?.label||"—";
 if(battles)battles.textContent=Number(d.total_battles||0);
 if(hunters)hunters.textContent=Number(d.active_hunters||0);
 if(leader)leader.textContent=d.crown?.username||"—";
 if(meta)meta.textContent=(d.leaders?.length||0)+" leaders tracked";

 if(crownCard){
   if(d.crown){
     crownCard.innerHTML='<div class="crown-icon">👑</div>'
       +'<div class="crown-name"><b>'+escapeHtml(d.crown.username)+'</b><span>'+Number(d.crown.successful_defenses||0)+' successful defenses from '+Number(d.crown.attacks||0)+' Crown attacks</span></div>'
       +'<div class="crown-record"><b>'+Number(d.crown.wins||0)+' WINS</b><span>'+Number(d.crown.losses||0)+' LOSSES</span></div>';
   }else{
     crownCard.innerHTML='<div class="crown-icon">👑</div><div class="crown-name"><b>Waiting for the first Crown</b><span>Win a Clash to start the race.</span></div><div class="crown-record"><b>0 WINS</b><span>NO HOLDER YET</span></div>';
   }
 }

 if(top3){
   const rows=Array.isArray(d.leaders)?d.leaders:[];
   top3.innerHTML=rows.length?rows.map(u=>
     '<a class="season-leader-card" href="/hunter/'+encodeURIComponent(u.username)+'">'
     +'<div class="season-rank">#'+Number(u.rank||0)+'</div>'
     +'<div class="season-leader-main"><b>'+escapeHtml(u.avatar||"👾")+' '+escapeHtml(u.username)+'</b><span>'+escapeHtml(u.creature||"Hunter")+' · '+Number(u.battles||0)+' battles</span></div>'
     +'<div class="season-leader-record"><b>'+Number(u.wins||0)+'W / '+Number(u.losses||0)+'L</b><span>🔥 '+Number(u.win_streak||0)+' STREAK</span></div></a>'
   ).join(""):'<div class="season-empty">No Clash wins this season yet.</div>';
 }
}

let spotlightSlides=[];
let spotlightIndex=0;
let spotlightTimer=null;

function buildSpotlightSlides(data){
 const hunters=Array.isArray(data?.hunters)?data.hunters:[];
 const rivalries=Array.isArray(data?.rivalries)?data.rivalries:[];
 const slides=[];

 hunters.slice(0,2).forEach((h,i)=>slides.push({
   type:"hunter",
   kicker:i===0?"🔥 TRENDING HUNTER":"⚡ RISING HUNTER",
   name:h.username,
   avatar:h.avatar||"👾",
   subtitle:(h.creature||"Hunter")+" · LEVEL "+Number(h.level||1),
   meta:Number(h.activity_count||0)+" 7D ACTIVITY · "+Number(h.wins||0)+" WINS · "+Number(h.battles||0)+" CLASHES",
   stats:[
     [Number(h.wins||0),"WINS"],
     [Number(h.followers||0),"FOLLOWERS"],
     [Number(h.unlocks||0),"UNLOCKS"]
   ],
   primary:"/hunter/"+encodeURIComponent(h.username),
   primaryLabel:"VIEW HUNTER",
   secondary:"/progress/"+encodeURIComponent(h.username),
   secondaryLabel:"PROGRESS"
 }));

 rivalries.slice(0,2).forEach((r,i)=>slides.push({
   type:"rivalry",
   kicker:i===0?"⚔️ FEATURED RIVALRY":"🩸 ACTIVE MATCHUP",
   name:r.hunter_a+" VS "+r.hunter_b,
   avatar:"⚔️",
   subtitle:Number(r.clashes||0)+" RECENT CLASHES",
   meta:Number(r.a_wins||0)+" — "+Number(r.b_wins||0)+" RECENT WINS",
   stats:[
     [Number(r.clashes||0),"CLASHES"],
     [Number(r.a_wins||0),"A WINS"],
     [Number(r.b_wins||0),"B WINS"]
   ],
   primary:"/rivalry/"+encodeURIComponent(r.hunter_a)+"/"+encodeURIComponent(r.hunter_b),
   primaryLabel:"OPEN RIVALRY",
   secondary:"/?challenge="+encodeURIComponent(r.hunter_b)+"&ref="+encodeURIComponent(r.hunter_a),
   secondaryLabel:"CHALLENGE"
 }));

 return slides;
}

function renderSpotlight(){
 const root=document.getElementById("spotlightBody");
 if(!root)return;
 if(!spotlightSlides.length){
   root.innerHTML='<div class="spot-empty">Not enough network heat yet. Start hunting, clashing and unlocking.</div>';
   return;
 }
 const s=spotlightSlides[spotlightIndex%spotlightSlides.length];
 const stats=(s.stats||[]).map(x=>'<div class="spot-stat"><strong>'+escapeHtml(String(x[0]))+'</strong><small>'+escapeHtml(x[1])+'</small></div>').join("");
 root.innerHTML='<div class="spot-body spot-fade">'
   +'<div class="spot-main"><div class="spot-kicker">'+escapeHtml(s.kicker)+'</div>'
   +'<div class="spot-name">'+escapeHtml(s.name)+'</div>'
   +'<div class="spot-meta">'+escapeHtml(s.subtitle)+'<br>'+escapeHtml(s.meta)+'</div>'
   +'<div class="spot-actions"><a class="hot" href="'+s.primary+'">'+escapeHtml(s.primaryLabel)+' →</a>'
   +'<a class="alt" href="'+s.secondary+'">'+escapeHtml(s.secondaryLabel)+'</a></div></div>'
   +'<div class="spot-side"><div class="spot-avatar">'+escapeHtml(s.avatar)+'</div><b>'+escapeHtml(s.type==="hunter"?"HUNTER SPOTLIGHT":"RIVALRY SPOTLIGHT")+'</b>'
   +'<span>'+escapeHtml(s.subtitle)+'</span><div class="spot-stat-row">'+stats+'</div></div></div>';

 const dots=[...document.querySelectorAll("#spotPager .spot-dot")];
 dots.forEach((d,i)=>d.classList.toggle("active",i===spotlightIndex%dots.length));
}

function startSpotlightTimer(){
 if(spotlightTimer)clearInterval(spotlightTimer);
 if(window.matchMedia("(prefers-reduced-motion: reduce)").matches)return;
 spotlightTimer=setInterval(()=>{
   if(document.hidden||!spotlightSlides.length)return;
   spotlightIndex=(spotlightIndex+1)%spotlightSlides.length;
   renderSpotlight();
 },7000);
}
function setSpotlightData(data){
 spotlightSlides=buildSpotlightSlides(data);
 spotlightIndex=0;
 renderSpotlight();
 if(!spotlightTimer)startSpotlightTimer();
}

function paintNetworkHeat(data){
 const hunterGrid=document.getElementById("hunterHeatGrid");
 const rivalryList=document.getElementById("rivalryHeatList");
 if(!hunterGrid||!rivalryList)return;

 const hunters=Array.isArray(data?.hunters)?data.hunters:[];
 if(!hunters.length){
   hunterGrid.innerHTML='<div class="heat-empty">Not enough Hunter activity yet.</div>';
 }else{
   hunterGrid.innerHTML=hunters.map((h,i)=>{
     const tags=[];
     if(Number(h.wins||0))tags.push(Number(h.wins)+" WINS");
     if(Number(h.battles||0))tags.push(Number(h.battles)+" CLASHES");
     if(Number(h.unlocks||0))tags.push(Number(h.unlocks)+" UNLOCKS");
     if(Number(h.proofs||0))tags.push(Number(h.proofs)+" PROOFS");
     return '<a class="heat-hunter" href="/hunter/'+encodeURIComponent(h.username)+'">'
       +'<div class="heat-hunter-head"><div class="heat-id"><div class="heat-avatar">'+escapeHtml(h.avatar||"👾")+'</div>'
       +'<div class="heat-name"><b>#'+(i+1)+' '+escapeHtml(h.username)+'</b><span>'+escapeHtml(h.creature||"Hunter")+' · LVL '+Number(h.level||1)+'</span></div></div>'
       +'<div class="heat-score">⚡ '+Number(h.activity_count||0)+'</div></div>'
       +'<div class="heat-bar"><i style="width:'+Math.max(0,Math.min(100,Number(h.heat_percent||0)))+'%"></i></div>'
       +'<div class="heat-tags">'+tags.slice(0,3).map(t=>'<span class="heat-tag">'+escapeHtml(t)+'</span>').join("")+'</div></a>';
   }).join("");
 }

 const rivalries=Array.isArray(data?.rivalries)?data.rivalries:[];
 if(!rivalries.length){
   rivalryList.innerHTML='<div class="heat-empty">No rivalry heat yet. Start a Clash.</div>';
 }else{
   rivalryList.innerHTML=rivalries.map((r,i)=>{
     const url='/rivalry/'+encodeURIComponent(r.hunter_a)+'/'+encodeURIComponent(r.hunter_b);
     return '<a class="hot-rivalry" href="'+url+'">'
       +'<div class="rivalry-line"><b>🔥 #'+(i+1)+' '+escapeHtml(r.hunter_a)+' <span>VS</span> '+escapeHtml(r.hunter_b)+'</b><span>'+Number(r.clashes||0)+' CLASHES</span></div>'
       +'<div class="heat-bar"><i style="width:'+Math.max(0,Math.min(100,Number(r.heat_percent||0)))+'%"></i></div>'
       +'<div class="rivalry-score">'+Number(r.a_wins||0)+' — '+Number(r.b_wins||0)+' recent wins</div></a>';
   }).join("");
 }
}
async function loadNetworkHeat(){
 const d=await jsonFetch("/api/network-heat");
 if(d&&d.success){
   paintNetworkHeat(d);
   setSpotlightData(d);
 }
}

function pulseRelativeTime(value){
 if(!value)return "NOW";
 const t=new Date(value);if(Number.isNaN(t.getTime()))return "";
 const seconds=Math.max(0,Math.floor((Date.now()-t.getTime())/1000));
 if(seconds<60)return seconds+"s";
 if(seconds<3600)return Math.floor(seconds/60)+"m";
 if(seconds<86400)return Math.floor(seconds/3600)+"h";
 return Math.floor(seconds/86400)+"d";
}
function paintNetworkPulse(events){
 const track=document.getElementById("pulseTrack");
 const count=document.getElementById("pulseCount");
 if(!track)return;
 const items=Array.isArray(events)?events:[];
 if(count)count.textContent=items.length;
 if(!items.length){track.innerHTML='<div class="pulse-empty">Network quiet. Waiting for the next signal…</div>';return}

 const card=e=>'<div class="pulse-item">'
   +'<div class="pulse-icon">'+escapeHtml(e.icon||"⚡")+'</div>'
   +'<div class="pulse-copy"><b>'+escapeHtml(e.title||"Network signal")+' <em class="pulse-kind">'+escapeHtml((e.kind||"signal").toUpperCase())+'</em></b>'
   +'<span>'+escapeHtml(e.detail||"")+'</span></div>'
   +'<div class="pulse-time">'+escapeHtml(pulseRelativeTime(e.created_at))+'</div></div>';

 const html=items.map(card).join("");
 // Duplicate the stream so the CSS marquee can loop without a hard visual stop.
 track.innerHTML=html+html;
}
async function loadNetworkPulse(){
 const d=await jsonFetch("/api/activity?limit=14");
 if(d&&d.success)paintNetworkPulse(d.events||[]);
}

async function loadHunterHUD(){
 currentUser();
 const safeUser=encodeURIComponent(username);
 const [profile,titleData,progressData,unlockData]=await Promise.all([
   jsonFetch("/api/hunter/"+safeUser),
   jsonFetch("/api/title/"+safeUser),
   jsonFetch("/api/progress/"+safeUser),
   jsonFetch("/api/unlocks/"+safeUser+"?limit=1")
 ]);
 if(!profile.success)return;

 const creature=profile.creature||{};
 const title=(titleData&&titleData.current)||{};
 const closest=(progressData&&progressData.closest)||{};
 const unseen=(unlockData&&Number(unlockData.unseen||0))||0;

 const set=(id,value)=>{const el=document.getElementById(id);if(el)el.textContent=value};
 set("hudCreature",creature.avatar||"👾");
 set("hudHunterName",(profile.username||username).toUpperCase());
 set("hudCreatureMeta",(creature.name||"Hunter")+" // "+(creature.stage||"ACTIVE")+" // LEVEL "+Number(profile.level||1));
 set("hudTitle",(title.icon||"🏷️")+" "+(title.title||"HUNTER"));
 set("hudTitleTier",title.tier||"UNRANKED");
 set("hudRep",Number(profile.reputation||0).toLocaleString()+" REP");
 set("hudCombat",Number(profile.wins||0)+" WINS // "+Number(profile.network||0)+" NETWORK");
 set("hudUnlockBadge","✨ "+unseen+" NEW");
 set("hudNextTitle",(closest.icon||"🧭")+" "+(closest.title||"PROGRESSION ACTIVE"));
 set("hudNextPercent",Number(closest.percent||0)+"%");
 set("hudNextDetail",closest.detail||"Keep hunting to unlock the next layer.");
 set("hudIdentityLine",(creature.name||"HUNTER")+" // "+(title.title||"HUNTER"));
 set("hudCombatLine",Number(profile.wins||0)+" WINS // "+Number(profile.rivals||0)+" RIVALS");
 set("hudProgressLine",(closest.kind||"PROGRESS")+" // "+Number(closest.percent||0)+"%");
 const bar=document.getElementById("hudNextBar");if(bar)bar.style.width=Math.max(0,Math.min(100,Number(closest.percent||0)))+"%";

 const profilePath="/hunter/"+safeUser,loadoutPath="/loadout/"+safeUser,progressPath="/progress/"+safeUser;
 const links=[["hudProfileLink",profilePath],["hudLoadoutLink",loadoutPath],["hudProgressLink",progressPath],["commandProgressLink",progressPath]];
 links.forEach(([id,href])=>{const el=document.getElementById(id);if(el)el.href=href});
 await loadHunterMomentum();
}

document.addEventListener("click",(ev)=>{
 const btn=ev.target.closest(".js-revenge-target,.js-threat-target,.js-feature-nemesis,.js-featured-target,.js-share-nemesis,.js-clear-nemesis");
 if(!btn)return;
 const rival=btn.dataset.rival||"";
 if(btn.classList.contains("js-revenge-target"))targetRevengeRival(rival);
 else if(btn.classList.contains("js-threat-target"))targetThreatRival(rival);
 else if(btn.classList.contains("js-feature-nemesis"))featureNemesis(rival);
 else if(btn.classList.contains("js-featured-target"))targetFeaturedNemesis(rival);
 else if(btn.classList.contains("js-share-nemesis"))shareFeaturedNemesis(btn.dataset.owner||username,rival);
 else if(btn.classList.contains("js-clear-nemesis"))clearFeaturedNemesis();
});

document.getElementById("crownWarAttackBtn")?.addEventListener("click",attackCurrentCrown);
document.getElementById("warAlertAttackBtn")?.addEventListener("click",warAlertAttack);
document.getElementById("warAlertDismissBtn")?.addEventListener("click",dismissWarAlert);

async function loadUser(){
 currentUser();
 const data=await jsonFetch("/api/user/"+encodeURIComponent(username));
 update(data);
 const rep=await jsonFetch("/api/reputation/"+encodeURIComponent(username));
 if(rep.success){
   document.getElementById("wins").innerText=rep.wins||0;
   document.getElementById("earned").innerText=Number(rep.earned||0).toLocaleString();
   document.getElementById("reputation").innerText=Number(rep.reputation||0).toLocaleString();
 }
 const passport=await jsonFetch("/api/passport/"+encodeURIComponent(username));
 if(passport.success) updatePassport(passport);
 await loadLeaderboard(); await claimReferral(); await authStatus(); await loadArenas(); await loadSeason(); await loadSeasonCommandCenter(); await loadCrownWar(); await loadDailyMissions(); await loadActivity(); await loadRivalFeed(); await loadDiscovery(); await loadThreatRadar(); await loadRevengeQueue(); await loadMissionControl(); await loadOpsPulse(); await loadSeasonFeudSpotlight(); await loadHallOfFeuds(); await loadFeudEvents(); await loadFeudMoments(); await loadTrendingFeuds(); await loadDiscoveryEngine(); await loadNemesisDuel(); await loadInbox(); await loadSignals(); await loadOnboarding(); await loadNetworkPulse(); await loadNetworkHeat(); await loadHunterHUD();
}
async function refreshLiveSignals(){
 if(document.hidden)return;
 await Promise.allSettled([
   loadNetworkPulse(),
   loadNetworkHeat(),
   loadSeasonCommandCenter(),
   loadCrownWar(),
   loadMomentumBoard()
 ]);
}
const liveSignalTimer=setInterval(refreshLiveSignals,20000);
const feudLiveTimer=setInterval(()=>refreshFeudLive(false),12000);
document.addEventListener("visibilitychange",()=>{
 if(!document.hidden){
   refreshLiveSignals();
   refreshFeudLive(false);
 }
});
refreshLiveSignals();
refreshFeudLive(true);
startSpotlightTimer();

function update(data){
 if(data.wallet!==undefined)document.getElementById("wallet").value=data.wallet||"";
 if(data.xp!==undefined)document.getElementById("xp").innerText=data.xp;
 if(data.rank!==undefined)document.getElementById("rank").innerText=data.rank;
 if(data.streak!==undefined){
  const s=Number(data.streak),c=Array.isArray(data.claimed_milestones)?data.claimed_milestones.map(Number):[];
  document.getElementById("streak").innerText=s;
  const r=document.getElementById("streakReward"),b=document.getElementById("streakClaimButton");b.classList.add("hidden");
  if(s>=3&&!c.includes(3)){r.innerText="🔥 3-Day Flame — UNLOCKED";b.classList.remove("hidden")}
  else if(s>=7&&!c.includes(7)){r.innerText="🏆 7-Day House — UNLOCKED";b.classList.remove("hidden")}
  else if(s>=30&&!c.includes(30)){r.innerText="🌕 30-Day Moon — UNLOCKED";b.classList.remove("hidden")}
  else if(s<3)r.innerText="🔥 Next: 3-Day Flame • "+(3-s)+" days left";
  else if(s<7)r.innerText="🏆 Next: 7-Day House • "+(7-s)+" days left";
  else if(s<30)r.innerText="🌕 Next: 30-Day Moon • "+(30-s)+" days left";
  else r.innerText="👑 All streak rewards claimed!";
 }
}
function updatePassport(p){
 const network=Number(p.network||0);
 document.getElementById("network").innerText=network;
 document.getElementById("empireLabel").innerText=network+" HUNTER"+(network===1?"":"S");
 document.getElementById("creatureAvatar").innerText=p.creature.avatar;
 document.getElementById("creatureStage").innerText=p.creature.stage;
 document.getElementById("creatureName").innerText=p.creature.name;
 document.getElementById("creatureLevel").innerText="LEVEL "+p.level;
 document.getElementById("evolutionText").innerText=p.evolution.current+" / "+p.evolution.target+" XP";
 document.getElementById("evolutionBar").style.width=Math.max(0,Math.min(100,p.evolution.percent))+"%";
}
async function quest(name){currentUser();const d=await jsonFetch("/api/quest",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({user:username,quest:name})});if(d.xp!==undefined)update(d);show(d.message||"Quest finished");loadLeaderboard();if(d.success)loadDailyMissions()}
function share(){window.open("https://warpcast.com/~/compose?text="+encodeURIComponent("BL3 — Hunt alpha. Prove it. 👑 https://bl3meme.com"),"_blank");show("Post your cast, paste its URL, then verify.")}
async function verifyShare(){currentUser();const cast_url=document.getElementById("castUrl").value.trim();const d=await jsonFetch("/api/share/verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({user:username,cast_url})});if(d.xp!==undefined)update(d);show(d.message||"Verification finished");if(d.success){loadLeaderboard();loadDailyMissions()}}
function invite(){const link=location.origin+"/?ref="+encodeURIComponent(currentUser());if(navigator.clipboard)navigator.clipboard.writeText(link);show("Invite link: "+link)}
async function claimReferral(){const p=new URLSearchParams(location.search),inviter=(p.get("ref")||"").trim(),invited=currentUser();if(!inviter)return;if(!invited||invited==="demo_user"){show("Referral detected. Enter your username.");return}if(inviter===invited){show("You cannot refer yourself.");return}const d=await jsonFetch("/api/referral",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({inviter,invited})});show(d.message||"Referral checked");if(d.success){history.replaceState({},"",location.pathname);loadLeaderboard()}}
async function loadSeason(){
 currentUser();
 const d=await jsonFetch("/api/season/"+encodeURIComponent(username));
 if(!d.success)return;
 document.getElementById("seasonKey").innerText=d.season_label||d.season_key||"—";
 document.getElementById("seasonRecord").innerText=(d.user.wins||0)+"-"+(d.user.losses||0);
 document.getElementById("seasonStreak").innerText=d.user.win_streak||0;
 document.getElementById("seasonRank").innerText=d.user.rank?"#"+d.user.rank:"—";
 currentCrown=d.crown?d.crown.username:null;
 document.getElementById("crownHolder").innerText=d.crown?"👑 "+d.crown.username+" • "+d.crown.wins+" wins":"👑 Waiting for the first win";
 const cb=document.getElementById("crownChallengeButton");
 if(currentCrown&&currentCrown!==username){cb.classList.remove("hidden");cb.innerText="⚔️ CHALLENGE "+currentCrown.toUpperCase()}else{cb.classList.add("hidden")}
 const ds=await jsonFetch("/api/crown/defense/"+encodeURIComponent(username));
 if(ds.success)document.getElementById("crownDefenseStats").innerText="👑 Crown attacks: "+ds.attacks+" • successful defenses: "+ds.successful_defenses;
 let h="";
 (d.leaderboard||[]).slice(0,5).forEach((u,i)=>h+='<div class="leader"><span>#'+(i+1)+' '+escapeHtml(u.username)+'</span><b>'+u.wins+'W / '+u.losses+'L</b></div>');
 document.getElementById("seasonLeaders").innerHTML=h||'<div class="meta">No Clash wins this season yet.</div>';
}
function challengeCrown(){
 if(!currentCrown){show("No Crown holder yet. Win a Clash and start the race.");return}
 if(currentCrown===currentUser()){show("You hold the Crown 👑 Wait for hunters to challenge you.");return}
 const el=document.getElementById("battleOpponent");el.value=currentCrown;el.scrollIntoView({behavior:motionBehavior(),block:"center"});show("👑 Crown target locked: "+currentCrown);
}
async function loadDailyMissions(){
 currentUser();
 const d=await jsonFetch("/api/daily/"+encodeURIComponent(username));
 if(!d.success)return;
 document.getElementById("dailyProgress").innerText=d.completed+" / "+d.total+(d.completed===d.total?" • SWEEP ✓":"");
 let h="";
 (d.missions||[]).forEach(m=>{h+='<div class="mission"><span>'+escapeHtml(m.icon)+" "+escapeHtml(m.label)+'</span><span class="'+(m.complete?'mission-ok':'mission-wait')+'">'+(m.complete?'DONE ✓':'OPEN')+'</span></div>'});
 document.getElementById("dailyMissions").innerHTML=h||'<div class="meta">No missions loaded.</div>';
}

function closeClashReplay(){
 const shell=document.getElementById("clashReplayShell");
 if(shell)shell.classList.remove("show");
}

function openClashReplay(d){
 if(!d?.success)return;
 const mine=d.challenger||{};
 const them=d.opponent||{};
 const shell=document.getElementById("clashReplayShell");
 if(!shell)return;

 const mineName=username;
 const themName=them.opponent||"Opponent";
 const mineWon=d.winner===mineName;

 const combo=d.combo||{key:"standard",icon:"⚔️",label:"CLASH WIN",tier:0};
 const winnerStreak=Number(d.winner_streak||0);
 const replayCard=document.getElementById("clashReplayCard");
 const comboEl=document.getElementById("replayCombo");
 const burst=document.getElementById("comboBurst");
 ["hot","dominating","unstoppable","mythic"].forEach(k=>{
   if(replayCard)replayCard.classList.remove("combo-"+k);
   if(comboEl)comboEl.classList.remove(k);
   if(burst)burst.classList.remove(k);
 });
 if(comboEl)comboEl.classList.toggle("show",Number(combo.tier||0)>0);
 if(Number(combo.tier||0)>0){
   if(replayCard)replayCard.classList.add("combo-"+combo.key);
   if(comboEl)comboEl.classList.add(combo.key);
   if(burst){burst.classList.add("show",combo.key);setTimeout(()=>burst.classList.remove("show"),1300)}
   const comboToast=document.getElementById("comboToast");
   if(comboToast){
     document.getElementById("comboToastTitle").textContent=(combo.icon||"🔥")+" "+(combo.label||"HOT STREAK");
     document.getElementById("comboToastMeta").textContent=winnerStreak+" STRAIGHT SEASON WINS";
     comboToast.classList.add("show");
     setTimeout(()=>comboToast.classList.remove("show"),4200);
   }
 }

 const set=(id,value)=>{const el=document.getElementById(id);if(el)el.textContent=value};
 set("replayComboIcon",combo.icon||"🔥");
 set("replayComboLabel",combo.label||"HOT STREAK");
 set("replayComboCount",winnerStreak+" WINS");
 set("replayTopMeta","ALPHA CLASH // "+(d.crown_attack?"CROWN WAR":"STANDARD ARENA"));
 set("replayChallengerAvatar",mine.avatar||"👾");
 set("replayChallengerName",mineName);
 set("replayChallengerPower",Number(mine.power||0));
 set("replayOpponentAvatar",them.avatar||"👾");
 set("replayOpponentName",themName);
 set("replayOpponentPower",Number(them.power||0));
 set("replayBattleNo","CLASH #"+Number(d.battle_id||0));
 set("replayWinner",(d.winner||"—").toUpperCase());
 set("replayCommentary",d.commentary||"The clash resolved.");
 set("replayPowerGap",Math.abs(Number(mine.power||0)-Number(them.power||0)));
 set("replayPersonalResult",mineWon?"VICTORY":"DEFEAT");
 set("replayOutcomeLabel",d.crown_attack?(mineWon?"CROWN WAR VICTORY":"CROWN WAR RESULT"):"WINNER");

 const left=document.getElementById("replayChallenger");
 const right=document.getElementById("replayOpponent");
 if(left){left.classList.toggle("winner",d.winner===mineName);left.classList.toggle("loser",d.winner!==mineName)}
 if(right){right.classList.toggle("winner",d.winner===themName);right.classList.toggle("loser",d.winner!==themName)}

 const card=document.getElementById("replayOpenCard");
 if(card)card.href="/clash/"+Number(d.battle_id||0);

 shell.classList.remove("show");
 void shell.offsetWidth;
 shell.classList.add("show");
}

async function battleHunter(){
 currentUser();
 const opponent=document.getElementById("battleOpponent").value.trim();
 if(!opponent){show("Enter an opponent username.");return}
 if(opponent===username){show("Your creature refuses to fight itself 😈");return}
 const d=await jsonFetch("/api/battle",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({challenger:username,opponent})});
 if(!d.success){show(d.message||"Clash failed");return}
 const mine=d.challenger,them=d.opponent,won=d.winner===username;
 const challengeLink=location.origin+"/?challenge="+encodeURIComponent(username)+"&ref="+encodeURIComponent(username)+"&from_battle="+d.battle_id;
 const battleCard=location.origin+"/clash/"+d.battle_id;
 lastBattleShare={
   text:"⚔️ BL3 ALPHA CLASH #"+d.battle_id+"\n"+mine.avatar+" "+username+" "+mine.power+" — "+them.power+" "+them.opponent+" "+them.avatar+"\n👑 Winner: "+d.winner+"\n"+d.commentary+"\n\nOpen the battle card + challenge me 👇",
   link:battleCard, challenge:challengeLink, card:battleCard
 };
 const el=document.getElementById("battleResult");
 el.classList.remove("hidden");
 el.innerHTML='<div class="small">'+(won?'👑 VICTORY':'💀 DEFEAT')+'</div><div class="battle-vs">'+escapeHtml(mine.avatar)+' '+escapeHtml(username)+' <span class="meta">VS</span> '+escapeHtml(them.opponent)+' '+escapeHtml(them.avatar)+'</div><div class="battle-log">POWER '+mine.power+' — '+them.power+'<br>'+escapeHtml(d.commentary)+'</div><a href="/clash/'+d.battle_id+'" target="_blank" style="display:block;text-decoration:none;color:inherit;margin-top:10px"><div class="proof">🃏 BATTLE CARD #'+d.battle_id+' • OPEN PUBLIC RESULT ↗</div></a><div class="battle-actions"><button class="btn hot" onclick="shareBattle()">📣 SHARE CARD</button><button class="btn" onclick="copyChallengeLink()">🔗 COPY CHALLENGE</button></div>';
 openClashReplay(d);
 if(d.feud_event)showFeudEventBurst(d.feud_event);
 if(d.feud_moment)showFeudMomentBurst(d.feud_moment);
 show(won?"Your creature took the crown 👑":"Chaos chose your opponent this round.");
 await loadSeason();
 await refreshFeudLive(true);
 await loadUser();
}
function shareBattle(){
 if(!lastBattleShare){show("Finish a clash first.");return}
 const body=lastBattleShare.text+"\n"+lastBattleShare.link;
 window.open("https://warpcast.com/~/compose?text="+encodeURIComponent(body),"_blank");
 show("Clash card ready to cast. 👑");
}
function copyChallengeLink(){
 if(!lastBattleShare){show("Finish a clash first.");return}
 if(navigator.clipboard)navigator.clipboard.writeText(lastBattleShare.challenge);
 show("Challenge link copied: "+lastBattleShare.challenge);
}
function hydrateChallenge(){
 const p=new URLSearchParams(location.search),target=(p.get("challenge")||"").trim();
 if(!target)return;
 const el=document.getElementById("battleOpponent");
 if(el)el.value=target;
 const moment=(p.get("moment")||"").trim();
 const source=(p.get("source")||"").trim();
 const suffix=(source==="feud-moment"&&moment)?(" · from Feud Moment #"+moment):(source.startsWith("discovery-v13")?" · from Discovery Engine":"");
 show("⚔️ Challenge detected: "+target+" is waiting in the arena"+suffix+".");
}

async function connectWallet(){if(!window.ethereum){show("No browser wallet detected.");return}try{const a=await ethereum.request({method:"eth_requestAccounts"});if(!a.length)return;document.getElementById("wallet").value=a[0];show("Wallet connected. Now sign the message.")}catch(e){show("Wallet connection cancelled.")}}
async function signInWallet(){if(!window.ethereum){show("No browser wallet detected.");return}try{currentUser();if(username==="demo_user"){show("Enter your BL3 username first.");return}const a=await ethereum.request({method:"eth_requestAccounts"}),wallet=a[0];const n=await jsonFetch("/api/auth/nonce?wallet="+encodeURIComponent(wallet)+"&user="+encodeURIComponent(username));if(!n.success){show(n.message);return}const signature=await ethereum.request({method:"personal_sign",params:[n.message,wallet]});const d=await jsonFetch("/api/auth/verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({wallet,username,message:n.message,signature})});show(d.message||"Sign-in finished");if(d.success){document.getElementById("authStatus").innerText="Verified: "+wallet.slice(0,6)+"…"+wallet.slice(-4);document.getElementById("navAuth").innerText="WALLET VERIFIED";await loadUser()}}catch(e){show("Wallet sign-in cancelled or failed.")}}
async function authStatus(){const d=await jsonFetch("/api/auth/status");if(d.authenticated){document.getElementById("authStatus").innerText="Verified: "+d.wallet.slice(0,6)+"…"+d.wallet.slice(-4);document.getElementById("navAuth").innerText="WALLET VERIFIED"}}
async function loadLeaderboard(){const d=await jsonFetch("/api/leaderboard");let h="";(Array.isArray(d)?d:[]).slice(0,10).forEach((u,i)=>h+='<div class="leader"><span>#'+(i+1)+' '+escapeHtml(u.username)+'</span><b>'+u.xp+' XP</b></div>');document.getElementById("leaderboard").innerHTML=h||'<div class="meta">No hunters yet.</div>';document.getElementById("totalHunters").innerText=Array.isArray(d)?d.length:0}
async function claimStreakReward(){currentUser();const s=Number(document.getElementById("streak").innerText),p=await jsonFetch("/api/user/"+encodeURIComponent(username)),c=Array.isArray(p.claimed_milestones)?p.claimed_milestones.map(Number):[];let m=0;if(s>=3&&!c.includes(3))m=3;else if(s>=7&&!c.includes(7))m=7;else if(s>=30&&!c.includes(30))m=30;if(!m){show("No streak reward available yet.");return}const d=await jsonFetch("/api/streak/claim",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({user:username,milestone:m})});show(d.message||"Claim finished");if(d.success)await loadUser()}
function escapeHtml(v){return String(v??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]))}
function relativeTime(iso){
 if(!iso)return "now";
 const t=Date.parse(String(iso).endsWith("Z")?iso:iso+"Z");
 if(Number.isNaN(t))return "";
 const s=Math.max(0,Math.floor((Date.now()-t)/1000));
 if(s<60)return s+"s";
 const m=Math.floor(s/60); if(m<60)return m+"m";
 const h=Math.floor(m/60); if(h<24)return h+"h";
 return Math.floor(h/24)+"d";
}
async function sendChallengeRequest(){
 currentUser();
 const opponent=document.getElementById("battleOpponent").value.trim();
 if(!opponent){show("Enter an opponent username first.");return}
 if(opponent===username){show("You cannot challenge yourself.");return}
 const d=await jsonFetch("/api/challenges",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({challenger:username,opponent})});
 show(d.message||"Challenge request finished");
 if(d.success)await loadInbox();
}
async function loadInbox(){
 currentUser();
 const el=document.getElementById("challengeInbox"),badge=document.getElementById("inboxBadge");
 const d=await jsonFetch("/api/challenges/"+encodeURIComponent(username));
 if(!d.success){
   if(badge)badge.innerText="INBOX —";
   el.innerHTML='<div class="meta">'+escapeHtml(d.message||"Sign in with this Hunter ID to open the inbox.")+'</div>';
   return;
 }
 const items=Array.isArray(d.incoming)?d.incoming:[];
 if(badge)badge.innerText="INBOX "+items.length;
 el.innerHTML=items.map(c=>'<div class="inbox-item"><div class="inbox-top"><div><div class="inbox-title">⚔️ '+escapeHtml(c.challenger)+' challenged you</div><div class="meta">'+escapeHtml(relativeTime(c.created_at))+' ago · Request #'+c.id+'</div></div><div class="inbox-badge">PENDING</div></div><div class="inbox-actions"><button class="btn hot" onclick="acceptChallenge('+c.id+')">ACCEPT ⚔️</button><button class="btn danger" onclick="declineChallenge('+c.id+')">DECLINE</button></div></div>').join("")||'<div class="meta">Inbox clear. Share a Battle Card and pull someone into the arena.</div>';
}
async function acceptChallenge(id){
 const d=await jsonFetch("/api/challenges/"+id+"/accept",{method:"POST"});
 if(!d.success){show(d.message||"Could not accept challenge");return}
 show("⚔️ Challenge accepted — Clash #"+d.battle_id+" resolved.");
 openClashReplay(d);
 const mine=d.challenger,them=d.opponent;
 const el=document.getElementById("battleResult");
 el.classList.remove("hidden");
 el.innerHTML='<div class="small">CHALLENGE ACCEPTED // 👑 '+escapeHtml(d.winner)+' WON</div><div class="battle-vs">'+escapeHtml(mine.avatar)+' '+escapeHtml(mine.username)+' <span class="meta">VS</span> '+escapeHtml(them.opponent)+' '+escapeHtml(them.avatar)+'</div><div class="battle-log">POWER '+mine.power+' — '+them.power+'<br>'+escapeHtml(d.commentary)+'</div><a href="/clash/'+d.battle_id+'" target="_blank" style="display:block;text-decoration:none;color:inherit;margin-top:10px"><div class="proof">🃏 OPEN BATTLE CARD #'+d.battle_id+' ↗</div></a>';
 await loadInbox(); await loadSeason(); await loadActivity(); await refreshFeudLive(true); await loadUser();
}
async function declineChallenge(id){
 const d=await jsonFetch("/api/challenges/"+id+"/decline",{method:"POST"});
 show(d.message||"Challenge declined");
 if(d.success)await loadInbox();
}

async function loadSignals(){
 currentUser();
 const el=document.getElementById("signalCenter"),badge=document.getElementById("signalBadge");
 const d=await jsonFetch("/api/notifications/"+encodeURIComponent(username));
 if(!d.success){
   if(badge)badge.innerText="SIGNALS —";
   el.innerHTML='<div class="meta">'+escapeHtml(d.message||"Sign in with this Hunter ID to open private signals.")+'</div>';
   return;
 }
 const items=Array.isArray(d.notifications)?d.notifications:[];
 if(badge)badge.innerText="SIGNALS "+Number(d.unread||0);
 el.innerHTML=items.map(n=>'<div class="signal-item '+(n.is_read?'':'unread')+'"><div class="signal-top"><div><div class="signal-title">'+escapeHtml(n.title||"BL3 signal")+'</div><div class="meta">'+escapeHtml(n.detail||"")+'</div></div><div class="feed-time">'+escapeHtml(relativeTime(n.created_at))+'</div></div>'+(n.link?'<a class="signal-link" href="'+escapeHtml(n.link)+'">OPEN SIGNAL ↗</a>':'')+'</div>').join("")||'<div class="meta">No private signals yet. Go make noise. ⚡</div>';
}
async function markSignalsRead(){
 currentUser();
 const d=await jsonFetch("/api/notifications/"+encodeURIComponent(username)+"/read-all",{method:"POST"});
 show(d.message||"Signals updated");
 if(d.success)await loadSignals();
}

async function loadActivity(){
 const d=await jsonFetch("/api/activity?limit=18");
 const el=document.getElementById("activityFeed");
 if(!d.success){el.innerHTML='<div class="meta">Network signal unavailable.</div>';return}
 const items=Array.isArray(d.events)?d.events:[];
 el.innerHTML=items.map(e=>'<div class="feed-item"><div class="feed-icon">'+escapeHtml(e.icon||"⚡")+'</div><div class="feed-main"><div class="feed-title">'+escapeHtml(e.title||"Network activity")+'</div><div class="feed-meta">'+escapeHtml(e.detail||"")+'</div></div><div class="feed-time">'+escapeHtml(relativeTime(e.created_at))+'</div></div>').join("")||'<div class="meta">No activity yet. Be the first signal.</div>';
}
async function loadRivalFeed(){
 currentUser();
 const el=document.getElementById("rivalFeed");
 if(!el)return;
 const d=await jsonFetch("/api/rivals/"+encodeURIComponent(username)+"/activity?limit=16");
 if(!d.success){el.innerHTML='<div class="meta">'+escapeHtml(d.message||"Sign in with this Hunter ID to watch Rivals.")+'</div>';return}
 const items=Array.isArray(d.events)?d.events:[];
 const rivals=Array.isArray(d.rivals)?d.rivals:[];
 if(!rivals.length){el.innerHTML='<div class="meta">No Rivals yet. Open a public Hunter profile and tap 🎯 MARK RIVAL.</div>';return}
 el.innerHTML=items.map(e=>'<div class="feed-item"><div class="feed-icon">'+escapeHtml(e.icon||"🎯")+'</div><div class="feed-main"><div class="feed-title">'+escapeHtml(e.title||"Rival activity")+'</div><div class="feed-meta">'+escapeHtml(e.detail||"")+'</div></div><div class="feed-time">'+escapeHtml(relativeTime(e.created_at))+'</div></div>').join("")||'<div class="meta">Your Rivals are quiet right now. 👀</div>';
}
function openRivalDirectory(){currentUser();window.open("/rivals/"+encodeURIComponent(username),"_blank","noopener")}

async function loadDiscovery(){
 currentUser();
 const el=document.getElementById("hunterDiscovery");
 if(!el)return;
 const d=await jsonFetch("/api/discovery/"+encodeURIComponent(username)+"?limit=6");
 if(!d.success){el.innerHTML='<div class="meta">'+escapeHtml(d.message||"Sign in to discover Hunters.")+'</div>';return}
 const items=Array.isArray(d.hunters)?d.hunters:[];
 if(!items.length){el.innerHTML='<div class="meta">No new Hunter suggestions yet. Invite someone into the network. 👥</div>';return}
 el.innerHTML=items.map(h=>{
   const rival=h.is_rival?'🎯 RIVAL ✓':'🎯 RIVAL';
   const follow=h.is_following?'✓ FOLLOWING':'👁️ FOLLOW';
   const u=escapeHtml(h.username);
   return '<div class="feed-item" style="align-items:flex-start">'+
     '<div class="feed-icon">'+escapeHtml(h.avatar||"👾")+'</div>'+
     '<div class="feed-main"><div class="feed-title">'+u+
     ' <span class="small">LVL '+Number(h.level||1)+'</span></div>'+
     '<div class="feed-meta">'+Number(h.xp||0)+' XP • '+Number(h.reputation||0)+' REP • '+Number(h.wins||0)+' wins • '+Number(h.followers||0)+' followers</div>'+
     '<div class="battle-actions">'+
       '<button class="btn tab" data-user="'+u+'" data-kind="follow">'+follow+'</button>'+
       '<button class="btn tab" data-user="'+u+'" data-kind="rival">'+rival+'</button>'+
       '<button class="btn tab violet" data-profile="'+u+'">PROFILE ↗</button>'+
     '</div></div>'+
     '<div class="feed-time">MATCH '+Number(h.match_score||0)+'</div></div>';
 }).join("");
 el.querySelectorAll("[data-kind]").forEach(btn=>btn.addEventListener("click",()=>{
   const target=btn.dataset.user,kind=btn.dataset.kind;
   const h=items.find(x=>x.username===target);
   const enabled=kind==="follow"?!h.is_following:!h.is_rival;
   discoverySocial(target,kind,enabled);
 }));
 el.querySelectorAll("[data-profile]").forEach(btn=>btn.addEventListener("click",()=>{
   window.open("/hunter/"+encodeURIComponent(btn.dataset.profile),"_blank","noopener");
 }));
}
async function discoverySocial(target,kind,enabled){
 const d=await jsonFetch("/api/hunter/"+encodeURIComponent(target)+"/social",{
   method:"POST",headers:{"Content-Type":"application/json"},
   body:JSON.stringify({kind:kind,enabled:enabled})
 });
 show(d.message||"Social graph updated");
 if(d.success){await loadDiscovery();await loadRivalFeed();}
}
setInterval(()=>{loadActivity();loadRivalFeed();loadSignals();},20000);

async function loadArenas(){
 const d=await jsonFetch("/api/arenas"),list=Array.isArray(d.arenas)?d.arenas:[];
 document.getElementById("liveArenas").innerText=list.filter(a=>a.status==="live").length;
 document.getElementById("totalBounty").innerText=list.reduce((n,a)=>n+Number(a.bounty_amount||0),0).toLocaleString();
 let h="";
 list.forEach(a=>{
   const winner=a.winner_username?'<div class="proof">👑 WINNER: <b>'+escapeHtml(a.winner_username)+'</b> • '+(a.paid?'PAID ✅':'PAYMENT PENDING')+'</div>':'';
   const creatorControls=(currentUser()===a.creator)?'<button class="btn" onclick="reviewSubmissions('+a.id+')">REVIEW PROOFS</button><div id="reviews-'+a.id+'" class="hidden"></div>':'';
   h+='<article class="card arena"><div class="live">● '+escapeHtml(a.status).toUpperCase()+' // '+escapeHtml(a.category)+'</div><h2>'+escapeHtml(a.title)+'</h2><div class="bounty">'+Number(a.bounty_amount||0).toLocaleString()+' '+escapeHtml(a.bounty_asset)+'</div><div class="meta">'+escapeHtml(a.description)+'</div><div class="meta" style="margin-top:10px">By '+escapeHtml(a.creator)+' • '+a.submissions+' proofs • Deadline '+escapeHtml(a.deadline||"open")+'</div>'+winner+(a.status==="live"?'<button class="btn hot enter-arena" data-arena="'+a.id+'">ENTER ARENA →</button><div id="submit-'+a.id+'" class="hidden"><textarea id="pitch-'+a.id+'" placeholder="Your thesis / proof / contribution"></textarea><input id="proof-'+a.id+'" placeholder="Proof URL (optional)"><button class="btn violet" onclick="submitProof('+a.id+')">SUBMIT PROOF</button></div>':'')+creatorControls+'</article>';
 });
 document.getElementById("arenas").innerHTML=h||'<div class="card"><h2>The first arena is waiting.</h2><div class="meta">Verified project creators can launch the first hunt from the Project Desk.</div></div>';
 document.querySelectorAll(".enter-arena").forEach(btn=>btn.addEventListener("click",()=>openSubmission(Number(btn.dataset.arena),"Arena")));
}
function openSubmission(id,title){document.getElementById("submit-"+id).classList.toggle("hidden");show("Entering: "+title)}
async function submitProof(id){currentUser();const pitch=document.getElementById("pitch-"+id).value.trim(),proof_url=document.getElementById("proof-"+id).value.trim();const d=await jsonFetch("/api/arenas/"+id+"/submit",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({user:username,pitch,proof_url})});show(d.message||"Submission finished");if(d.success){await loadArenas();await loadUser()}}

async function reviewSubmissions(id){
 currentUser();
 const d=await jsonFetch("/api/arenas/"+id+"/submissions");
 if(!d.success){show(d.message||"Could not load proofs");return}
 let h="";
 (d.submissions||[]).forEach(s=>{
   h+='<div class="proof"><b>'+escapeHtml(s.username)+'</b><div class="meta">'+escapeHtml(s.pitch)+'</div>'+
      (s.proof_url?'<div class="meta">'+escapeHtml(s.proof_url)+'</div>':'')+
      (d.arena.status==="live"?'<button class="btn hot select-winner" data-arena="'+id+'" data-winner="'+escapeHtml(s.username)+'">SELECT WINNER 👑</button>':'')+
      '</div>';
 });
 if(d.arena.winner_username&&!d.arena.paid){
   h+='<button class="btn violet mark-paid" data-arena="'+id+'">MARK WINNER PAID ✓</button>';
 }
 const el=document.getElementById("reviews-"+id);el.innerHTML=h||'<div class="meta">No proofs yet.</div>';el.classList.remove("hidden");
 el.querySelectorAll(".select-winner").forEach(btn=>btn.addEventListener("click",()=>selectWinner(Number(btn.dataset.arena),btn.dataset.winner)));
 el.querySelectorAll(".mark-paid").forEach(btn=>btn.addEventListener("click",()=>markPaid(Number(btn.dataset.arena))));
}
async function selectWinner(id,winner){
 const d=await jsonFetch("/api/arenas/"+id+"/winner",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({creator:currentUser(),winner})});
 show(d.message||"Winner selection finished");if(d.success){await loadArenas();await loadUser()}
}
async function markPaid(id){
 const d=await jsonFetch("/api/arenas/"+id+"/paid",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({creator:currentUser()})});
 show(d.message||"Payment status updated");if(d.success){await loadArenas();await loadUser()}
}
async function createArena(){currentUser();const body={creator:username,title:document.getElementById("arenaTitle").value.trim(),description:document.getElementById("arenaDescription").value.trim(),category:document.getElementById("arenaCategory").value,bounty_amount:document.getElementById("arenaBounty").value,deadline:document.getElementById("arenaDeadline").value.trim()};const d=await jsonFetch("/api/arenas",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});show(d.message||"Arena request finished");if(d.success)loadArenas()}
let commandPaletteItems=[];
let commandPaletteIndex=0;
let commandPaletteTimer=null;

function openCommandPalette(){
 const shell=document.getElementById("commandPaletteShell"),input=document.getElementById("commandPaletteInput");
 if(!shell||!input)return;
 shell.classList.add("show");document.body.style.overflow="hidden";
 input.value="";commandPaletteIndex=0;
 setTimeout(()=>input.focus(),20);
 runGlobalSearch("");
}
function closeCommandPalette(){
 const shell=document.getElementById("commandPaletteShell");if(!shell)return;
 shell.classList.remove("show");document.body.style.overflow="";
}
function commandPaletteBackdrop(e){if(e.target?.id==="commandPaletteShell")closeCommandPalette()}
function commandTypeIcon(type){return ({hunter:"👾",rivalry:"⚔️",clash:"💥",arena:"🎯",moment:"🎬",command:"⌘"})[type]||"🔎"}
function renderCommandResults(items){
 const root=document.getElementById("commandResults"),status=document.getElementById("commandPaletteStatus");if(!root)return;
 commandPaletteItems=Array.isArray(items)?items:[];commandPaletteIndex=Math.min(commandPaletteIndex,Math.max(0,commandPaletteItems.length-1));
 if(status)status.textContent=commandPaletteItems.length?commandPaletteItems.length+" RESULTS // GLOBAL INDEX":"GLOBAL SEARCH // NO MATCH";
 if(!commandPaletteItems.length){root.innerHTML='<div class="command-empty">No match yet. Try a Hunter name, Clash number, feud, or command.</div>';return}
 root.innerHTML=commandPaletteItems.map((item,i)=>'<button class="command-result '+(i===commandPaletteIndex?'active':'')+'" type="button" data-command-index="'+i+'"><span class="command-result-icon">'+escapeHtml(item.icon||commandTypeIcon(item.type))+'</span><span class="command-result-copy"><b>'+escapeHtml(item.title||"Result")+'</b><span>'+escapeHtml(item.subtitle||"")+'</span></span><span class="command-result-type">'+escapeHtml((item.type||"result").toUpperCase())+'</span></button>').join("");
 root.querySelectorAll("[data-command-index]").forEach(btn=>btn.addEventListener("click",()=>activateCommandResult(Number(btn.dataset.commandIndex))));
 const active=root.querySelector(".command-result.active");if(active)active.scrollIntoView({block:"nearest"});
}
async function runGlobalSearch(query){
 const status=document.getElementById("commandPaletteStatus");if(status)status.textContent="SEARCHING BL3…";
 const d=await jsonFetch("/api/global-search?q="+encodeURIComponent(query||""));
 if(!d?.success){renderCommandResults([]);if(status)status.textContent="SEARCH UNAVAILABLE";return}
 renderCommandResults(d.results||[]);
}
function activateCommandResult(index){
 const item=commandPaletteItems[index];if(!item)return;closeCommandPalette();
 const url=item.url||"#";
 if(url.startsWith("#")){const el=document.querySelector(url);if(el)el.scrollIntoView({behavior:motionBehavior(),block:"start"});return}
 if(item.new_tab){window.open(url,"_blank","noopener");return}
 window.location.href=url;
}
function moveCommandSelection(delta){
 if(!commandPaletteItems.length)return;
 commandPaletteIndex=(commandPaletteIndex+delta+commandPaletteItems.length)%commandPaletteItems.length;renderCommandResults(commandPaletteItems);
}
const commandInput=document.getElementById("commandPaletteInput");
if(commandInput){commandInput.addEventListener("input",()=>{clearTimeout(commandPaletteTimer);commandPaletteIndex=0;commandPaletteTimer=setTimeout(()=>runGlobalSearch(commandInput.value.trim()),120)});}
document.addEventListener("keydown",e=>{
 const shell=document.getElementById("commandPaletteShell"),open=!!shell?.classList.contains("show");
 if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==="k"){e.preventDefault();open?closeCommandPalette():openCommandPalette();return}
 if(!open)return;
 if(e.key==="Escape"){e.preventDefault();closeCommandPalette()}
 else if(e.key==="ArrowDown"){e.preventDefault();moveCommandSelection(1)}
 else if(e.key==="ArrowUp"){e.preventDefault();moveCommandSelection(-1)}
 else if(e.key==="Enter"){e.preventDefault();activateCommandResult(commandPaletteIndex)}
});

loadUser();loadArenas();

hydrateChallenge();
</script>
</body>
</html>
"""


@app.route("/api/user/<username>")
def user_api(username):

    user = get_user(username)

    conn = db()

    ranking = conn.execute(
        "SELECT username, xp FROM users ORDER BY xp DESC"
    ).fetchall()

    claimed_rows = conn.execute(
        """
        SELECT milestone
        FROM streak_rewards
        WHERE username = ?
        ORDER BY milestone
        """,
        (username,)
    ).fetchall()

    claimed_milestones = [
        row["milestone"]
        for row in claimed_rows
    ]

    conn.close()

    rank = 1

    for i, row in enumerate(
        ranking,
        start=1
    ):
        if row["username"] == username:
            rank = i
            break

    return jsonify({
        "success": True,
        "username": username,
        "wallet": user["wallet"],
        "xp": user["xp"],
        "streak": user["streak"],
        "rank": rank,
        "claimed_milestones": claimed_milestones
    })
    

@app.route("/api/quest", methods=["POST"])
def quest_api():
    

    data = request.get_json(silent=True) or {}

    username = data.get(
        "user",
        "demo_user"
    )

    quest_name = data.get(
        "quest",
        "checkin"
    )

    if quest_name not in REWARDS:

        return jsonify({
            "success": False,
            "message": "Unknown quest"
        }), 400

    # V5.3: only Daily Check-in may use the generic quest endpoint.
    if quest_name != "checkin":
        return jsonify({
            "success": False,
            "message": "🔐 This quest requires verified completion"
        }), 403

    get_user(username)

    today = datetime.utcnow().strftime(
        "%Y-%m-%d"
    )

    conn = db()

    existing = conn.execute(
        """
        SELECT id
        FROM quests
        WHERE username = ?
        AND quest = ?
        AND date = ?
        """,
        (
            username,
            quest_name,
            today
        )
    ).fetchone()

    if existing:

        conn.close()

        return jsonify({
            "success": False,
            "message":
                "⚠️ Quest already completed today"
        })
    reward = REWARDS[quest_name]

    if quest_name == "checkin":

        last_checkin = conn.execute(
            """
            SELECT date
            FROM quests
            WHERE username = ?
            AND quest = 'checkin'
            ORDER BY date DESC
            LIMIT 1
            """,
            (username,)
        ).fetchone()

        yesterday = (
            datetime.utcnow() - timedelta(days=1)
        ).strftime("%Y-%m-%d")

        if last_checkin and last_checkin["date"] == yesterday:
            current_streak = conn.execute(
                "SELECT streak FROM users WHERE username = ?",
                (username,)
            ).fetchone()["streak"]

            new_streak = current_streak + 1

        else:
            new_streak = 1

        conn.execute(
            """
            UPDATE users
            SET xp = xp + ?,
                streak = ?
            WHERE username = ?
            """,
            (reward, new_streak, username)
        )

    else:

        conn.execute(
            """
            UPDATE users
            SET xp = xp + ?
            WHERE username = ?
            """,
            (reward, username)
        )

    conn.execute(
        """
        INSERT INTO quests
        (username, quest, date)
        VALUES (?, ?, ?)
        """,
        (
            username,
            quest_name,
            today
        )
    )

    conn.commit()

    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    ranking = conn.execute(
        "SELECT username, xp FROM users ORDER BY xp DESC"
    ).fetchall()

    conn.close()

    rank = 1

    for i, row in enumerate(
        ranking,
        start=1
    ):

        if row["username"] == username:
            rank = i
            break

    return jsonify({
        "success": True,
        "xp": user["xp"],
        "streak": user["streak"],
        "rank": rank,
        "message":
            f"🔥 Quest complete! +{reward} XP"
    })



@app.route("/api/auth/nonce")
def auth_nonce():

    wallet = request.args.get("wallet", "").strip().lower()
    username = request.args.get("user", "").strip()

    if not wallet or not username:
        return jsonify({
            "success": False,
            "message": "❌ Wallet and username are required"
        }), 400

    if not wallet.startswith("0x") or len(wallet) != 42:
        return jsonify({
            "success": False,
            "message": "❌ Invalid EVM wallet address"
        }), 400

    nonce = secrets.token_hex(16)

    message = (
        "Sign in to BL3 Hub\n\n"
        f"Username: {username}\n"
        f"Wallet: {wallet}\n"
        f"Nonce: {nonce}\n\n"
        "This signature does not send a transaction or cost gas."
    )

    session["auth_wallet"] = wallet
    session["auth_username"] = username
    session["auth_nonce"] = nonce
    session["auth_message"] = message
    session["auth_created_at"] = int(time.time())

    return jsonify({
        "success": True,
        "message": message
    })


@app.route("/api/auth/verify", methods=["POST"])
def auth_verify():

    data = request.get_json(silent=True) or {}

    wallet = str(data.get("wallet", "")).strip().lower()
    username = str(data.get("username", "")).strip()
    message = str(data.get("message", ""))
    signature = str(data.get("signature", ""))

    expected_wallet = session.get("auth_wallet")
    expected_username = session.get("auth_username")
    expected_message = session.get("auth_message")
    created_at = session.get("auth_created_at", 0)

    if not wallet or not username or not message or not signature:
        return jsonify({
            "success": False,
            "message": "❌ Missing wallet signature data"
        }), 400

    if int(time.time()) - int(created_at or 0) > 300:
        session.clear()
        return jsonify({
            "success": False,
            "message": "❌ Sign-in challenge expired. Try again."
        }), 400

    if (
        wallet != expected_wallet
        or username != expected_username
        or message != expected_message
    ):
        return jsonify({
            "success": False,
            "message": "❌ Sign-in challenge mismatch"
        }), 400

    try:
        encoded_message = encode_defunct(text=message)
        recovered = Account.recover_message(
            encoded_message,
            signature=signature
        ).lower()
    except Exception:
        return jsonify({
            "success": False,
            "message": "❌ Invalid wallet signature"
        }), 400

    if recovered != wallet:
        return jsonify({
            "success": False,
            "message": "❌ Signature does not match this wallet"
        }), 401

    get_user(username)

    conn = db()

    owner = conn.execute(
        "SELECT username FROM users WHERE lower(wallet) = ? AND username != ?",
        (wallet, username)
    ).fetchone()

    if owner:
        conn.close()
        return jsonify({
            "success": False,
            "message": "❌ This wallet is already linked to another BL3 profile"
        }), 409

    conn.execute(
        "UPDATE users SET wallet = ? WHERE username = ?",
        (wallet, username)
    )

    conn.commit()
    conn.close()

    session.pop("auth_nonce", None)
    session.pop("auth_message", None)
    session.pop("auth_created_at", None)

    session["authenticated_wallet"] = wallet
    session["authenticated_username"] = username

    return jsonify({
        "success": True,
        "message": "🔐 Wallet signature verified. Signed in successfully.",
        "wallet": wallet,
        "username": username
    })


@app.route("/api/auth/status")
def auth_status():

    wallet = session.get("authenticated_wallet")
    username = session.get("authenticated_username")

    return jsonify({
        "success": True,
        "authenticated": bool(wallet and username),
        "wallet": wallet or "",
        "username": username or ""
    })


@app.route("/api/wallet", methods=["POST"])
def wallet_api():

    data = request.get_json(silent=True) or {}

    username = str(data.get("user", "")).strip()
    wallet = str(data.get("wallet", "")).strip().lower()

    if (
        session.get("authenticated_username") != username
        or session.get("authenticated_wallet") != wallet
    ):
        return jsonify({
            "success": False,
            "message": "❌ Verify wallet ownership before saving"
        }), 401

    get_user(username)

    conn = db()
    conn.execute(
        "UPDATE users SET wallet = ? WHERE username = ?",
        (wallet, username)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "👛 Verified wallet saved successfully"
    })



@app.route("/api/share/verify", methods=["POST"])
def share_verify_api():
    data = request.get_json(silent=True) or {}
    username = str(data.get("user", "")).strip()
    cast_url = str(data.get("cast_url", "")).strip()

    if not username or not cast_url:
        return jsonify({"success": False, "message": "❌ Username and cast URL are required"}), 400

    auth_user = session.get("authenticated_username")
    auth_wallet = str(session.get("authenticated_wallet") or "").lower()

    if auth_user != username or not auth_wallet:
        return jsonify({"success": False, "message": "🔐 Sign in with your verified wallet before claiming Share XP"}), 401

    api_key = os.environ.get("NEYNAR_API_KEY", "").strip()
    if not api_key:
        return jsonify({"success": False, "message": "❌ Share verification is not configured"}), 503

    try:
        host = (urllib.parse.urlparse(cast_url).hostname or "").lower()
    except Exception:
        host = ""

    if host not in {"warpcast.com", "www.warpcast.com", "farcaster.xyz", "www.farcaster.xyz"}:
        return jsonify({"success": False, "message": "❌ Paste a valid Farcaster/Warpcast cast URL"}), 400

    query = urllib.parse.urlencode({"identifier": cast_url, "type": "url"})
    req = urllib.request.Request(
        "https://api.neynar.com/v2/farcaster/cast?" + query,
        headers={"accept": "application/json", "x-api-key": api_key, "user-agent": "BL3-Hub/5.3"},
        method="GET"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return jsonify({"success": False, "message": f"❌ Neynar could not verify this cast (HTTP {exc.code})"}), 502
    except Exception:
        return jsonify({"success": False, "message": "❌ Could not reach Neynar to verify this cast"}), 502

    cast = payload.get("cast") or {}
    cast_hash = str(cast.get("hash") or "").strip()
    cast_text = str(cast.get("text") or "")
    author = cast.get("author") or {}
    verified = author.get("verified_addresses") or {}
    eth_addresses = [str(a).lower() for a in (verified.get("eth_addresses") or [])]

    if not cast_hash:
        return jsonify({"success": False, "message": "❌ Cast not found"}), 404

    if "bl3" not in cast_text.lower() and "bl3meme.com" not in cast_text.lower():
        return jsonify({"success": False, "message": "❌ This cast does not mention BL3"}), 400

    if auth_wallet not in eth_addresses:
        return jsonify({"success": False, "message": "❌ This cast author is not verified with your BL3 wallet on Farcaster"}), 403

    conn = db()
    user = conn.execute("SELECT username, wallet FROM users WHERE username = ?", (username,)).fetchone()

    if user is None or not user["wallet"] or str(user["wallet"]).lower() != auth_wallet:
        conn.close()
        return jsonify({"success": False, "message": "❌ Verified wallet does not match this BL3 profile"}), 401

    if conn.execute("SELECT id FROM share_claims WHERE cast_hash = ?", (cast_hash,)).fetchone():
        conn.close()
        return jsonify({"success": False, "message": "⚠️ This cast has already been used for Share XP"}), 409

    today = datetime.utcnow().strftime("%Y-%m-%d")
    if conn.execute("SELECT id FROM share_claims WHERE username = ? AND date = ?", (username, today)).fetchone():
        conn.close()
        return jsonify({"success": False, "message": "⚠️ Share quest already completed today"}), 409

    try:
        conn.execute("INSERT INTO share_claims (username, cast_hash, cast_url, date) VALUES (?, ?, ?, ?)",
                     (username, cast_hash, cast_url, today))
        conn.execute("UPDATE users SET xp = xp + ? WHERE username = ?", (REWARDS["share"], username))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        return jsonify({"success": False, "message": "⚠️ This cast has already been used for Share XP"}), 409

    user = conn.execute("SELECT xp, streak FROM users WHERE username = ?", (username,)).fetchone()
    ranking = conn.execute("SELECT username, xp FROM users ORDER BY xp DESC").fetchall()
    conn.close()

    rank = next((i for i, row in enumerate(ranking, start=1) if row["username"] == username), 1)

    return jsonify({
        "success": True, "xp": user["xp"], "streak": user["streak"], "rank": rank,
        "message": f"📢 Verified Farcaster share! +{REWARDS['share']} XP"
    })


@app.route("/api/referral", methods=["POST"])
def referral_api():

    data = request.get_json(silent=True) or {}
    inviter = str(data.get("inviter", "")).strip()
    invited = str(data.get("invited", "")).strip()

    if not inviter or not invited:
        return jsonify({
            "success": False,
            "message": "❌ Inviter and invited username are required"
        }), 400

    if inviter == invited:
        return jsonify({
            "success": False,
            "message": "❌ You cannot invite yourself"
        }), 400

    # V5.2: reward referrals only after the invited user proves wallet ownership.
    if session.get("authenticated_username") != invited:
        return jsonify({
            "success": False,
            "message": "🔐 Sign in with the invited user's wallet before claiming this referral"
        }), 401

    conn = db()

    inviter_user = conn.execute(
        "SELECT username FROM users WHERE username = ?",
        (inviter,)
    ).fetchone()

    invited_user = conn.execute(
        "SELECT username, wallet FROM users WHERE username = ?",
        (invited,)
    ).fetchone()

    if inviter_user is None:
        conn.close()
        return jsonify({
            "success": False,
            "message": "❌ Inviter profile does not exist"
        }), 404

    if invited_user is None or not invited_user["wallet"]:
        conn.close()
        return jsonify({
            "success": False,
            "message": "🔐 Invited user must verify a wallet first"
        }), 401

    if session.get("authenticated_wallet") != invited_user["wallet"].lower():
        conn.close()
        return jsonify({
            "success": False,
            "message": "❌ Verified wallet does not match the invited profile"
        }), 401

    today = datetime.utcnow().strftime("%Y-%m-%d")

    existing = conn.execute(
        "SELECT id FROM referrals WHERE invited = ?",
        (invited,)
    ).fetchone()

    if existing:
        conn.close()
        return jsonify({
            "success": False,
            "message": "⚠️ This user has already been referred"
        })

    conn.execute(
        "INSERT INTO referrals (inviter, invited, date) VALUES (?, ?, ?)",
        (inviter, invited, today)
    )

    conn.execute(
        "UPDATE users SET xp = xp + ? WHERE username = ?",
        (REWARDS["invite"], inviter)
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"👥 Referral complete! +{REWARDS['invite']} XP"
    })



@app.route("/api/streak/claim", methods=["POST"])
def streak_claim_api():

    data = request.get_json(silent=True) or {}

    username = str(data.get("user", "")).strip()
    milestone = data.get("milestone")

    
    if session.get("authenticated_username") != username:
        return jsonify({
            "success": False,
            "message": "🔐 Sign in with this profile's wallet before claiming a streak reward"
        }), 401
    rewards = {
        3: 25,
        7: 75,
        30: 300
    }

    try:
        milestone = int(milestone)
    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "message": "❌ Invalid milestone"
        }), 400

    if milestone not in rewards:
        return jsonify({
            "success": False,
            "message": "❌ Invalid milestone"
        }), 400

    conn = db()

    user = conn.execute(
        "SELECT streak, xp FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if user is None:
        conn.close()
        return jsonify({
            "success": False,
            "message": "❌ User not found"
        }), 404

    if user["streak"] < milestone:
        conn.close()
        return jsonify({
            "success": False,
            "message": f"🔒 Reach a {milestone}-day streak first"
        }), 403

    existing = conn.execute(
        """
        SELECT id
        FROM streak_rewards
        WHERE username = ?
        AND milestone = ?
        """,
        (username, milestone)
    ).fetchone()

    if existing:
        conn.close()
        return jsonify({
            "success": False,
            "message": "⚠️ This streak reward has already been claimed"
        }), 409

    reward = rewards[milestone]
    claimed_at = datetime.utcnow().isoformat()

    try:
        conn.execute(
            """
            INSERT INTO streak_rewards
            (username, milestone, claimed_at)
            VALUES (?, ?, ?)
            """,
            (username, milestone, claimed_at)
        )

        conn.execute(
            "UPDATE users SET xp = xp + ? WHERE username = ?",
            (reward, username)
        )

        conn.commit()

    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()

        return jsonify({
            "success": False,
            "message": "⚠️ This streak reward has already been claimed"
        }), 409

    updated = conn.execute(
        "SELECT xp, streak FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    conn.close()

    return jsonify({
        "success": True,
        "xp": updated["xp"],
        "streak": updated["streak"],
        "reward": reward,
        "message": f"🎁 {milestone}-Day reward claimed! +{reward} XP"
    })



@app.route("/api/arenas", methods=["GET", "POST"])
def arenas_api():
    if request.method == "GET":
        conn = db()
        rows = conn.execute("""
            SELECT a.*,
                   (SELECT COUNT(*) FROM arena_submissions s WHERE s.arena_id = a.id) AS submissions
            FROM arenas a
            ORDER BY CASE WHEN a.status = 'live' THEN 0 ELSE 1 END, a.id DESC
            LIMIT 100
        """).fetchall()
        conn.close()
        return jsonify({"success": True, "arenas": [dict(row) for row in rows]})

    data = request.get_json(silent=True) or {}
    creator = str(data.get("creator", "")).strip()
    title = str(data.get("title", "")).strip()
    description = str(data.get("description", "")).strip()
    category = str(data.get("category", "Alpha")).strip()[:40]
    deadline = str(data.get("deadline", "")).strip()[:40]

    try:
        bounty_amount = max(0.0, float(data.get("bounty_amount") or 0))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "❌ Invalid bounty amount"}), 400

    if not creator or not title or not description:
        return jsonify({"success": False, "message": "❌ Creator, title and description are required"}), 400

    # Creating paid-looking campaigns is restricted to a wallet-authenticated profile.
    if session.get("authenticated_username") != creator:
        return jsonify({"success": False, "message": "🔐 Sign in with the creator wallet before launching an Arena"}), 401

    get_user(creator)
    now = datetime.utcnow().isoformat()

    conn = db()
    cur = conn.execute("""
        INSERT INTO arenas
        (creator, title, description, category, bounty_amount, bounty_asset, status, deadline, created_at)
        VALUES (?, ?, ?, ?, ?, 'USDC', 'live', ?, ?)
    """, (creator, title[:120], description[:3000], category, bounty_amount, deadline, now))
    arena_id = cur.lastrowid
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "arena_id": arena_id,
        "message": "⚡ Arena launched. Listed bounty is project-funded; BL3 does not custody funds in this MVP."
    })


@app.route("/api/arenas/<int:arena_id>/submit", methods=["POST"])
def arena_submit_api(arena_id):
    data = request.get_json(silent=True) or {}
    username = str(data.get("user", "")).strip()
    pitch = str(data.get("pitch", "")).strip()
    proof_url = str(data.get("proof_url", "")).strip()

    if not username or not pitch:
        return jsonify({"success": False, "message": "❌ Username and contribution are required"}), 400

    if session.get("authenticated_username") != username:
        return jsonify({"success": False, "message": "🔐 Sign in with this hunter wallet before submitting proof"}), 401

    conn = db()
    arena = conn.execute("SELECT id, status FROM arenas WHERE id = ?", (arena_id,)).fetchone()
    if arena is None:
        conn.close()
        return jsonify({"success": False, "message": "❌ Arena not found"}), 404
    if arena["status"] != "live":
        conn.close()
        return jsonify({"success": False, "message": "🔒 This Arena is closed"}), 403

    now = datetime.utcnow().isoformat()
    try:
        conn.execute("""
            INSERT INTO arena_submissions
            (arena_id, username, proof_url, pitch, status, created_at)
            VALUES (?, ?, ?, ?, 'submitted', ?)
        """, (arena_id, username, proof_url[:1000], pitch[:5000], now))
        conn.execute("""
            INSERT INTO reputation_events (username, points, reason, created_at)
            VALUES (?, 5, ?, ?)
        """, (username, f"Arena #{arena_id} submission", now))
        conn.execute("UPDATE users SET xp = xp + 5 WHERE username = ?", (username,))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        return jsonify({"success": False, "message": "⚠️ You already submitted to this Arena"}), 409

    conn.close()
    return jsonify({"success": True, "message": "⚡ Proof submitted. +5 XP participation signal."})



@app.route("/api/arenas/<int:arena_id>/submissions")
def arena_submissions_api(arena_id):
    conn = db()
    arena = conn.execute("SELECT * FROM arenas WHERE id = ?", (arena_id,)).fetchone()
    if arena is None:
        conn.close()
        return jsonify({"success": False, "message": "❌ Arena not found"}), 404
    if session.get("authenticated_username") != arena["creator"]:
        conn.close()
        return jsonify({"success": False, "message": "🔐 Creator wallet authentication required"}), 401
    rows = conn.execute("""
        SELECT id, username, proof_url, pitch, status, created_at
        FROM arena_submissions WHERE arena_id = ? ORDER BY id DESC
    """, (arena_id,)).fetchall()
    conn.close()
    return jsonify({"success": True, "arena": dict(arena), "submissions": [dict(r) for r in rows]})


@app.route("/api/arenas/<int:arena_id>/winner", methods=["POST"])
def arena_winner_api(arena_id):
    data = request.get_json(silent=True) or {}
    creator = str(data.get("creator", "")).strip()
    winner = str(data.get("winner", "")).strip()
    conn = db()
    arena = conn.execute("SELECT * FROM arenas WHERE id = ?", (arena_id,)).fetchone()
    if arena is None:
        conn.close()
        return jsonify({"success": False, "message": "❌ Arena not found"}), 404
    if session.get("authenticated_username") != arena["creator"] or creator != arena["creator"]:
        conn.close()
        return jsonify({"success": False, "message": "🔐 Only the authenticated creator can select a winner"}), 401
    submission = conn.execute(
        "SELECT id FROM arena_submissions WHERE arena_id = ? AND username = ?",
        (arena_id, winner)
    ).fetchone()
    if submission is None:
        conn.close()
        return jsonify({"success": False, "message": "❌ Winner must have a valid submission"}), 400
    if arena["winner_username"]:
        conn.close()
        return jsonify({"success": False, "message": "⚠️ Winner already selected"}), 409
    now = datetime.utcnow().isoformat()
    conn.execute("UPDATE arenas SET winner_username = ?, status = 'closed' WHERE id = ?", (winner, arena_id))
    conn.execute("UPDATE arena_submissions SET status = CASE WHEN username = ? THEN 'winner' ELSE 'not_selected' END WHERE arena_id = ?", (winner, arena_id))
    conn.execute("INSERT INTO reputation_events (username, points, reason, created_at) VALUES (?, 100, ?, ?)",
                 (winner, f"Arena #{arena_id} winner", now))
    conn.execute("UPDATE users SET xp = xp + 100 WHERE username = ?", (winner,))
    _notify(conn, winner, "arena", f"👑 You won Arena #{arena_id}", "Winner selected. +100 XP / REP signal recorded.", "/")
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"👑 {winner} selected as winner. +100 XP / REP signal."})


@app.route("/api/arenas/<int:arena_id>/paid", methods=["POST"])
def arena_paid_api(arena_id):
    data = request.get_json(silent=True) or {}
    creator = str(data.get("creator", "")).strip()
    conn = db()
    arena = conn.execute("SELECT * FROM arenas WHERE id = ?", (arena_id,)).fetchone()
    if arena is None:
        conn.close()
        return jsonify({"success": False, "message": "❌ Arena not found"}), 404
    if session.get("authenticated_username") != arena["creator"] or creator != arena["creator"]:
        conn.close()
        return jsonify({"success": False, "message": "🔐 Only the authenticated creator can mark payment"}), 401
    if not arena["winner_username"]:
        conn.close()
        return jsonify({"success": False, "message": "❌ Select a winner first"}), 400
    if arena["paid"]:
        conn.close()
        return jsonify({"success": False, "message": "⚠️ Payment already marked"}), 409
    now = datetime.utcnow().isoformat()
    conn.execute("UPDATE arenas SET paid = 1, paid_at = ? WHERE id = ?", (now, arena_id))
    _notify(conn, arena["winner_username"], "payment", f"✅ Arena #{arena_id} marked paid", f"{arena['bounty_amount']:g} {arena['bounty_asset']} is now counted in your BL3 earned total.", "/")
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "✅ Payment marked as completed. Earnings are now counted in the winner profile."})


@app.route("/api/onboarding/<username>")
def onboarding_api(username):
    username = str(username or "").strip()
    if not username or username == "demo_user":
        return jsonify({"success": True, "profile": False, "wallet": False, "first_action": False, "completed": 0})

    conn = db()
    user = conn.execute("SELECT username, wallet FROM users WHERE username = ?", (username,)).fetchone()
    has_profile = user is not None
    has_wallet = bool(user and user["wallet"])
    battle = conn.execute(
        "SELECT 1 FROM creature_battles WHERE challenger = ? OR opponent = ? LIMIT 1",
        (username, username)
    ).fetchone()
    proof = conn.execute(
        "SELECT 1 FROM arena_submissions WHERE username = ? LIMIT 1",
        (username,)
    ).fetchone()
    conn.close()
    first_action = bool(battle or proof)
    completed = int(has_profile) + int(has_wallet) + int(first_action)
    return jsonify({
        "success": True,
        "profile": has_profile,
        "wallet": has_wallet,
        "first_action": first_action,
        "completed": completed
    })


@app.route("/api/passport/<username>")
def passport_api(username):
    user = get_user(username)
    xp = int(user["xp"] or 0)
    # Evolution is deliberately derived from existing XP: no destructive DB migration.
    stages = [
        (0, 100, "🥚", "BL3 Seed", "DORMANT"),
        (100, 300, "👾", "Glitchling", "AWAKENED"),
        (300, 700, "😈", "Chaos Spawn", "EVOLVED"),
        (700, 1500, "🦹", "Alpha Beast", "ALPHA"),
        (1500, None, "👑", "Crown Entity", "ASCENDED"),
    ]
    selected = stages[0]
    for stage in stages:
        if xp >= stage[0]:
            selected = stage
    floor, ceiling, avatar, name, stage_name = selected
    if ceiling is None:
        current = xp - floor
        target = max(1, current)
        percent = 100
    else:
        current = max(0, xp - floor)
        target = ceiling - floor
        percent = round((current / target) * 100, 1)
    level = max(1, xp // 100 + 1)
    conn = db()
    network = conn.execute(
        "SELECT COUNT(*) AS n FROM referrals WHERE inviter = ?",
        (username,)
    ).fetchone()["n"]
    conn.close()
    return jsonify({
        "success": True,
        "username": username,
        "level": level,
        "network": network,
        "creature": {"avatar": avatar, "name": name, "stage": stage_name},
        "evolution": {"current": current, "target": target, "percent": percent}
    })


def _creature_avatar_from_xp(xp):
    xp = int(xp or 0)
    if xp >= 1500: return "👑"
    if xp >= 700: return "🦹"
    if xp >= 300: return "😈"
    if xp >= 100: return "👾"
    return "🥚"



def _hunter_trophies(username):
    """Public, read-only achievements derived from existing BL3 activity."""
    conn = db()
    user = conn.execute(
        "SELECT username, wallet, xp, streak FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    if user is None:
        conn.close()
        return None

    trophies = []
    def add(key, icon, title, detail, tier="BRONZE"):
        trophies.append({
            "key": key,
            "icon": icon,
            "title": title,
            "detail": detail,
            "tier": tier
        })

    xp = int(user["xp"] or 0)
    streak = int(user["streak"] or 0)
    rep = int(conn.execute(
        "SELECT COALESCE(SUM(points),0) AS n FROM reputation_events WHERE username = ?",
        (username,)
    ).fetchone()["n"] or 0)

    battle_stats = conn.execute(
        """SELECT
             COUNT(*) AS battles,
             SUM(CASE WHEN winner = ? THEN 1 ELSE 0 END) AS wins
           FROM creature_battles
           WHERE challenger = ? OR opponent = ?""",
        (username, username, username)
    ).fetchone()
    battles = int(battle_stats["battles"] or 0)
    clash_wins = int(battle_stats["wins"] or 0)

    arena_wins = int(conn.execute(
        "SELECT COUNT(*) AS n FROM arenas WHERE winner_username = ?",
        (username,)
    ).fetchone()["n"] or 0)
    paid_wins = int(conn.execute(
        "SELECT COUNT(*) AS n FROM arenas WHERE winner_username = ? AND paid = 1",
        (username,)
    ).fetchone()["n"] or 0)

    defenses = int(conn.execute(
        """SELECT COUNT(*) AS n FROM crown_events
           WHERE defender = ? AND successful_defense = 1""",
        (username,)
    ).fetchone()["n"] or 0)
    crown_breaks = int(conn.execute(
        """SELECT COUNT(*) AS n FROM crown_events
           WHERE challenger = ? AND winner = ? AND successful_defense = 0""",
        (username, username)
    ).fetchone()["n"] or 0)

    referrals = int(conn.execute(
        "SELECT COUNT(*) AS n FROM referrals WHERE inviter = ?",
        (username,)
    ).fetchone()["n"] or 0)

    followers = int(conn.execute(
        "SELECT COUNT(*) AS n FROM hunter_connections WHERE target = ? AND kind = 'follow'",
        (username,)
    ).fetchone()["n"] or 0)

    # Rivalry depth: strongest direct opponent by number of clashes.
    rival_rows = conn.execute(
        """SELECT
             CASE WHEN challenger = ? THEN opponent ELSE challenger END AS rival,
             COUNT(*) AS clashes
           FROM creature_battles
           WHERE challenger = ? OR opponent = ?
           GROUP BY rival
           ORDER BY clashes DESC""",
        (username, username, username)
    ).fetchall()

    conn.close()

    if user["wallet"]:
        add("verified_hunter", "🔐", "VERIFIED HUNTER",
            "Wallet ownership verified for this Hunter ID.", "BRONZE")

    if battles >= 1:
        add("first_clash", "⚔️", "FIRST CLASH",
            f"Entered the BL3 arena. {battles} total direct Clash{'es' if battles != 1 else ''}.", "BRONZE")
    if clash_wins >= 1:
        add("clash_victor", "🩸", "CLASH VICTOR",
            f"{clash_wins} Alpha Clash win{'s' if clash_wins != 1 else ''}.", "BRONZE")
    if battles >= 10:
        add("battle_hardened", "🛡️", "BATTLE HARDENED",
            f"Survived {battles} direct Clashes.", "SILVER")
    if clash_wins >= 10:
        add("alpha_hunter", "😈", "ALPHA HUNTER",
            f"Reached {clash_wins} direct Clash wins.", "GOLD")

    strongest = rival_rows[0] if rival_rows else None
    if strongest and int(strongest["clashes"] or 0) >= 5:
        add("nemesis_found", "🔥", "NEMESIS FOUND",
            f"{int(strongest['clashes'])} clashes with {strongest['rival']}.", "SILVER")

    if arena_wins >= 1:
        add("arena_winner", "🎯", "ARENA WINNER",
            f"Won {arena_wins} project Arena{'s' if arena_wins != 1 else ''}.", "SILVER")
    if paid_wins >= 1:
        add("proof_paid", "💎", "PROOF PAID",
            f"{paid_wins} winning Arena result{'s' if paid_wins != 1 else ''} marked paid.", "GOLD")

    if defenses >= 1:
        add("crown_defender", "👑", "CROWN DEFENDER",
            f"Defended the Crown {defenses} time{'s' if defenses != 1 else ''}.", "GOLD")
    if crown_breaks >= 1:
        add("crown_breaker", "💥", "CROWN BREAKER",
            f"Broke a Crown defense {crown_breaks} time{'s' if crown_breaks != 1 else ''}.", "GOLD")

    if referrals >= 5:
        add("network_builder", "👥", "NETWORK BUILDER",
            f"Built a verified network of {referrals} Hunters.", "SILVER")
    if followers >= 10:
        add("signal_magnet", "📡", "SIGNAL MAGNET",
            f"Reached {followers} followers.", "SILVER")

    if rep >= 100:
        add("reputation_100", "⚡", "100 REP",
            f"Built {rep} reputation points.", "SILVER")
    if rep >= 500:
        add("reputation_500", "🌠", "500 REP",
            f"Crossed the 500 REP threshold with {rep} total.", "GOLD")
    if xp >= 1500:
        add("ascended", "👑", "ASCENDED",
            f"Reached Crown Entity evolution at {xp} XP.", "LEGENDARY")
    if streak >= 7:
        add("seven_day_flame", "🔥", "7-DAY FLAME",
            f"Maintained a {streak}-day activity streak.", "GOLD")

    # Highest tiers first, then stable title order.
    tier_order = {"LEGENDARY": 4, "GOLD": 3, "SILVER": 2, "BRONZE": 1}
    trophies.sort(key=lambda t: (-tier_order.get(t["tier"], 0), t["title"]))

    return {
        "username": username,
        "count": len(trophies),
        "trophies": trophies
    }


@app.route("/api/trophies/<username>")
def hunter_trophies_api(username):
    data = _hunter_trophies(username)
    if data is None:
        return jsonify({"success": False, "message": "Hunter not found"}), 404
    return jsonify({"success": True, **data})



def _hunter_showcase(username):
    """Return the equipped Featured Trophy, falling back to strongest unlocked Trophy."""
    data = _hunter_trophies(username)
    if data is None:
        return None

    trophies = data.get("trophies", [])
    if not trophies:
        return {
            "username": username,
            "featured": None,
            "options": []
        }

    by_key = {t["key"]: t for t in trophies}
    conn = db()
    row = conn.execute(
        "SELECT trophy_key FROM hunter_showcase_choices WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    selected_key = row["trophy_key"] if row is not None else None
    featured = by_key.get(selected_key)
    if featured is None:
        featured = trophies[0]

    return {
        "username": username,
        "featured": featured,
        "options": trophies
    }


@app.route("/api/showcase/<username>", methods=["GET", "POST"])
def hunter_showcase_api(username):
    data = _hunter_showcase(username)
    if data is None:
        return jsonify({"success": False, "message": "Hunter not found"}), 404

    if request.method == "GET":
        return jsonify({"success": True, **data})

    if session.get("authenticated_username") != username:
        return jsonify({
            "success": False,
            "message": "Sign in with this Hunter ID to pin a Featured Trophy."
        }), 401

    payload = request.get_json(silent=True) or {}
    trophy_key = str(payload.get("trophy_key", "")).strip()
    by_key = {t["key"]: t for t in data.get("options", [])}
    if trophy_key not in by_key:
        return jsonify({
            "success": False,
            "message": "That Trophy is not unlocked for this Hunter."
        }), 400

    conn = db()
    conn.execute(
        """INSERT INTO hunter_showcase_choices(username, trophy_key, updated_at)
           VALUES (?, ?, ?)
           ON CONFLICT(username) DO UPDATE SET
             trophy_key = excluded.trophy_key,
             updated_at = excluded.updated_at""",
        (username, trophy_key, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"🏆 Featured {by_key[trophy_key]['title']}",
        "featured": by_key[trophy_key]
    })


def _hunter_title_options(username):
    """Return all titles unlocked by the Hunter's current Trophy Room."""
    data = _hunter_trophies(username)
    if data is None:
        return None

    trophies = data.get("trophies", [])
    by_key = {t["key"]: t for t in trophies}

    catalog = [
        ("ascended", "CROWN ENTITY", "👑", "LEGENDARY"),
        ("crown_breaker", "CROWN BREAKER", "💥", "GOLD"),
        ("crown_defender", "CROWN DEFENDER", "👑", "GOLD"),
        ("proof_paid", "PROOF HUNTER", "💎", "GOLD"),
        ("alpha_hunter", "ALPHA HUNTER", "😈", "GOLD"),
        ("seven_day_flame", "FLAMEKEEPER", "🔥", "GOLD"),
        ("reputation_500", "REPUTATION ELITE", "🌠", "GOLD"),
        ("nemesis_found", "NEMESIS", "🔥", "SILVER"),
        ("arena_winner", "ARENA WINNER", "🎯", "SILVER"),
        ("signal_magnet", "SIGNAL MAGNET", "📡", "SILVER"),
        ("network_builder", "NETWORK BUILDER", "👥", "SILVER"),
        ("reputation_100", "PROVEN HUNTER", "⚡", "SILVER"),
        ("battle_hardened", "BATTLE HARDENED", "🛡️", "SILVER"),
        ("clash_victor", "CLASH VICTOR", "🩸", "BRONZE"),
        ("verified_hunter", "VERIFIED HUNTER", "🔐", "BRONZE"),
        ("first_clash", "NEW BLOOD", "⚔️", "BRONZE"),
    ]

    unlocked = []
    for key, title, icon, tier in catalog:
        if key in by_key:
            unlocked.append({
                "key": key,
                "title": title,
                "icon": icon,
                "tier": tier,
                "source": by_key[key]["title"]
            })

    # Everyone has a neutral fallback title.
    unlocked.append({
        "key": "hunter",
        "title": "HUNTER",
        "icon": "👾",
        "tier": "UNRANKED",
        "source": None
    })
    return unlocked


def _hunter_title(username):
    """Return the equipped title if still unlocked, else strongest unlocked title."""
    options = _hunter_title_options(username)
    if options is None:
        return None

    conn = db()
    row = conn.execute(
        "SELECT title_key FROM hunter_title_choices WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    by_key = {t["key"]: t for t in options}
    if row is not None and row["title_key"] in by_key:
        return {**by_key[row["title_key"]], "equipped": True}

    # Options are ordered strongest to weakest, with HUNTER last.
    return {**options[0], "equipped": False}


@app.route("/api/title/<username>", methods=["GET", "POST"])
def hunter_title_api(username):
    current = _hunter_title(username)
    options = _hunter_title_options(username)
    if current is None or options is None:
        return jsonify({"success": False, "message": "Hunter not found"}), 404

    if request.method == "GET":
        return jsonify({
            "success": True,
            "username": username,
            "current": current,
            "options": options
        })

    if session.get("authenticated_username") != username:
        return jsonify({
            "success": False,
            "message": "Sign in with this Hunter ID to equip a title."
        }), 401

    data = request.get_json(silent=True) or {}
    title_key = str(data.get("title_key", "")).strip()
    by_key = {t["key"]: t for t in options}
    if title_key not in by_key:
        return jsonify({
            "success": False,
            "message": "That title is not unlocked for this Hunter."
        }), 400

    conn = db()
    conn.execute(
        """INSERT INTO hunter_title_choices(username, title_key, updated_at)
           VALUES (?, ?, ?)
           ON CONFLICT(username) DO UPDATE SET
             title_key = excluded.title_key,
             updated_at = excluded.updated_at""",
        (username, title_key, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"🏷️ Equipped {by_key[title_key]['title']}",
        "current": {**by_key[title_key], "equipped": True},
        "options": options
    })


def _hunter_public_data(username):
    """Read-only public Hunter profile. Never auto-creates usernames."""
    conn = db()
    user = conn.execute("SELECT username, wallet, xp, streak FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        conn.close()
        return None

    xp = int(user["xp"] or 0)
    stages = [
        (0, 100, "🥚", "BL3 Seed", "DORMANT"),
        (100, 300, "👾", "Glitchling", "AWAKENED"),
        (300, 700, "😈", "Chaos Spawn", "EVOLVED"),
        (700, 1500, "🦹", "Alpha Beast", "ALPHA"),
        (1500, None, "👑", "Crown Entity", "ASCENDED"),
    ]
    selected = stages[0]
    for stage in stages:
        if xp >= stage[0]:
            selected = stage
    floor, ceiling, avatar, creature_name, creature_stage = selected
    if ceiling is None:
        evo_current = max(0, xp - floor)
        evo_target = max(1, evo_current)
        evo_percent = 100
    else:
        evo_current = max(0, xp - floor)
        evo_target = ceiling - floor
        evo_percent = round((evo_current / evo_target) * 100, 1)

    rep = conn.execute("SELECT COALESCE(SUM(points),0) AS n FROM reputation_events WHERE username = ?", (username,)).fetchone()["n"]
    network = conn.execute("SELECT COUNT(*) AS n FROM referrals WHERE inviter = ?", (username,)).fetchone()["n"]
    arena_wins = conn.execute("SELECT COUNT(*) AS n FROM arenas WHERE winner_username = ?", (username,)).fetchone()["n"]
    clash_wins = conn.execute("SELECT COUNT(*) AS n FROM creature_battles WHERE winner = ?", (username,)).fetchone()["n"]
    earned = conn.execute("SELECT COALESCE(SUM(bounty_amount),0) AS n FROM arenas WHERE winner_username = ? AND paid = 1", (username,)).fetchone()["n"]

    season_key = _current_season_key()
    board = _season_rows(conn, season_key)
    season_row = next((r for r in board if r["username"] == username), {"username": username, "wins": 0, "losses": 0, "battles": 0})
    season_rank = next((i for i, r in enumerate(board, 1) if r["username"] == username), None)
    win_streak = _season_win_streak(conn, username, season_key)
    crown = board[0]["username"] if board and int(board[0].get("wins") or 0) > 0 else None

    battles = conn.execute(
        """SELECT id, challenger, opponent, winner, challenger_power, opponent_power, commentary, created_at
           FROM creature_battles
           WHERE challenger = ? OR opponent = ?
           ORDER BY id DESC LIMIT 6""",
        (username, username)
    ).fetchall()
    recent = [dict(r) for r in battles]

    ranking = conn.execute("SELECT username FROM users ORDER BY xp DESC, username COLLATE NOCASE ASC").fetchall()
    xp_rank = next((i for i, r in enumerate(ranking, 1) if r["username"] == username), None)
    followers = conn.execute("SELECT COUNT(*) AS n FROM hunter_connections WHERE target = ? AND kind = 'follow'", (username,)).fetchone()["n"]
    following = conn.execute("SELECT COUNT(*) AS n FROM hunter_connections WHERE owner = ? AND kind = 'follow'", (username,)).fetchone()["n"]
    rivals = conn.execute("SELECT COUNT(*) AS n FROM hunter_connections WHERE owner = ? AND kind = 'rival'", (username,)).fetchone()["n"]
    conn.close()

    return {
        "username": username,
        "wallet_verified": bool(user["wallet"]),
        "xp": xp,
        "xp_rank": xp_rank,
        "streak": int(user["streak"] or 0),
        "level": max(1, xp // 100 + 1),
        "reputation": int(rep or 0),
        "network": int(network or 0),
        "wins": int(arena_wins or 0) + int(clash_wins or 0),
        "earned": float(earned or 0),
        "followers": int(followers or 0),
        "following": int(following or 0),
        "rivals": int(rivals or 0),
        "creature": {"avatar": avatar, "name": creature_name, "stage": creature_stage},
        "evolution": {"current": evo_current, "target": evo_target, "percent": evo_percent},
        "season": {
            "key": season_key,
            "rank": season_rank,
            "wins": int(season_row.get("wins") or 0),
            "losses": int(season_row.get("losses") or 0),
            "battles": int(season_row.get("battles") or 0),
            "win_streak": int(win_streak or 0),
            "is_crown": crown == username,
            "crown": crown,
        },
        "recent_battles": recent,
    }


@app.route("/api/hunter/<username>")
def hunter_public_api(username):
    data = _hunter_public_data(username)
    if data is None:
        return jsonify({"success": False, "message": "Hunter not found"}), 404
    return jsonify({"success": True, **data})


@app.route("/hunter/<username>/card.svg")
def hunter_profile_card_svg(username):
    d = _hunter_public_data(username)
    if d is None:
        return Response("Hunter not found", status=404, mimetype="text/plain")
    esc = lambda v: html.escape(str(v or ""))
    hunter_title = _hunter_title(username) or {"title": "HUNTER", "icon": "👾", "tier": "UNRANKED"}
    momentum = _momentum_state(d["season"]["win_streak"])
    showcase = _hunter_showcase(username) or {"featured": None}
    featured = showcase.get("featured")
    featured_nemesis_data = _featured_nemesis(username) or {"featured": None}
    card_nemesis = featured_nemesis_data.get("featured")
    card_nemesis_line = (
        f"FEATURED NEMESIS: {card_nemesis['rival']} // {card_nemesis['escalation']['tier']['label']}"
        if card_nemesis else "FEATURED NEMESIS: UNSET"
    )
    featured_line = (
        f"FEATURED: {featured['icon']} {featured['title']} // {featured['tier']}"
        if featured else "FEATURED: TROPHY ROOM AWAITS"
    )
    season_rank = f"#{d['season']['rank']}" if d['season']['rank'] else "—"
    crown = "CURRENT CROWN" if d['season']['is_crown'] else "HUNTER"
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
      <defs>
        <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop stop-color="{skin['bg0']}"/><stop offset=".55" stop-color="#141221"/><stop offset="1" stop-color="#09090e"/></linearGradient>
        <linearGradient id="accent" x1="0" y1="0" x2="1" y2="0"><stop stop-color="{skin['accent']}"/><stop offset="1" stop-color="{skin['accent2']}"/></linearGradient>
      </defs>
      <rect width="1200" height="630" rx="38" fill="url(#bg)"/>
      <rect x="34" y="34" width="1132" height="562" rx="30" fill="none" stroke="#30303a" stroke-width="2"/>
      <text x="70" y="92" fill="{skin['accent']}" font-family="Arial,sans-serif" font-size="26" font-weight="900">BL3 // PUBLIC HUNTER PROFILE</text>
      <text x="70" y="142" fill="#777785" font-family="Arial,sans-serif" font-size="18" letter-spacing="3">THE HUMAN ALPHA NETWORK // {esc(crown)}</text>
      <text x="72" y="258" fill="#ffffff" font-family="Arial,sans-serif" font-size="70" font-weight="950">{esc(d['username'])}</text>
      <text x="72" y="304" fill="{skin['accent']}" font-family="Arial,sans-serif" font-size="24" font-weight="900" letter-spacing="2">{esc(hunter_title['icon'])} {esc(hunter_title['title'])}</text>
      <text x="72" y="346" fill="url(#accent)" font-family="Arial,sans-serif" font-size="28" font-weight="900">{esc(d['creature']['avatar'])} {esc(d['creature']['name'])} // LVL {d['level']}</text>
      <text x="72" y="386" fill="#a7a7b6" font-family="Arial,sans-serif" font-size="22">{d['reputation']} REP   •   {d['xp']} XP   •   {d['wins']} WINS   •   {d['network']} NETWORK</text>
      <text x="72" y="421" fill="{skin['gold']}" font-family="Arial,sans-serif" font-size="18" font-weight="900">{esc(featured_line)}</text>
      <rect x="72" y="448" width="1056" height="1" fill="{skin['line']}"/>
      <text x="72" y="493" fill="#ffffff" font-family="Arial,sans-serif" font-size="21" font-weight="800">SEASON {esc(d['season']['key'])}</text>
      <text x="72" y="535" fill="{skin['accent2']}" font-family="Arial,sans-serif" font-size="25" font-weight="900">RANK {season_rank}   •   {d['season']['wins']}W / {d['season']['losses']}L   •   {d['season']['win_streak']} WIN STREAK</text>
      <text x="72" y="570" fill="{skin['accent']}" font-family="Arial,sans-serif" font-size="17" font-weight="900">{esc(momentum['icon'])} {esc(momentum['label'])}   //   {esc(card_nemesis_line)}</text>
      <text x="1128" y="570" fill="{skin['accent']}" font-family="Arial,sans-serif" font-size="17" font-weight="900" text-anchor="end">CHALLENGE THIS HUNTER →</text>
    </svg>"""
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "public, max-age=300"})


@app.route("/api/hunter/<username>/social")
def hunter_social_status(username):
    conn = db()
    exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    if exists is None:
        conn.close()
        return jsonify({"success": False, "message": "Hunter not found"}), 404
    viewer = session.get("authenticated_username") or ""
    followers = conn.execute("SELECT COUNT(*) AS n FROM hunter_connections WHERE target = ? AND kind = 'follow'", (username,)).fetchone()["n"]
    following = conn.execute("SELECT COUNT(*) AS n FROM hunter_connections WHERE owner = ? AND kind = 'follow'", (username,)).fetchone()["n"]
    rivals = conn.execute("SELECT COUNT(*) AS n FROM hunter_connections WHERE owner = ? AND kind = 'rival'", (username,)).fetchone()["n"]
    is_following = False
    is_rival = False
    if viewer:
        is_following = conn.execute("SELECT 1 FROM hunter_connections WHERE owner = ? AND target = ? AND kind = 'follow'", (viewer, username)).fetchone() is not None
        is_rival = conn.execute("SELECT 1 FROM hunter_connections WHERE owner = ? AND target = ? AND kind = 'rival'", (viewer, username)).fetchone() is not None
    conn.close()
    return jsonify({
        "success": True, "username": username, "viewer": viewer,
        "followers": int(followers or 0), "following": int(following or 0), "rivals": int(rivals or 0),
        "is_following": is_following, "is_rival": is_rival
    })


@app.route("/api/hunter/<username>/social", methods=["POST"])
def hunter_social_toggle(username):
    viewer = session.get("authenticated_username") or ""
    if not viewer:
        return jsonify({"success": False, "message": "🔐 Sign in with your verified wallet first."}), 401
    if viewer == username:
        return jsonify({"success": False, "message": "You cannot follow or rival yourself."}), 400
    data = request.get_json(silent=True) or {}
    kind = str(data.get("kind", "")).strip().lower()
    enabled = bool(data.get("enabled", True))
    if kind not in {"follow", "rival"}:
        return jsonify({"success": False, "message": "Invalid social connection."}), 400

    conn = db()
    exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    if exists is None:
        conn.close()
        return jsonify({"success": False, "message": "Hunter not found"}), 404

    if enabled:
        conn.execute(
            "INSERT OR IGNORE INTO hunter_connections (owner, target, kind, created_at) VALUES (?, ?, ?, ?)",
            (viewer, username, kind, datetime.utcnow().isoformat())
        )
        if kind == "follow":
            _notify(conn, username, "social", f"👁️ {viewer} followed you", "A Hunter started following your public profile.", f"/hunter/{urllib.parse.quote(viewer)}")
            message = f"👁️ Following {username}."
        else:
            _notify(conn, username, "rival", f"🎯 {viewer} marked you as a rival", "A Hunter added you to their Rival Network.", f"/hunter/{urllib.parse.quote(viewer)}")
            message = f"🎯 {username} added to your Rival Network."
    else:
        conn.execute("DELETE FROM hunter_connections WHERE owner = ? AND target = ? AND kind = ?", (viewer, username, kind))
        message = f"{username} removed from your {'Rival Network' if kind == 'rival' else 'following list'}."

    conn.commit()
    followers = conn.execute("SELECT COUNT(*) AS n FROM hunter_connections WHERE target = ? AND kind = 'follow'", (username,)).fetchone()["n"]
    conn.close()
    return jsonify({"success": True, "message": message, "followers": int(followers or 0), "kind": kind, "enabled": enabled})


@app.route("/api/social/me")
def social_me():
    viewer = session.get("authenticated_username") or ""
    if not viewer:
        return jsonify({"success": False, "message": "Sign in required"}), 401
    conn = db()
    rows = conn.execute(
        """SELECT hc.target, hc.kind, hc.created_at, u.xp
           FROM hunter_connections hc
           JOIN users u ON u.username = hc.target
           WHERE hc.owner = ?
           ORDER BY hc.id DESC""" if False else
        """SELECT hc.target, hc.kind, hc.created_at, u.xp
           FROM hunter_connections hc
           JOIN users u ON u.username = hc.target
           WHERE hc.owner = ?
           ORDER BY hc.created_at DESC""",
        (viewer,)
    ).fetchall()
    conn.close()
    return jsonify({"success": True, "username": viewer, "connections": [dict(r) for r in rows]})



def _rivalry_tier(total):
    """Canonical rivalry escalation tier used by every Feud surface."""
    total = int(total or 0)
    if total >= 12:
        return {"key": "legendary", "icon": "🌠", "label": "LEGENDARY FEUD", "level": 5, "next_at": None}
    if total >= 8:
        return {"key": "blood", "icon": "🩸", "label": "BLOOD FEUD", "level": 4, "next_at": 12}
    if total >= 5:
        return {"key": "nemesis", "icon": "😈", "label": "NEMESIS", "level": 3, "next_at": 8}
    if total >= 3:
        return {"key": "ignited", "icon": "🔥", "label": "RIVALRY IGNITED", "level": 2, "next_at": 5}
    if total >= 1:
        return {"key": "spark", "icon": "⚔️", "label": "FIRST BLOOD", "level": 1, "next_at": 3}
    return {"key": "dormant", "icon": "🎯", "label": "RIVALRY DORMANT", "level": 0, "next_at": 1}


def _rivalry_stakes(total, owner_wins, rival_wins, owner, rival, streak_holder=None, streak_count=0):
    """Narrative stakes for the next direct Clash. This does not create a wager or transfer value."""
    total = max(0, int(total or 0))
    owner_wins = max(0, int(owner_wins or 0))
    rival_wins = max(0, int(rival_wins or 0))
    owner = str(owner or "Hunter")
    rival = str(rival or "Rival")
    streak_holder = str(streak_holder or "")
    streak_count = max(0, int(streak_count or 0))

    tier = _rivalry_tier(total)
    next_tier = _rivalry_tier(total + 1)
    crosses_tier = int(next_tier.get("level") or 0) > int(tier.get("level") or 0)
    diff = owner_wins - rival_wins

    if diff < 0:
        headline = "TIE THE FEUD" if diff == -1 else "CLOSE THE GAP"
        detail = f"A win moves the record to {owner_wins + 1}-{rival_wins}."
    elif diff == 0:
        headline = "TAKE THE LEAD"
        detail = f"The next winner breaks the {owner_wins}-{rival_wins} tie."
    else:
        headline = "DEFEND THE LEAD"
        detail = f"A win extends your edge to {owner_wins + 1}-{rival_wins}."

    if streak_holder == rival and streak_count >= 2:
        headline = "BREAK THE STREAK"
        detail = f"{rival} has won {streak_count} straight direct Clashes."
    elif streak_holder == owner and streak_count >= 2:
        headline = "PROTECT THE STREAK"
        detail = f"You have won {streak_count} straight direct Clashes."

    if crosses_tier:
        headline = f"{next_tier.get('icon', '🔥')} TIER-UP CLASH"
        detail = f"The next completed direct Clash unlocks {next_tier.get('label', 'the next rivalry tier')}."

    level = int(tier.get("level") or 0)
    if level >= 5:
        key, icon, label, tone = "mythic", "🌠", "MYTHIC STAKES", "Every result writes another chapter into a Legendary Feud."
    elif level >= 4:
        key, icon, label, tone = "blood", "🩸", "BLOOD STAKES", "Streaks and lead swings now define the story."
    elif level >= 3:
        key, icon, label, tone = "nemesis", "😈", "NEMESIS STAKES", "This is a named feud. The next Clash changes who owns the pressure."
    elif level >= 2:
        key, icon, label, tone = "heated", "🔥", "HEATED STAKES", "Another result can turn pressure into a true Nemesis arc."
    elif level >= 1:
        key, icon, label, tone = "rematch", "⚔️", "REMATCH STAKES", "First Blood is on record. The next Clash decides whether this becomes a real feud."
    else:
        key, icon, label, tone = "scouting", "🎯", "SCOUTING", "No completed direct Clash exists yet."

    if owner_wins > rival_wins:
        pressure = f"{owner} leads {owner_wins}-{rival_wins}."
    elif rival_wins > owner_wins:
        pressure = f"{rival} leads {rival_wins}-{owner_wins}."
    else:
        pressure = f"The rivalry is tied {owner_wins}-{rival_wins}."

    return {
        "key": key, "icon": icon, "label": label, "tier_level": level,
        "headline": headline, "detail": detail, "tone": tone, "pressure": pressure,
        "crosses_tier": crosses_tier, "next_tier": next_tier if crosses_tier else None,
        "owner_if_win": {"owner": owner_wins + 1, "rival": rival_wins},
        "owner_if_loss": {"owner": owner_wins, "rival": rival_wins + 1},
        "streak_holder": streak_holder or None, "streak_count": streak_count
    }


def _build_rivalry_index(rows):
    """Single-pass all-time rivalry index from completed, valid direct Clashes."""
    pairs = {}
    for row in rows:
        challenger = str(row["challenger"] or "").strip()
        opponent = str(row["opponent"] or "").strip()
        winner = str(row["winner"] or "").strip()
        if not challenger or not opponent or challenger == opponent or winner not in (challenger, opponent):
            continue

        key = tuple(sorted((challenger, opponent), key=lambda s: s.lower()))
        a, b = key
        item = pairs.setdefault(key, {
            "hunter_a": a,
            "hunter_b": b,
            "clashes": 0,
            "score": {a: 0, b: 0},
            "leader": None,
            "lead_changes": 0,
            "biggest_lead": 0,
            "streak_holder": None,
            "streak_count": 0,
            "best_streak": {a: 0, b: 0},
            "last_winner": None,
            "last_battle_id": 0,
            "last_created_at": ""
        })

        item["clashes"] += 1
        item["score"][winner] += 1
        item["last_winner"] = winner
        item["last_battle_id"] = int(row["id"])
        item["last_created_at"] = row["created_at"] if "created_at" in row.keys() else ""

        if item["streak_holder"] == winner:
            item["streak_count"] += 1
        else:
            item["streak_holder"] = winner
            item["streak_count"] = 1
        item["best_streak"][winner] = max(
            int(item["best_streak"][winner]),
            int(item["streak_count"])
        )

        score_a = int(item["score"][a])
        score_b = int(item["score"][b])
        new_leader = a if score_a > score_b else b if score_b > score_a else None
        if item["leader"] and new_leader and new_leader != item["leader"]:
            item["lead_changes"] += 1
        if new_leader:
            item["leader"] = new_leader
        item["biggest_lead"] = max(int(item["biggest_lead"]), abs(score_a - score_b))

    return pairs


def _record_feud_escalation_event(conn, battle_id, hunter_a, hunter_b, winner, created_at):
    """Persist exactly one event when this Clash crosses a canonical Rivalry tier."""
    a, b = sorted((str(hunter_a or "").strip(), str(hunter_b or "").strip()), key=lambda x: x.lower())
    if not a or not b or a == b or winner not in (a, b):
        return None

    total = int(conn.execute(
        """SELECT COUNT(*) AS n FROM creature_battles
           WHERE ((challenger = ? AND opponent = ?) OR (challenger = ? AND opponent = ?))
             AND (winner = challenger OR winner = opponent)""",
        (a, b, b, a)
    ).fetchone()["n"] or 0)
    if total <= 0:
        return None

    old_tier = _rivalry_tier(total - 1)
    new_tier = _rivalry_tier(total)
    if int(new_tier.get("level") or 0) <= int(old_tier.get("level") or 0):
        return None

    cursor = conn.execute(
        """INSERT OR IGNORE INTO feud_events
           (battle_id, hunter_a, hunter_b, winner, old_tier_key, new_tier_key, tier_level, icon, label, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (int(battle_id), a, b, winner, old_tier.get("key") or "dormant", new_tier.get("key") or "spark",
         int(new_tier.get("level") or 0), new_tier.get("icon") or "⚔️", new_tier.get("label") or "RIVALRY", created_at)
    )
    if not cursor.rowcount:
        return None

    event = {
        "id": int(cursor.lastrowid),
        "battle_id": int(battle_id),
        "hunter_a": a,
        "hunter_b": b,
        "winner": winner,
        "old_tier_key": old_tier.get("key") or "dormant",
        "new_tier_key": new_tier.get("key") or "spark",
        "tier_level": int(new_tier.get("level") or 0),
        "icon": new_tier.get("icon") or "⚔️",
        "label": new_tier.get("label") or "RIVALRY",
        "created_at": created_at
    }

    # First Blood is public feed material; direct inbox alerts begin at Rivalry Ignited to avoid notification spam.
    if event["tier_level"] >= 2:
        detail = f"Your direct rivalry reached {event['label']} after Clash #{battle_id}."
        link = f"/rivalry/{urllib.parse.quote(a)}/{urllib.parse.quote(b)}"
        _notify(conn, a, "feud", f"{event['icon']} {event['label']}", detail, link)
        _notify(conn, b, "feud", f"{event['icon']} {event['label']}", detail, link)
    return event


def _record_feud_moment(conn, battle_id, challenger, opponent, winner, challenger_power, opponent_power, created_at):
    """Detect one strongest shareable story beat from the completed direct Clash."""
    challenger = str(challenger or "").strip()
    opponent = str(opponent or "").strip()
    winner = str(winner or "").strip()
    if not challenger or not opponent or challenger == opponent or winner not in (challenger, opponent):
        return None
    loser = opponent if winner == challenger else challenger
    a, b = sorted((challenger, opponent), key=lambda x: x.lower())

    rows = conn.execute(
        """SELECT id, challenger, opponent, winner, challenger_power, opponent_power
           FROM creature_battles
           WHERE ((challenger = ? AND opponent = ?) OR (challenger = ? AND opponent = ?))
             AND id <= ? AND (winner = challenger OR winner = opponent)
           ORDER BY id ASC""",
        (a, b, b, a, int(battle_id))
    ).fetchall()
    if not rows:
        return None

    prev = rows[:-1]
    score = {a: 0, b: 0}
    leader_before = None
    last_winner = None
    streak_holder = None
    streak_count = 0
    for r in prev:
        w = str(r["winner"] or "")
        if w not in score:
            continue
        score[w] += 1
        if streak_holder == w:
            streak_count += 1
        else:
            streak_holder, streak_count = w, 1
        last_winner = w
    if score[a] > score[b]: leader_before = a
    elif score[b] > score[a]: leader_before = b

    before_winner = int(score.get(winner, 0))
    before_loser = int(score.get(loser, 0))
    score[winner] = before_winner + 1
    leader_after = a if score[a] > score[b] else b if score[b] > score[a] else None

    winner_power = int(challenger_power if winner == challenger else opponent_power)
    loser_power = int(opponent_power if winner == challenger else challenger_power)
    candidates = []

    if leader_before and leader_after and leader_before != leader_after and leader_after == winner:
        candidates.append((5, "lead_flip", "🔄", "LEAD FLIP", f"{winner} flipped the all-time rivalry lead in Clash #{battle_id}."))
    if streak_holder == loser and streak_count >= 3:
        candidates.append((5, "streak_break", "💥", "STREAK BREAKER", f"{winner} snapped {loser}'s {streak_count}-Clash winning streak."))
    if winner_power < loser_power:
        gap = loser_power - winner_power
        intensity = 5 if gap >= 35 else 4 if gap >= 20 else 3
        candidates.append((intensity, "power_upset", "⚡", "POWER UPSET", f"{winner} won despite a {gap}-power disadvantage."))
    if last_winner == loser:
        candidates.append((3, "revenge", "🩸", "REVENGE WIN", f"{winner} answered the previous loss and took the rematch."))
    if before_winner + 2 <= before_loser:
        candidates.append((4, "comeback", "🔥", "COMEBACK STRIKE", f"{winner} struck back while trailing the feud {before_winner}-{before_loser}."))

    if not candidates:
        return None
    candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
    intensity, key, icon, label, detail = candidates[0]
    cursor = conn.execute(
        """INSERT OR IGNORE INTO feud_moments
           (battle_id, hunter_a, hunter_b, winner, loser, moment_key, icon, label, detail, intensity, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (int(battle_id), a, b, winner, loser, key, icon, label, detail, int(intensity), created_at)
    )
    if not cursor.rowcount:
        return None
    moment = {
        "id": int(cursor.lastrowid), "battle_id": int(battle_id), "hunter_a": a, "hunter_b": b,
        "winner": winner, "loser": loser, "moment_key": key, "icon": icon, "label": label,
        "detail": detail, "intensity": int(intensity), "created_at": created_at,
        "share_url": f"/clash/{int(battle_id)}",
        "card_url": f"/clash/{int(battle_id)}/card.svg"
    }
    if intensity >= 4:
        link = f"/clash/{int(battle_id)}"
        _notify(conn, winner, "feud_moment", f"{icon} {label}", detail, link)
        _notify(conn, loser, "feud_moment", f"{icon} {label}", detail, link)
    return moment


# V13.3 GLOBAL SEARCH builds on the process-local Feud snapshots. A tiny COUNT/MAX signature query protects
# against external DB changes while avoiding a full rivalry-history scan on every request.
_RIVALRY_CACHE_LOCK = threading.RLock()
_RIVALRY_CACHE = {}


def _rivalry_cache_signature(conn, season_key=None):
    if season_key:
        row = conn.execute(
            """SELECT COUNT(*) AS n, COALESCE(MAX(id), 0) AS max_id
               FROM creature_battles
               WHERE season_key = ?
                 AND (winner = challenger OR winner = opponent)""",
            (season_key,)
        ).fetchone()
    else:
        row = conn.execute(
            """SELECT COUNT(*) AS n, COALESCE(MAX(id), 0) AS max_id
               FROM creature_battles
               WHERE winner = challenger OR winner = opponent"""
        ).fetchone()
    return (int(row["n"] or 0), int(row["max_id"] or 0))


def _invalidate_rivalry_cache():
    with _RIVALRY_CACHE_LOCK:
        _RIVALRY_CACHE.clear()


def _rivalry_index_snapshot(season_key=None):
    cache_key = season_key or "__all_time__"
    conn = db()
    signature = _rivalry_cache_signature(conn, season_key)

    with _RIVALRY_CACHE_LOCK:
        cached = _RIVALRY_CACHE.get(cache_key)
        if cached and cached.get("signature") == signature:
            conn.close()
            return cached["pairs"], "hit"

    if season_key:
        rows = conn.execute(
            """SELECT id, challenger, opponent, winner, created_at
               FROM creature_battles
               WHERE season_key = ?
                 AND (winner = challenger OR winner = opponent)
               ORDER BY id ASC""",
            (season_key,)
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT id, challenger, opponent, winner, created_at
               FROM creature_battles
               WHERE winner = challenger OR winner = opponent
               ORDER BY id ASC"""
        ).fetchall()
    conn.close()

    pairs = _build_rivalry_index(rows)
    with _RIVALRY_CACHE_LOCK:
        _RIVALRY_CACHE[cache_key] = {"signature": signature, "pairs": pairs}
    return pairs, "miss"


def _rivalry_index():
    """Compatibility wrapper for callers that only need the all-time rivalry index."""
    pairs, _ = _rivalry_index_snapshot()
    return pairs

def _head_to_head(a, b, limit=6):
    """Read-only rivalry record between two existing Hunters."""
    if not a or not b or a == b:
        return {
            "a": a, "b": b, "total": 0, "a_wins": 0, "b_wins": 0,
            "leader": None, "last_winner": None, "recent": []
        }

    conn = db()
    rows = conn.execute(
        """SELECT id, challenger, opponent, winner, challenger_power, opponent_power,
                  commentary, created_at
           FROM creature_battles
           WHERE (
                    (challenger = ? AND opponent = ?)
                 OR (challenger = ? AND opponent = ?)
                 )
             AND winner IN (?, ?)
           ORDER BY id DESC LIMIT ?""",
        (a, b, b, a, a, b, max(1, min(int(limit or 6), 20)))
    ).fetchall()

    totals = conn.execute(
        """SELECT
             COUNT(*) AS total,
             SUM(CASE WHEN winner = ? THEN 1 ELSE 0 END) AS a_wins,
             SUM(CASE WHEN winner = ? THEN 1 ELSE 0 END) AS b_wins
           FROM creature_battles
           WHERE (
                    (challenger = ? AND opponent = ?)
                 OR (challenger = ? AND opponent = ?)
                 )
             AND winner IN (?, ?)""",
        (a, b, a, b, b, a, a, b)
    ).fetchone()
    conn.close()

    total = int(totals["total"] or 0)
    a_wins = int(totals["a_wins"] or 0)
    b_wins = int(totals["b_wins"] or 0)
    leader = a if a_wins > b_wins else b if b_wins > a_wins else None
    recent = [dict(r) for r in rows]
    last_winner = recent[0]["winner"] if recent else None

    return {
        "a": a, "b": b, "total": total, "a_wins": a_wins, "b_wins": b_wins,
        "leader": leader, "last_winner": last_winner, "recent": recent
    }



def _rivalry_milestones(a, b):
    """Derive rivalry badges from immutable battle history. No extra XP is minted."""
    conn = db()
    rows = conn.execute(
        """SELECT id, winner, challenger, opponent, created_at
           FROM creature_battles
           WHERE (
                    (challenger = ? AND opponent = ?)
                 OR (challenger = ? AND opponent = ?)
                 )
             AND winner IN (?, ?)
           ORDER BY id ASC""",
        (a, b, b, a, a, b)
    ).fetchall()
    conn.close()

    if not rows:
        return []

    badges = []
    first_winner = rows[0]["winner"]
    badges.append({
        "key": "first_blood",
        "icon": "🩸",
        "title": "FIRST BLOOD",
        "detail": f"{first_winner} won the first Clash."
    })

    score = {a: 0, b: 0}
    max_lead = {a: 0, b: 0}
    trailed_by_two = {a: False, b: False}
    comeback_hunter = None
    streak_owner = None
    streak = 0
    max_streak = {a: 0, b: 0}

    for row in rows:
        winner = row["winner"]
        loser = b if winner == a else a
        score[winner] += 1

        lead_a = score[a] - score[b]
        lead_b = score[b] - score[a]
        max_lead[a] = max(max_lead[a], lead_a)
        max_lead[b] = max(max_lead[b], lead_b)

        if lead_a <= -2:
            trailed_by_two[a] = True
        if lead_b <= -2:
            trailed_by_two[b] = True

        if streak_owner == winner:
            streak += 1
        else:
            streak_owner = winner
            streak = 1
        max_streak[winner] = max(max_streak[winner], streak)

        # Comeback: Hunter had trailed by 2+, later reached tie or took lead.
        if trailed_by_two[winner] and score[winner] >= score[loser]:
            comeback_hunter = winner

    total = len(rows)
    final_a, final_b = score[a], score[b]

    if total >= 3:
        badges.append({
            "key": "rivalry_live",
            "icon": "🔥",
            "title": "RIVALRY IGNITED",
            "detail": f"{total} direct Clashes and counting."
        })

    if total >= 5:
        badges.append({
            "key": "nemesis",
            "icon": "😈",
            "title": "NEMESIS",
            "detail": "Five or more direct Clashes. This is personal now."
        })

    dominant = a if final_a - final_b >= 3 else b if final_b - final_a >= 3 else None
    if dominant:
        badges.append({
            "key": "three_win_lead",
            "icon": "👑",
            "title": "3-WIN LEAD",
            "detail": f"{dominant} leads the rivalry by at least three wins."
        })

    streak_hunter = a if max_streak[a] >= 3 and max_streak[a] >= max_streak[b] else b if max_streak[b] >= 3 else None
    if streak_hunter:
        badges.append({
            "key": "hot_streak",
            "icon": "⚡",
            "title": "HOT STREAK",
            "detail": f"{streak_hunter} recorded {max_streak[streak_hunter]} straight rivalry wins."
        })

    if comeback_hunter:
        badges.append({
            "key": "comeback",
            "icon": "🧨",
            "title": "COMEBACK",
            "detail": f"{comeback_hunter} erased a two-win deficit and came back."
        })

    if total >= 2 and final_a == final_b:
        badges.append({
            "key": "dead_even",
            "icon": "⚖️",
            "title": "DEAD EVEN",
            "detail": f"The rivalry is tied {final_a}-{final_b}."
        })

    return badges


def _rivalry_chronicle(hunter_a, hunter_b):
    conn = db()
    rows = conn.execute(
        """SELECT id, challenger, opponent, winner, commentary, created_at
           FROM creature_battles
           WHERE (
                    (challenger = ? AND opponent = ?)
                 OR (challenger = ? AND opponent = ?)
                 )
             AND winner IN (?, ?)
           ORDER BY id ASC""",
        (hunter_a, hunter_b, hunter_b, hunter_a, hunter_a, hunter_b)
    ).fetchall()
    conn.close()

    events = []
    score = {hunter_a: 0, hunter_b: 0}
    leader = None
    current_streak_holder = None
    current_streak = 0
    longest = {hunter_a: 0, hunter_b: 0}
    first_blood = None
    lead_changes = 0
    biggest_lead = 0
    comeback_hunter = None

    # Once a Hunter has been down by 2+, arm their comeback.
    comeback_armed = {hunter_a: False, hunter_b: False}
    comeback_from = {hunter_a: 0, hunter_b: 0}
    completed_comebacks = {hunter_a: 0, hunter_b: 0}

    for completed_idx, row in enumerate(rows, 1):
        winner = str(row["winner"] or "")
        if winner not in score:
            continue

        loser = hunter_b if winner == hunter_a else hunter_a
        score[winner] += 1

        # First Blood.
        if first_blood is None:
            first_blood = winner
            events.append({
                "kind": "first_blood",
                "icon": "⚔️",
                "title": "FIRST BLOOD",
                "detail": f"{winner} took the first direct Clash.",
                "battle_id": int(row["id"]),
                "created_at": row["created_at"]
            })

        # Streak tracking.
        if current_streak_holder == winner:
            current_streak += 1
        else:
            current_streak_holder = winner
            current_streak = 1
        longest[winner] = max(longest[winner], current_streak)

        if current_streak in (3, 5):
            events.append({
                "kind": "streak",
                "icon": "🔥" if current_streak == 3 else "🩸",
                "title": f"{current_streak}-WIN RIVALRY STREAK",
                "detail": f"{winner} won {current_streak} direct Clashes in a row.",
                "battle_id": int(row["id"]),
                "created_at": row["created_at"]
            })

        # Leader changes.
        new_leader = None
        if score[hunter_a] > score[hunter_b]:
            new_leader = hunter_a
        elif score[hunter_b] > score[hunter_a]:
            new_leader = hunter_b

        if leader and new_leader and new_leader != leader:
            lead_changes += 1
            events.append({
                "kind": "lead_change",
                "icon": "🔄",
                "title": "LEAD CHANGED HANDS",
                "detail": f"{new_leader} moved ahead {score[hunter_a]}-{score[hunter_b]}.",
                "battle_id": int(row["id"]),
                "created_at": row["created_at"]
            })
        if new_leader:
            leader = new_leader

        # Gap / comeback state after this completed Clash.
        a_deficit = score[hunter_b] - score[hunter_a]
        b_deficit = score[hunter_a] - score[hunter_b]
        biggest_lead = max(biggest_lead, abs(a_deficit))

        if a_deficit >= 2:
            comeback_armed[hunter_a] = True
            comeback_from[hunter_a] = max(comeback_from[hunter_a], a_deficit)
        if b_deficit >= 2:
            comeback_armed[hunter_b] = True
            comeback_from[hunter_b] = max(comeback_from[hunter_b], b_deficit)

        # A comeback completes when a previously armed Hunter reaches tie or takes the lead.
        if comeback_armed[winner] and score[winner] >= score[loser]:
            deficit = int(comeback_from[winner] or 2)
            comeback_hunter = winner
            completed_comebacks[winner] += 1
            events.append({
                "kind": "comeback",
                "icon": "🧨",
                "title": "COMEBACK COMPLETED",
                "detail": f"{winner} erased a {deficit}-win deficit and reached level or better.",
                "battle_id": int(row["id"]),
                "created_at": row["created_at"]
            })
            comeback_armed[winner] = False
            comeback_from[winner] = 0

        # Escalation milestones use completed direct Clashes only.
        tier_map = {
            3: ("🔥", "RIVALRY IGNITED"),
            5: ("😈", "NEMESIS"),
            8: ("🩸", "BLOOD FEUD"),
            12: ("🌠", "LEGENDARY FEUD"),
        }
        if completed_idx in tier_map:
            icon, title = tier_map[completed_idx]
            events.append({
                "kind": "tier",
                "icon": icon,
                "title": title,
                "detail": f"The rivalry reached {completed_idx} completed direct Clashes.",
                "battle_id": int(row["id"]),
                "created_at": row["created_at"]
            })

    events.sort(key=lambda e: int(e.get("battle_id") or 0), reverse=True)

    return {
        "hunter_a": hunter_a,
        "hunter_b": hunter_b,
        "total": len(rows),
        "score": {
            hunter_a: score[hunter_a],
            hunter_b: score[hunter_b]
        },
        "first_blood": first_blood,
        "lead_changes": int(lead_changes),
        "biggest_lead": int(biggest_lead),
        "longest_streaks": {
            hunter_a: int(longest[hunter_a]),
            hunter_b: int(longest[hunter_b])
        },
        "comeback_hunter": comeback_hunter,
        "completed_comebacks": {
            hunter_a: int(completed_comebacks[hunter_a]),
            hunter_b: int(completed_comebacks[hunter_b])
        },
        "events": events[:12]
    }


def _season_feud_spotlight():
    season_key = _current_season_key()
    pairs, season_cache = _rivalry_index_snapshot(season_key)
    if not pairs:
        return {
            "season_key": season_key,
            "spotlight": None,
            "engine": "snapshot-discovery-v13.2",
            "cache": {"season": season_cache, "all_time": "not-needed"}
        }

    # Primary rank is current-season completed direct Clash count.
    max_clashes = max(int(item["clashes"]) for item in pairs.values())
    finalists = [
        (key, item)
        for key, item in pairs.items()
        if int(item["clashes"]) == max_clashes
    ]

    # V12.3: cached all-time snapshot serves every tied finalist. No per-finalist
    # Chronicle/Escalation DB scans are needed for the tie-break anymore.
    all_time, all_time_cache = _rivalry_index_snapshot() if finalists else ({}, "not-needed")
    ranked = []
    for (a, b), base in finalists:
        lifetime = all_time.get((a, b), {})
        all_time_clashes = int(lifetime.get("clashes") or 0)
        ranked.append({
            "hunter_a": a,
            "hunter_b": b,
            "clashes": int(base["clashes"]),
            "season_score_a": int(base["score"][a]),
            "season_score_b": int(base["score"][b]),
            "last_battle_id": int(base["last_battle_id"]),
            "last_winner": base["last_winner"],
            "last_created_at": base.get("last_created_at") or "",
            "lead_changes_all_time": int(lifetime.get("lead_changes") or 0),
            "tier": _rivalry_tier(all_time_clashes),
            "all_time_clashes": all_time_clashes,
            "chronicle_card": f"/rivalry/{urllib.parse.quote(a)}/{urllib.parse.quote(b)}/chronicle.svg",
            "rivalry_url": f"/rivalry/{urllib.parse.quote(a)}/{urllib.parse.quote(b)}"
        })

    ranked.sort(
        key=lambda r: (
            int(r["lead_changes_all_time"]),
            int(r["all_time_clashes"]),
            int(r["last_battle_id"])
        ),
        reverse=True
    )

    return {
        "season_key": season_key,
        "spotlight": ranked[0],
        "engine": "snapshot-discovery-v13.2",
        "cache": {"season": season_cache, "all_time": all_time_cache}
    }


@app.route("/api/feud-live-state")
def feud_live_state_api():
    """Tiny cross-client version probe for Hall/Spotlight live refreshes."""
    season_key = _current_season_key()
    conn = db()
    all_time_sig = _rivalry_cache_signature(conn)
    season_sig = _rivalry_cache_signature(conn, season_key)
    feud_event_row = conn.execute("SELECT COALESCE(MAX(id), 0) AS n FROM feud_events").fetchone()
    latest_feud_event_id = int(feud_event_row["n"] or 0)
    feud_moment_row = conn.execute("SELECT COALESCE(MAX(id), 0) AS n FROM feud_moments").fetchone()
    latest_feud_moment_id = int(feud_moment_row["n"] or 0)
    conn.close()
    latest_battle_id = max(int(all_time_sig[1]), int(season_sig[1]))
    version = f"{all_time_sig[0]}:{all_time_sig[1]}:{season_sig[0]}:{season_sig[1]}:{latest_feud_event_id}:{latest_feud_moment_id}"
    return jsonify({
        "success": True,
        "season_key": season_key,
        "version": version,
        "latest_battle_id": latest_battle_id,
        "latest_feud_event_id": latest_feud_event_id,
        "latest_feud_moment_id": latest_feud_moment_id,
        "all_time_completed": int(all_time_sig[0]),
        "season_completed": int(season_sig[0]),
        "engine": "discovery-v13.2",
        "poll_after_ms": 12000
    })


@app.route("/api/feud-events")
def feud_events_api():
    try:
        limit = max(1, min(25, int(request.args.get("limit", 10))))
    except (TypeError, ValueError):
        limit = 10
    conn = db()
    rows = conn.execute(
        """SELECT id, battle_id, hunter_a, hunter_b, winner, old_tier_key, new_tier_key,
                  tier_level, icon, label, created_at
           FROM feud_events ORDER BY id DESC LIMIT ?""",
        (limit,)
    ).fetchall()
    total = int(conn.execute("SELECT COUNT(*) AS n FROM feud_events").fetchone()["n"] or 0)
    conn.close()
    return jsonify({
        "success": True,
        "events": [dict(r) for r in rows],
        "total_events": total,
        "engine": "discovery-v13.2"
    })


def _trend_label(score):
    score = int(score or 0)
    if score >= 220:
        return "🔥 ON FIRE"
    if score >= 140:
        return "⚡ SURGING"
    if score >= 80:
        return "📈 RISING"
    return "👀 WATCHING"


def _trending_feud_rows(limit=6, window_hours=168):
    """Derived viral leaderboard. No paid boosts, wallet value, or identity weighting."""
    limit = max(1, min(12, int(limit or 6)))
    window_hours = max(1, min(24 * 30, int(window_hours or 168)))
    cutoff = (datetime.utcnow() - timedelta(hours=window_hours)).isoformat()
    conn = db()
    rows = conn.execute(
        """SELECT m.id, m.hunter_a, m.hunter_b, m.intensity, m.created_at,
                  COUNT(v.id) AS viral_clicks,
                  SUM(CASE WHEN v.action_key IN ('challenge-winner','challenge-rival') THEN 1 ELSE 0 END) AS challenge_intent,
                  SUM(CASE WHEN v.action_key = 'open-clash' THEN 1 ELSE 0 END) AS open_clash
           FROM feud_moments m
           LEFT JOIN feud_viral_clicks v ON v.moment_id = m.id
           WHERE m.created_at >= ?
           GROUP BY m.id
           ORDER BY m.id DESC""",
        (cutoff,)
    ).fetchall()
    conn.close()

    now = datetime.utcnow()
    pairs = {}
    for row in rows:
        a = str(row["hunter_a"] or "").strip()
        b = str(row["hunter_b"] or "").strip()
        if not a or not b or a == b:
            continue
        key = tuple(sorted((a, b), key=lambda x: x.lower()))
        try:
            created = datetime.fromisoformat(str(row["created_at"] or ""))
            age_hours = max(0.0, (now - created).total_seconds() / 3600.0)
        except Exception:
            age_hours = float(window_hours)
        freshness = max(0, int(round(24 * (1 - min(age_hours, window_hours) / window_hours))))
        intensity = max(1, min(5, int(row["intensity"] or 1)))
        clicks = int(row["viral_clicks"] or 0)
        challenge = int(row["challenge_intent"] or 0)
        opens = int(row["open_clash"] or 0)
        # Story quality dominates; organic actions add momentum; freshness prevents stale monopolies.
        moment_score = intensity * 20 + clicks * 3 + challenge * 8 + opens * 2 + freshness
        item = pairs.setdefault(key, {
            "hunter_a": key[0], "hunter_b": key[1], "trend_score": 0, "moments": 0,
            "viral_clicks": 0, "challenge_intent": 0, "open_clash": 0,
            "max_heat": 0, "latest_at": ""
        })
        item["trend_score"] += int(moment_score)
        item["moments"] += 1
        item["viral_clicks"] += clicks
        item["challenge_intent"] += challenge
        item["open_clash"] += opens
        item["max_heat"] = max(item["max_heat"], intensity)
        item["latest_at"] = max(item["latest_at"], str(row["created_at"] or ""))

    ranked = list(pairs.values())
    ranked.sort(key=lambda r: (int(r["trend_score"]), int(r["challenge_intent"]), int(r["viral_clicks"]), r["latest_at"]), reverse=True)
    for item in ranked:
        item["trend_label"] = _trend_label(item["trend_score"])
        item["rivalry_url"] = f"/rivalry/{urllib.parse.quote(item['hunter_a'])}/{urllib.parse.quote(item['hunter_b'])}"
    return ranked[:limit]


@app.route("/api/trending-feuds")
def trending_feuds_api():
    try:
        limit = int(request.args.get("limit", 6))
    except (TypeError, ValueError):
        limit = 6
    try:
        window_hours = int(request.args.get("window_hours", 168))
    except (TypeError, ValueError):
        window_hours = 168
    limit = max(1, min(12, limit))
    window_hours = max(1, min(24 * 30, window_hours))
    rows = _trending_feud_rows(limit=limit, window_hours=window_hours)
    return jsonify({
        "success": True,
        "feuds": rows,
        "window_hours": window_hours,
        "method": "Trend Score = story heat + organic CTA activity + challenge intent + freshness. No paid boosts or wallet weighting.",
        "engine": "discovery-v13.2"
    })


def _discovery_reason(feud):
    label = str(feud.get("trend_label") or "WATCHING")
    moments = int(feud.get("moments") or 0)
    challenge = int(feud.get("challenge_intent") or 0)
    clicks = int(feud.get("viral_clicks") or 0)
    if "ON FIRE" in label:
        return f"Network reaction is peaking: {moments} story moments and {challenge} challenge intents in the active window."
    if "SURGING" in label:
        return f"This Feud is accelerating with {clicks} CTA reactions and {challenge} challenge intents."
    if challenge > 0:
        return f"Viewers are converting into challengers: {challenge} challenge intents across {moments} recent moments."
    return f"Fresh story activity is building: {moments} recent moment{'s' if moments != 1 else ''} in the discovery window."


def _discovery_engine_rows(feud_limit=4, hunter_limit=6, window_hours=168):
    """Public discovery from BL3-native activity only. No wallet value or paid placement."""
    feud_limit = max(1, min(8, int(feud_limit or 4)))
    hunter_limit = max(1, min(12, int(hunter_limit or 6)))
    window_hours = max(1, min(24 * 30, int(window_hours or 168)))

    # Pull a slightly wider trend set so Hunter discovery does not mirror only the top card.
    trend_rows = _trending_feud_rows(limit=max(12, feud_limit), window_hours=window_hours)
    feuds = []
    hunter_scores = {}
    for rank, row in enumerate(trend_rows, start=1):
        item = dict(row)
        a = str(item.get("hunter_a") or "").strip()
        b = str(item.get("hunter_b") or "").strip()
        item["discovery_reason"] = _discovery_reason(item)
        item["challenge_a_url"] = "/?challenge=" + urllib.parse.quote(a) + "&source=discovery-v13"
        item["challenge_b_url"] = "/?challenge=" + urllib.parse.quote(b) + "&source=discovery-v13"
        item["discovery_rank"] = rank
        if rank <= feud_limit:
            feuds.append(item)

        base = int(item.get("trend_score") or 0)
        intent = int(item.get("challenge_intent") or 0)
        moments = int(item.get("moments") or 0)
        clicks = int(item.get("viral_clicks") or 0)
        heat = int(item.get("max_heat") or 0)
        for hunter, rival in ((a, b), (b, a)):
            if not hunter:
                continue
            h = hunter_scores.setdefault(hunter, {
                "username": hunter, "discovery_score": 0, "feud_count": 0,
                "challenge_intent": 0, "moments": 0, "viral_clicks": 0,
                "max_heat": 0, "rivals": set(), "hottest_feud": ""
            })
            # Trend score carries the story signal; intent and heat reward actual interaction.
            contribution = max(1, base // 2) + intent * 4 + heat * 8
            h["discovery_score"] += contribution
            h["feud_count"] += 1
            h["challenge_intent"] += intent
            h["moments"] += moments
            h["viral_clicks"] += clicks
            h["max_heat"] = max(h["max_heat"], heat)
            h["rivals"].add(rival)
            if not h["hottest_feud"]:
                h["hottest_feud"] = rival

    # Add identity context in one pass. If the trend graph is empty, bootstrap with top XP Hunters
    # so first-time visitors still have somewhere to start.
    conn = db()
    names = list(hunter_scores.keys())
    if not names:
        seed_rows = conn.execute("SELECT username, xp FROM users ORDER BY xp DESC LIMIT ?", (hunter_limit,)).fetchall()
        for r in seed_rows:
            hunter_scores[r["username"]] = {
                "username": r["username"], "discovery_score": 0, "feud_count": 0,
                "challenge_intent": 0, "moments": 0, "viral_clicks": 0,
                "max_heat": 0, "rivals": set(), "hottest_feud": ""
            }
        names = list(hunter_scores.keys())

    user_map = {}
    rep_map = {}
    win_map = {}
    if names:
        ph = ",".join("?" for _ in names)
        for r in conn.execute(f"SELECT username, xp FROM users WHERE username IN ({ph})", names).fetchall():
            user_map[r["username"]] = int(r["xp"] or 0)
        for r in conn.execute(f"SELECT username, COALESCE(SUM(points),0) AS n FROM reputation_events WHERE username IN ({ph}) GROUP BY username", names).fetchall():
            rep_map[r["username"]] = int(r["n"] or 0)
        for r in conn.execute(f"SELECT winner AS username, COUNT(*) AS n FROM creature_battles WHERE winner IN ({ph}) GROUP BY winner", names).fetchall():
            win_map[r["username"]] = int(r["n"] or 0)
    conn.close()

    hunters = []
    for name, h in hunter_scores.items():
        xp = int(user_map.get(name, 0))
        creature = _creature_from_xp(xp)
        rival_count = len(h["rivals"])
        if h["feud_count"]:
            why = f"{h['feud_count']} active Feud{'s' if h['feud_count'] != 1 else ''} · {h['moments']} Moments · {h['challenge_intent']} challenge intents"
        else:
            why = "Established Hunter waiting for the next live story."
        hunters.append({
            "username": name,
            "xp": xp,
            "level": max(1, (xp // 100) + 1),
            "avatar": creature["avatar"],
            "reputation": int(rep_map.get(name, 0)),
            "wins": int(win_map.get(name, 0)),
            "discovery_score": int(h["discovery_score"]),
            "feud_count": int(h["feud_count"]),
            "rival_count": rival_count,
            "challenge_intent": int(h["challenge_intent"]),
            "max_heat": int(h["max_heat"]),
            "why_now": why,
            "profile_url": "/hunter/" + urllib.parse.quote(name),
            "challenge_url": "/?challenge=" + urllib.parse.quote(name) + "&source=discovery-v13"
        })

    hunters.sort(key=lambda h: (int(h["discovery_score"]), int(h["challenge_intent"]), int(h["reputation"]), int(h["xp"])), reverse=True)
    return feuds, hunters[:hunter_limit]



def _personalized_discovery(username, feud_limit=4, hunter_limit=6, window_hours=168):
    """Personal relevance layered on public discovery. Uses BL3-native behavior only."""
    feud_limit = max(1, min(8, int(feud_limit or 4)))
    hunter_limit = max(1, min(12, int(hunter_limit or 6)))
    window_hours = max(1, min(24 * 30, int(window_hours or 168)))

    public_feuds, public_hunters = _discovery_engine_rows(max(8, feud_limit), max(12, hunter_limit), window_hours)
    conn = db()
    me = conn.execute("SELECT username, xp FROM users WHERE username = ?", (username,)).fetchone()
    if me is None:
        conn.close()
        return None
    my_xp = int(me["xp"] or 0)

    tracked_rivals = {r["target"] for r in conn.execute(
        "SELECT target FROM hunter_connections WHERE owner = ? AND kind = 'rival'", (username,)
    ).fetchall()}
    followed = {r["target"] for r in conn.execute(
        "SELECT target FROM hunter_connections WHERE owner = ? AND kind = 'follow'", (username,)
    ).fetchall()}

    battle_rows = conn.execute(
        """SELECT id, challenger, opponent, winner FROM creature_battles
           WHERE challenger = ? OR opponent = ? ORDER BY id DESC LIMIT 400""",
        (username, username)
    ).fetchall()
    history = {}
    for r in battle_rows:
        rival = r["opponent"] if r["challenger"] == username else r["challenger"]
        h = history.setdefault(rival, {"clashes": 0, "wins": 0, "losses": 0, "last_winner": None})
        h["clashes"] += 1
        if h["last_winner"] is None:
            h["last_winner"] = r["winner"]
        if r["winner"] == username:
            h["wins"] += 1
        elif r["winner"] == rival:
            h["losses"] += 1

    # Add Hunters not currently trending so personalized discovery can surface a clean first matchup.
    candidate_rows = conn.execute(
        "SELECT username, xp FROM users WHERE username <> ? ORDER BY xp DESC LIMIT 80", (username,)
    ).fetchall()
    rep_rows = conn.execute(
        "SELECT username, COALESCE(SUM(points),0) AS n FROM reputation_events GROUP BY username"
    ).fetchall()
    rep_map = {r["username"]: int(r["n"] or 0) for r in rep_rows}
    win_rows = conn.execute(
        "SELECT winner AS username, COUNT(*) AS n FROM creature_battles GROUP BY winner"
    ).fetchall()
    win_map = {r["username"]: int(r["n"] or 0) for r in win_rows}
    conn.close()

    base_map = {h["username"]: dict(h) for h in public_hunters if h.get("username") != username}
    for r in candidate_rows:
        name = str(r["username"] or "").strip()
        if not name or name == username:
            continue
        if name not in base_map:
            xp = int(r["xp"] or 0)
            creature = _creature_from_xp(xp)
            base_map[name] = {
                "username": name, "xp": xp, "level": max(1, xp // 100 + 1),
                "avatar": creature["avatar"], "reputation": int(rep_map.get(name, 0)),
                "wins": int(win_map.get(name, 0)), "discovery_score": 0, "feud_count": 0,
                "rival_count": 0, "challenge_intent": 0, "max_heat": 0,
                "why_now": "Available for a fresh direct Clash.",
                "profile_url": "/hunter/" + urllib.parse.quote(name),
                "challenge_url": "/?challenge=" + urllib.parse.quote(name) + "&source=discovery-v13.2"
            }

    personalized_hunters = []
    for name, h in base_map.items():
        xp = int(h.get("xp") or 0)
        gap = abs(my_xp - xp)
        hist = history.get(name, {"clashes": 0, "wins": 0, "losses": 0, "last_winner": None})
        score = min(45, int(h.get("discovery_score") or 0) // 3)
        reasons = []

        # A close XP band is readable and fair-feeling without being a hidden power guarantee.
        proximity = max(0, 40 - min(40, gap // 15))
        score += proximity
        if gap <= 150:
            reasons.append("close power band")

        if hist["clashes"] == 0:
            score += 36
            reasons.append("fresh matchup")
        else:
            score += max(0, 18 - min(18, hist["clashes"] * 3))
            if hist["last_winner"] == name:
                score += 24
                reasons.append("revenge opportunity")
            elif hist["last_winner"] == username:
                reasons.append("defend your edge")

        if name in tracked_rivals:
            score += 32
            reasons.append("tracked rival")
        elif name in followed:
            score += 12
            reasons.append("you follow this Hunter")

        item = dict(h)
        item["personal_score"] = int(score)
        item["power_gap"] = int(gap)
        item["direct_clashes"] = int(hist["clashes"])
        item["personal_reason"] = " · ".join(reasons[:3]) or "network momentum match"
        item["challenge_url"] = "/?challenge=" + urllib.parse.quote(name) + "&source=discovery-v13.2"
        personalized_hunters.append(item)

    personalized_hunters.sort(
        key=lambda h: (int(h["personal_score"]), int(h.get("discovery_score") or 0), int(h.get("reputation") or 0)),
        reverse=True
    )

    personalized_feuds = []
    for f in public_feuds:
        a, b = str(f.get("hunter_a") or ""), str(f.get("hunter_b") or "")
        personal = 0
        reasons = []
        if username in (a, b):
            personal += 80
            reasons.append("your active Feud")
        other_names = {a, b} - {username}
        if tracked_rivals.intersection(other_names):
            personal += 45
            reasons.append("features a tracked rival")
        if followed.intersection(other_names):
            personal += 15
            reasons.append("features a Hunter you follow")
        item = dict(f)
        item["personal_rank_score"] = int(item.get("trend_score") or 0) + personal
        item["personal_reason"] = " · ".join(reasons)
        item["challenge_a_url"] = "/?challenge=" + urllib.parse.quote(a) + "&source=discovery-v13.2"
        item["challenge_b_url"] = "/?challenge=" + urllib.parse.quote(b) + "&source=discovery-v13.2"
        personalized_feuds.append(item)
    personalized_feuds.sort(key=lambda f: (int(f["personal_rank_score"]), int(f.get("trend_score") or 0)), reverse=True)

    return {
        "feuds": personalized_feuds[:feud_limit],
        "hunters": personalized_hunters[:hunter_limit],
        "window_hours": window_hours,
        "empty_state": {
            "feud_title": "Your Feud graph is still quiet.",
            "feud_detail": "Start one direct Clash or mark a Hunter as a Rival and BL3 will turn that relationship into a personal story feed.",
            "feud_action_label": "START A CLASH",
            "feud_action_url": "#clashCard",
            "hunter_title": "No strong personal match surfaced yet.",
            "hunter_detail": "Use Network Heat or a Hunter profile to seed your graph. Personalized Discovery improves after real interactions.",
            "hunter_action_label": "SCAN NETWORK HEAT",
            "hunter_action_url": "#networkHeatmap"
        }
    }


@app.route("/api/personalized-discovery/<username>")
def personalized_discovery_api(username):
    if session.get("authenticated_username") != username:
        return jsonify({"success": False, "message": "Sign in with this Hunter ID for personalized Discovery."}), 401
    try:
        feud_limit = int(request.args.get("feuds", 4))
    except (TypeError, ValueError):
        feud_limit = 4
    try:
        hunter_limit = int(request.args.get("hunters", 6))
    except (TypeError, ValueError):
        hunter_limit = 6
    try:
        window_hours = int(request.args.get("window_hours", 168))
    except (TypeError, ValueError):
        window_hours = 168
    data = _personalized_discovery(username, feud_limit, hunter_limit, window_hours)
    if data is None:
        return jsonify({"success": False, "message": "Hunter not found"}), 404
    return jsonify({
        "success": True,
        "personalized": True,
        **data,
        "method": "Personal relevance = public BL3 story momentum + direct Clash history + tracked rivals + XP proximity. No wallet-value weighting or paid placement.",
        "engine": "personalized-discovery-v13.2"
    })


@app.route("/api/discovery-engine")
def discovery_engine_api():
    try:
        feud_limit = int(request.args.get("feuds", 4))
    except (TypeError, ValueError):
        feud_limit = 4
    try:
        hunter_limit = int(request.args.get("hunters", 6))
    except (TypeError, ValueError):
        hunter_limit = 6
    try:
        window_hours = int(request.args.get("window_hours", 168))
    except (TypeError, ValueError):
        window_hours = 168
    feud_limit = max(1, min(8, feud_limit))
    hunter_limit = max(1, min(12, hunter_limit))
    window_hours = max(1, min(24 * 30, window_hours))
    feuds, hunters = _discovery_engine_rows(feud_limit, hunter_limit, window_hours)
    return jsonify({
        "success": True,
        "personalized": False,
        "feuds": feuds,
        "hunters": hunters,
        "window_hours": window_hours,
        "empty_state": {
            "feud_title": "No public Feud is trending yet.",
            "feud_detail": "A completed Clash can create a Moment; shared Moments and challenge intent seed the public Discovery graph.",
            "feud_action_label": "OPEN LIVE ARENAS",
            "feud_action_url": "#arenaSection",
            "hunter_title": "The Hunter graph is still warming up.",
            "hunter_detail": "Load a Hunter profile, explore Network Heat, or create the first matchup worth watching.",
            "hunter_action_label": "SCAN NETWORK HEAT",
            "hunter_action_url": "#networkHeatmap"
        },
        "method": "Discovery ranks BL3-native story momentum and interaction only. No paid placement or wallet-value weighting.",
        "engine": "discovery-v13.2"
    })


@app.route("/api/feud-moments")
def feud_moments_api():
    try:
        limit = max(1, min(25, int(request.args.get("limit", 10))))
    except (TypeError, ValueError):
        limit = 10
    conn = db()
    rows = conn.execute(
        """SELECT id, battle_id, hunter_a, hunter_b, winner, loser, moment_key, icon, label, detail, intensity, created_at
           FROM feud_moments ORDER BY id DESC LIMIT ?""",
        (limit,)
    ).fetchall()
    total = int(conn.execute("SELECT COUNT(*) AS n FROM feud_moments").fetchone()["n"] or 0)
    ids = [int(r["id"]) for r in rows]
    click_map = {}
    if ids:
        marks = ",".join("?" for _ in ids)
        click_rows = conn.execute(
            f"SELECT moment_id, COUNT(*) AS n FROM feud_viral_clicks WHERE moment_id IN ({marks}) GROUP BY moment_id",
            ids
        ).fetchall()
        click_map = {int(r["moment_id"]): int(r["n"] or 0) for r in click_rows}
    conn.close()
    moments = []
    for r in rows:
        item = dict(r)
        item["viral_clicks"] = click_map.get(int(item["id"]), 0)
        heat = max(1, min(5, int(item.get("intensity") or 1)))
        item["trend_score"] = heat * 20 + int(item["viral_clicks"]) * 3
        moments.append(item)
    return jsonify({
        "success": True,
        "moments": moments,
        "total_moments": total,
        "engine": "discovery-v13.2"
    })


def _feud_moment_record(moment_id):
    conn = db()
    row = conn.execute(
        """SELECT id, battle_id, hunter_a, hunter_b, winner, loser, moment_key, icon, label, detail, intensity, created_at
           FROM feud_moments WHERE id = ?""",
        (int(moment_id),)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def _feud_moment_cast_text(m):
    heat = int(m.get("intensity") or 1)
    icon = str(m.get("icon") or "🎬")
    label = str(m.get("label") or "FEUD MOMENT")
    winner = str(m.get("winner") or "A Hunter")
    loser = str(m.get("loser") or "their rival")
    battle_id = int(m.get("battle_id") or 0)
    return f"{icon} {label} on BL3\n{winner} changed the feud vs {loser} in Clash #{battle_id}.\nHeat {heat}/5 ⚔️\nBuild. Meme. Repeat."


def _feud_moment_viral_stats(moment_id):
    conn = db()
    rows = conn.execute(
        """SELECT action_key, COUNT(*) AS n
           FROM feud_viral_clicks WHERE moment_id = ?
           GROUP BY action_key""",
        (int(moment_id),)
    ).fetchall()
    conn.close()
    counts = {str(r["action_key"]): int(r["n"] or 0) for r in rows}
    return {
        "challenge_winner": counts.get("challenge-winner", 0),
        "challenge_rival": counts.get("challenge-rival", 0),
        "open_clash": counts.get("open-clash", 0),
        "total": sum(counts.values())
    }


def _feud_moment_cta_urls(m, moment_id):
    root = request.url_root.rstrip("/")
    return {
        "challenge_winner": f"{root}/feud-moment/{int(moment_id)}/go/challenge-winner",
        "challenge_rival": f"{root}/feud-moment/{int(moment_id)}/go/challenge-rival",
        "open_clash": f"{root}/feud-moment/{int(moment_id)}/go/open-clash"
    }


@app.route("/feud-moment/<int:moment_id>/go/<action_key>")
def feud_moment_viral_go(moment_id, action_key):
    m = _feud_moment_record(moment_id)
    if not m:
        return "Feud Moment not found", 404

    action_key = str(action_key or "").strip().lower()
    targets = {
        "challenge-winner": str(m.get("winner") or "").strip(),
        "challenge-rival": str(m.get("loser") or "").strip(),
        "open-clash": str(m.get("battle_id") or "").strip()
    }
    if action_key not in targets:
        return "Unknown viral action", 404

    target = targets[action_key]
    conn = db()
    conn.execute(
        """INSERT INTO feud_viral_clicks (moment_id, action_key, target, created_at)
           VALUES (?, ?, ?, ?)""",
        (int(moment_id), action_key, target[:160], datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

    if action_key == "open-clash":
        return redirect(f"/clash/{int(m['battle_id'])}", code=302)

    return redirect(
        "/?" + urllib.parse.urlencode({
            "challenge": target,
            "moment": int(moment_id),
            "source": "feud-moment"
        }) + "#clashCard",
        code=302
    )


@app.route("/api/feud-moment/<int:moment_id>/cast-kit")
def feud_moment_cast_kit_api(moment_id):
    m = _feud_moment_record(moment_id)
    if not m:
        return jsonify({"success": False, "message": "Feud Moment not found"}), 404
    root = request.url_root.rstrip("/")
    page_url = f"{root}/feud-moment/{moment_id}"
    card_url = f"{root}/feud-moment/{moment_id}/card.svg"
    ctas = _feud_moment_cta_urls(m, moment_id)
    loop_stats = _feud_moment_viral_stats(moment_id)
    return jsonify({
        "success": True,
        "cast_kit": {
            "title": f"BL3 {m['label']} — Clash #{m['battle_id']}",
            "cast_text": _feud_moment_cast_text(m),
            "page_url": page_url,
            "card_url": card_url,
            "battle_url": f"{root}/clash/{m['battle_id']}",
            "rivalry_url": f"{root}/rivalry/{urllib.parse.quote(m['hunter_a'])}/{urllib.parse.quote(m['hunter_b'])}",
            "intensity": int(m.get("intensity") or 1),
            "cta": {
                "challenge_winner": {"label": f"Challenge {m['winner']}", "url": ctas["challenge_winner"]},
                "challenge_rival": {"label": f"Challenge {m['loser']}", "url": ctas["challenge_rival"]},
                "open_clash": {"label": "Watch the Clash", "url": ctas["open_clash"]}
            },
            "viral_loop": loop_stats
        },
        "engine": "discovery-v13.2"
    })


@app.route("/feud-moment/<int:moment_id>/card.svg")
def feud_moment_card_svg(moment_id):
    m = _feud_moment_record(moment_id)
    if not m:
        return Response("Feud Moment not found", status=404, mimetype="text/plain")
    esc = lambda v: html.escape(str(v or ""))
    icon = esc(m.get("icon") or "🎬")
    label = esc(m.get("label") or "FEUD MOMENT")
    winner = esc(m.get("winner") or "Hunter")
    loser = esc(m.get("loser") or "Rival")
    detail = esc(m.get("detail") or "The feud changed.")
    heat = max(1, min(5, int(m.get("intensity") or 1)))
    bars = "".join(
        f'<rect x="{72+i*54}" y="515" width="42" height="10" rx="5" fill="{("#61f4ff" if i < heat else "#252532")}"/>'
        for i in range(5)
    )
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
      <defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#05070b"/><stop offset=".55" stop-color="#141120"/><stop offset="1" stop-color="#07161b"/></linearGradient><radialGradient id="glow"><stop stop-color="#61f4ff" stop-opacity=".24"/><stop offset="1" stop-color="#61f4ff" stop-opacity="0"/></radialGradient></defs>
      <rect width="1200" height="630" rx="40" fill="url(#bg)"/><circle cx="1010" cy="105" r="260" fill="url(#glow)"/><rect x="34" y="34" width="1132" height="562" rx="30" fill="none" stroke="#30303b" stroke-width="2"/>
      <text x="72" y="95" fill="#61f4ff" font-family="Arial,sans-serif" font-size="25" font-weight="900">BL3 // FEUD MOMENT // CLASH #{int(m['battle_id'])}</text><text x="72" y="148" fill="#77798b" font-family="Arial,sans-serif" font-size="18" letter-spacing="3">CAST KIT // STORY-GRADE BATTLE</text>
      <text x="72" y="240" fill="#ffffff" font-family="Arial,sans-serif" font-size="66" font-weight="950">{icon} {label}</text><text x="72" y="324" fill="#ffffff" font-family="Arial,sans-serif" font-size="42" font-weight="900">{winner}</text><text x="72" y="371" fill="#9fa1b1" font-family="Arial,sans-serif" font-size="25">changed the feud vs {loser}</text>
      <text x="72" y="433" fill="#c8cad6" font-family="Arial,sans-serif" font-size="21">{detail[:92]}</text><text x="72" y="491" fill="#61f4ff" font-family="Arial,sans-serif" font-size="18" font-weight="900">HEAT {heat}/5</text>{bars}<text x="72" y="565" fill="#686a78" font-family="Arial,sans-serif" font-size="18">BL3 // BUILD. MEME. REPEAT.</text><text x="1128" y="565" fill="#a17cff" font-family="Arial,sans-serif" font-size="18" text-anchor="end">SHARE THE STORY</text>
    </svg>'''
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "public, max-age=300"})


@app.route("/feud-moment/<int:moment_id>")
def feud_moment_public_page(moment_id):
    m = _feud_moment_record(moment_id)
    if not m:
        return "Feud Moment not found", 404
    esc = lambda v: html.escape(str(v or ""))
    root = request.url_root.rstrip("/")
    page_url = f"{root}/feud-moment/{moment_id}"
    image_url = f"{root}/feud-moment/{moment_id}/card.svg"
    battle_url = f"{root}/clash/{m['battle_id']}"
    rivalry_url = f"{root}/rivalry/{urllib.parse.quote(m['hunter_a'])}/{urllib.parse.quote(m['hunter_b'])}"
    title = f"{m['icon']} {m['label']} — BL3 Clash #{m['battle_id']}"
    desc = f"{m['winner']} changed the feud vs {m['loser']}. Heat {m['intensity']}/5."
    cast_text = _feud_moment_cast_text(m)
    ctas = _feud_moment_cta_urls(m, moment_id)
    loop_stats = _feud_moment_viral_stats(moment_id)
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title><meta name="description" content="{esc(desc)}"><meta property="og:title" content="{esc(title)}"><meta property="og:description" content="{esc(desc)}"><meta property="og:type" content="website"><meta property="og:url" content="{esc(page_url)}"><meta property="og:image" content="{esc(image_url)}"><meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="{esc(title)}"><meta name="twitter:description" content="{esc(desc)}"><meta name="twitter:image" content="{esc(image_url)}"><style>*{{box-sizing:border-box}}body{{margin:0;background:#05070b;color:#fff;font-family:Arial,sans-serif;min-height:100vh;display:grid;place-items:center;padding:24px}}.wrap{{width:min(900px,100%)}}.brand{{font-weight:950;font-size:26px}}.brand span{{color:#61f4ff}}.card{{margin-top:18px;border:1px solid #30303b;border-radius:28px;padding:30px;background:linear-gradient(145deg,#0b1015,#161120)}}.eyebrow{{color:#61f4ff;font-size:11px;font-weight:900;letter-spacing:2px}}h1{{font-size:clamp(40px,8vw,78px);line-height:.95;margin:16px 0}}.detail{{color:#adb0bf;line-height:1.65;font-size:17px}}.heat{{margin:18px 0;color:#61f4ff;font-weight:900}}.loop{{margin:12px 0;border:1px solid #2f3940;border-radius:14px;padding:11px;color:#61f4ff;background:#081014;font-size:12px;font-weight:900}}.cast{{white-space:pre-wrap;border:1px solid #30303b;border-radius:18px;padding:18px;background:#090a0f;color:#e7e7ef;line-height:1.55}}.actions{{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-top:16px}}.btn{{display:block;text-align:center;text-decoration:none;color:#07080b;background:#61f4ff;font-weight:950;padding:15px;border-radius:15px;border:0;cursor:pointer}}.btn.alt{{background:#a17cff;color:#fff}}.btn.ghost{{background:transparent;color:#fff;border:1px solid #30303b}}@media(max-width:620px){{.actions{{grid-template-columns:1fr}}}}</style></head><body><div class="wrap"><div class="brand">BL3<span>●</span> VIRAL LOOP</div><div class="card"><div class="eyebrow">FEUD MOMENT // CLASH #{int(m['battle_id'])}</div><h1>{esc(m['icon'])} {esc(m['label'])}</h1><div class="detail">{esc(m['detail'])}</div><div class="heat">HEAT {int(m['intensity'])}/5 · {esc(m['winner'])} VS {esc(m['loser'])}</div><div class="cast">{esc(cast_text)}\n{esc(page_url)}</div><div class="loop">🔁 VIRAL LOOP · {int(loop_stats['total'])} CTA clicks · {int(loop_stats['challenge_winner']) + int(loop_stats['challenge_rival'])} challenge intent</div><div class="actions"><a class="btn" href="{esc(ctas['challenge_winner'])}">⚔️ CHALLENGE {esc(m['winner']).upper()}</a><a class="btn alt" href="{esc(ctas['challenge_rival'])}">🔥 CHALLENGE {esc(m['loser']).upper()}</a><button class="btn ghost" onclick="copyCast()">📋 COPY FARCASTER CAST</button><button class="btn ghost" onclick="shareCast()">📣 SHARE</button><a class="btn ghost" href="{esc(image_url)}">🖼 OPEN CARD</a><a class="btn ghost" href="{esc(rivalry_url)}">⚔️ OPEN RIVALRY</a><a class="btn ghost" href="{esc(ctas['open_clash'])}">🎬 WATCH CLASH</a><a class="btn ghost" href="/">← BL3 NETWORK</a></div></div></div><script>const cast={json.dumps(cast_text)};const url={json.dumps(page_url)};async function copyCast(){{try{{await navigator.clipboard.writeText(cast+'\\n'+url);alert('Farcaster cast copied.')}}catch(e){{alert(cast+'\\n'+url)}}}}async function shareCast(){{try{{if(navigator.share){{await navigator.share({{title:{json.dumps(title)},text:cast,url}});return}}await navigator.clipboard.writeText(cast+'\\n'+url);alert('Cast Kit copied.')}}catch(e){{}}}}</script></body></html>'''


@app.route("/api/season-feud-spotlight")
def season_feud_spotlight_api():
    data = _season_feud_spotlight()
    return jsonify({
        "success": True,
        **data,
        "method": "Most active direct rivalry in the current season by completed Clash count. Ties break from the shared all-time rivalry index by lead changes, all-time clashes, then latest battle."
    })


def _rivalry_records(limit=6):
    pairs, cache_state = _rivalry_index_snapshot()
    records = []

    for (a, b), item in pairs.items():
        score_a = int(item["score"][a])
        score_b = int(item["score"][b])
        clashes = int(item["clashes"])
        records.append({
            "hunter_a": a,
            "hunter_b": b,
            "clashes": clashes,
            "score_a": score_a,
            "score_b": score_b,
            "gap": abs(score_a - score_b),
            "lead_changes": int(item["lead_changes"]),
            "biggest_lead": int(item["biggest_lead"]),
            "a_best_streak": int(item["best_streak"][a]),
            "b_best_streak": int(item["best_streak"][b]),
            "tier": _rivalry_tier(clashes),
            "last_winner": item["last_winner"],
            "last_battle_id": int(item["last_battle_id"])
        })

    most_clashes = sorted(
        records,
        key=lambda r: (r["clashes"], r["lead_changes"], -r["gap"], r["last_battle_id"]),
        reverse=True
    )[:limit]

    closest = sorted(
        [r for r in records if r["clashes"] >= 2],
        key=lambda r: (r["gap"], -r["clashes"], -r["lead_changes"], -r["last_battle_id"])
    )[:limit]

    wildest = sorted(
        records,
        key=lambda r: (
            r["lead_changes"],
            r["clashes"],
            max(r["a_best_streak"], r["b_best_streak"]),
            r["last_battle_id"]
        ),
        reverse=True
    )[:limit]

    return {
        "most_clashes": most_clashes,
        "closest": closest,
        "wildest": wildest,
        "total_rivalries": len(records),
        "engine": "snapshot-discovery-v13.2",
        "cache": cache_state
    }


@app.route("/api/rivalry-records")
def rivalry_records_api():
    data = _rivalry_records(limit=6)
    return jsonify({"success": True, **data})


@app.route("/api/rivalry-chronicle/<hunter_a>/<hunter_b>")
def rivalry_chronicle_api(hunter_a, hunter_b):
    conn = db()
    a = conn.execute("SELECT 1 FROM users WHERE username = ?", (hunter_a,)).fetchone()
    b = conn.execute("SELECT 1 FROM users WHERE username = ?", (hunter_b,)).fetchone()
    conn.close()
    if a is None or b is None or hunter_a == hunter_b:
        return jsonify({"success": False, "message": "Rivalry not found"}), 404

    return jsonify({
        "success": True,
        **_rivalry_chronicle(hunter_a, hunter_b)
    })


def _rivalry_escalation(hunter_a, hunter_b):
    h2h = _head_to_head(hunter_a, hunter_b, 12)
    total = int(h2h.get("total") or 0)
    a_wins = int(h2h.get("a_wins") or 0)
    b_wins = int(h2h.get("b_wins") or 0)
    gap = abs(a_wins - b_wins)

    tier = _rivalry_tier(total)

    progress_target = tier["next_at"]
    if progress_target:
        progress_from = {0: 0, 1: 1, 2: 3, 3: 5, 4: 8}.get(tier["level"], 0)
        span = max(1, progress_target - progress_from)
        percent = max(0, min(100, round(((total - progress_from) / span) * 100)))
        to_next = max(0, progress_target - total)
    else:
        percent = 100
        to_next = 0

    if h2h.get("leader") == hunter_a:
        leader = hunter_a
    elif h2h.get("leader") == hunter_b:
        leader = hunter_b
    else:
        leader = None

    return {
        "hunter_a": hunter_a,
        "hunter_b": hunter_b,
        "total": total,
        "a_wins": a_wins,
        "b_wins": b_wins,
        "gap": gap,
        "leader": leader,
        "last_winner": h2h.get("last_winner"),
        "tier": tier,
        "progress_percent": percent,
        "clashes_to_next": to_next
    }


@app.route("/api/rivalry-escalation/<hunter_a>/<hunter_b>")
def rivalry_escalation_api(hunter_a, hunter_b):
    conn = db()
    a = conn.execute("SELECT 1 FROM users WHERE username = ?", (hunter_a,)).fetchone()
    b = conn.execute("SELECT 1 FROM users WHERE username = ?", (hunter_b,)).fetchone()
    conn.close()
    if a is None or b is None or hunter_a == hunter_b:
        return jsonify({"success": False, "message": "Rivalry not found"}), 404
    return jsonify({"success": True, **_rivalry_escalation(hunter_a, hunter_b)})


@app.route("/api/headtohead/<hunter_a>/<hunter_b>")
def head_to_head_api(hunter_a, hunter_b):
    conn = db()
    a_exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (hunter_a,)).fetchone()
    b_exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (hunter_b,)).fetchone()
    conn.close()
    if a_exists is None or b_exists is None:
        return jsonify({"success": False, "message": "Hunter not found"}), 404
    return jsonify({
        "success": True,
        **_head_to_head(hunter_a, hunter_b, 8),
        "milestones": _rivalry_milestones(hunter_a, hunter_b)
    })



@app.route("/rivalry/<hunter_a>/<hunter_b>/card.svg")
def rivalry_card_svg(hunter_a, hunter_b):
    conn = db()
    a_row = conn.execute("SELECT username, xp FROM users WHERE username = ?", (hunter_a,)).fetchone()
    b_row = conn.execute("SELECT username, xp FROM users WHERE username = ?", (hunter_b,)).fetchone()
    conn.close()
    if a_row is None or b_row is None or hunter_a == hunter_b:
        return Response("Rivalry not found", status=404, mimetype="text/plain")

    h2h = _head_to_head(hunter_a, hunter_b, 6)
    a_avatar = _creature_avatar_from_xp(int(a_row["xp"] or 0))
    b_avatar = _creature_avatar_from_xp(int(b_row["xp"] or 0))
    esc = lambda v: html.escape(str(v or ""))

    if h2h["leader"] == hunter_a:
        status = f"{hunter_a.upper()} LEADS"
    elif h2h["leader"] == hunter_b:
        status = f"{hunter_b.upper()} LEADS"
    else:
        status = "RIVALRY TIED"

    last = h2h["last_winner"] or "NO CLASHES YET"
    milestones = _rivalry_milestones(hunter_a, hunter_b)
    escalation = _rivalry_escalation(hunter_a, hunter_b)
    escalation_tier = escalation["tier"]
    badge_line = "  •  ".join(
        f"{m['icon']} {m['title']}" for m in milestones[:3]
    ) or "NO MILESTONES YET"

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
      <defs>
        <linearGradient id="bg" x1="0" x2="1" y1="0" y2="1">
          <stop offset="0" stop-color="#07070c"/>
          <stop offset=".55" stop-color="#11111a"/>
          <stop offset="1" stop-color="#171022"/>
        </linearGradient>
        <linearGradient id="hot" x1="0" x2="1">
          <stop offset="0" stop-color="#b8ff5a"/>
          <stop offset="1" stop-color="{skin['accent2']}"/>
        </linearGradient>
        <filter id="glow"><feGaussianBlur stdDeviation="8" result="c"/><feMerge><feMergeNode in="c"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
      </defs>
      <rect width="1200" height="630" rx="36" fill="url(#bg)"/>
      <rect x="1" y="1" width="1198" height="628" rx="35" fill="none" stroke="{skin['line']}" stroke-width="2"/>
      <text x="70" y="74" fill="{skin['accent']}" font-family="Arial,sans-serif" font-size="22" font-weight="900" letter-spacing="3">BL3 // RIVALRY CARD</text>
      <text x="1130" y="74" fill="#6d6d7d" font-family="Arial,sans-serif" font-size="18" text-anchor="end">THE HUMAN ALPHA NETWORK</text>

      <text x="235" y="215" fill="#ffffff" font-family="Arial,sans-serif" font-size="54" text-anchor="middle">{esc(a_avatar)}</text>
      <text x="235" y="280" fill="#ffffff" font-family="Arial,sans-serif" font-size="42" font-weight="900" text-anchor="middle">{esc(hunter_a)}</text>
      <text x="235" y="405" fill="#ffffff" font-family="Arial,sans-serif" font-size="120" font-weight="900" text-anchor="middle">{h2h["a_wins"]}</text>

      <text x="600" y="250" fill="url(#hot)" font-family="Arial,sans-serif" font-size="64" font-weight="900" text-anchor="middle" filter="url(#glow)">VS</text>
      <text x="600" y="323" fill="{skin['accent']}" font-family="Arial,sans-serif" font-size="26" font-weight="900" text-anchor="middle">{h2h["total"]} CLASHES</text>
      <text x="600" y="362" fill="{skin['accent2']}" font-family="Arial,sans-serif" font-size="22" font-weight="900" text-anchor="middle">{esc(status)}</text>

      <text x="965" y="215" fill="#ffffff" font-family="Arial,sans-serif" font-size="54" text-anchor="middle">{esc(b_avatar)}</text>
      <text x="965" y="280" fill="#ffffff" font-family="Arial,sans-serif" font-size="42" font-weight="900" text-anchor="middle">{esc(hunter_b)}</text>
      <text x="965" y="405" fill="#ffffff" font-family="Arial,sans-serif" font-size="120" font-weight="900" text-anchor="middle">{h2h["b_wins"]}</text>

      <rect x="70" y="482" width="1060" height="1" fill="#2b2b38"/>
      <text x="70" y="522" fill="#a7a7b6" font-family="Arial,sans-serif" font-size="20">LAST WINNER: {esc(last)}</text>
      <text x="1130" y="522" fill="{skin['accent']}" font-family="Arial,sans-serif" font-size="20" font-weight="900" text-anchor="end">SETTLE IT IN BL3 →</text>
      <text x="70" y="558" fill="{skin['accent2']}" font-family="Arial,sans-serif" font-size="16" font-weight="900">{esc(badge_line)}</text>
      <text x="70" y="596" fill="{skin['accent']}" font-family="Arial,sans-serif" font-size="17" font-weight="900">{esc(escalation_tier["icon"])} {esc(escalation_tier["label"])} // LEVEL {int(escalation_tier["level"])}/5</text>
      <text x="1130" y="586" fill="#666677" font-family="Arial,sans-serif" font-size="17" text-anchor="end">bl3meme.com</text>
    </svg>"""
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "public, max-age=120"})


@app.route("/rivalry/<hunter_a>/<hunter_b>/chronicle.svg")
def rivalry_chronicle_card_svg(hunter_a, hunter_b):
    conn = db()
    a_row = conn.execute("SELECT username, xp FROM users WHERE username = ?", (hunter_a,)).fetchone()
    b_row = conn.execute("SELECT username, xp FROM users WHERE username = ?", (hunter_b,)).fetchone()
    conn.close()
    if a_row is None or b_row is None or hunter_a == hunter_b:
        return Response("Rivalry not found", status=404, mimetype="text/plain")

    esc = lambda v: html.escape(str(v or ""))
    short = lambda v, n=16: (str(v) if len(str(v)) <= n else str(v)[:max(1, n-1)] + "…")
    h2h = _head_to_head(hunter_a, hunter_b, 8)
    chron = _rivalry_chronicle(hunter_a, hunter_b)
    escalation = _rivalry_escalation(hunter_a, hunter_b)
    tier = escalation["tier"]

    a_avatar = _creature_avatar_from_xp(int(a_row["xp"] or 0))
    b_avatar = _creature_avatar_from_xp(int(b_row["xp"] or 0))
    latest = (chron.get("events") or [])[:3]

    event_lines = []
    for idx, event in enumerate(latest):
        y = 455 + (idx * 38)
        event_lines.append(
            f'<text x="74" y="{y}" fill="#d9d9e4" font-family="Arial,sans-serif" '
            f'font-size="17" font-weight="700">{esc(event["icon"])} {esc(event["title"])}'
            f'  //  CLASH #{int(event["battle_id"])}</text>'
        )
    if not event_lines:
        event_lines.append(
            '<text x="74" y="455" fill="#777788" font-family="Arial,sans-serif" '
            'font-size="17">Chronicle begins after the first direct Clash.</text>'
        )

    if h2h["leader"] == hunter_a:
        lead_line = f"{hunter_a.upper()} LEADS"
    elif h2h["leader"] == hunter_b:
        lead_line = f"{hunter_b.upper()} LEADS"
    else:
        lead_line = "RIVALRY TIED"

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
      <defs>
        <linearGradient id="bg" x1="0" x2="1" y1="0" y2="1">
          <stop offset="0" stop-color="#07070c"/>
          <stop offset=".56" stop-color="#12111b"/>
          <stop offset="1" stop-color="#211029"/>
        </linearGradient>
        <linearGradient id="line" x1="0" x2="1">
          <stop offset="0" stop-color="#b8ff5a"/>
          <stop offset="1" stop-color="#ff63d7"/>
        </linearGradient>
      </defs>
      <rect width="1200" height="630" rx="36" fill="url(#bg)"/>
      <rect x="1" y="1" width="1198" height="628" rx="35" fill="none" stroke="#302b3a" stroke-width="2"/>

      <text x="72" y="72" fill="#b8ff5a" font-family="Arial,sans-serif" font-size="22" font-weight="900" letter-spacing="3">BL3 // RIVALRY CHRONICLE</text>
      <text x="1128" y="72" fill="#747486" font-family="Arial,sans-serif" font-size="17" text-anchor="end">TURNING POINTS // PUBLIC RECORD</text>

      <text x="160" y="170" fill="#ffffff" font-family="Arial,sans-serif" font-size="48" text-anchor="middle">{esc(a_avatar)}</text>
      <text x="160" y="224" fill="#ffffff" font-family="Arial,sans-serif" font-size="28" font-weight="900" text-anchor="middle">{esc(short(hunter_a))}</text>
      <text x="160" y="314" fill="#ffffff" font-family="Arial,sans-serif" font-size="76" font-weight="900" text-anchor="middle">{int(h2h["a_wins"])}</text>

      <text x="600" y="188" fill="#ff63d7" font-family="Arial,sans-serif" font-size="46" font-weight="900" text-anchor="middle">VS</text>
      <text x="600" y="237" fill="#b8ff5a" font-family="Arial,sans-serif" font-size="21" font-weight="900" text-anchor="middle">{esc(lead_line)}</text>
      <text x="600" y="277" fill="#a8a8b8" font-family="Arial,sans-serif" font-size="17" text-anchor="middle">{int(h2h["total"])} DIRECT CLASHES</text>
      <text x="600" y="315" fill="#ff63d7" font-family="Arial,sans-serif" font-size="20" font-weight="900" text-anchor="middle">{esc(tier["icon"])} {esc(tier["label"])} // LEVEL {int(tier["level"])}/5</text>

      <text x="1040" y="170" fill="#ffffff" font-family="Arial,sans-serif" font-size="48" text-anchor="middle">{esc(b_avatar)}</text>
      <text x="1040" y="224" fill="#ffffff" font-family="Arial,sans-serif" font-size="28" font-weight="900" text-anchor="middle">{esc(short(hunter_b))}</text>
      <text x="1040" y="314" fill="#ffffff" font-family="Arial,sans-serif" font-size="76" font-weight="900" text-anchor="middle">{int(h2h["b_wins"])}</text>

      <rect x="72" y="356" width="1056" height="1" fill="#2b2b38"/>
      <text x="72" y="392" fill="#8d8d9c" font-family="Arial,sans-serif" font-size="15">LEAD CHANGES</text>
      <text x="220" y="392" fill="#ffffff" font-family="Arial,sans-serif" font-size="20" font-weight="900">{int(chron["lead_changes"])}</text>
      <text x="330" y="392" fill="#8d8d9c" font-family="Arial,sans-serif" font-size="15">BIGGEST LEAD</text>
      <text x="474" y="392" fill="#ffffff" font-family="Arial,sans-serif" font-size="20" font-weight="900">{int(chron["biggest_lead"])}</text>
      <text x="595" y="392" fill="#8d8d9c" font-family="Arial,sans-serif" font-size="15">{esc(short(hunter_a,12)).upper()} BEST STREAK</text>
      <text x="812" y="392" fill="#ffffff" font-family="Arial,sans-serif" font-size="20" font-weight="900">{int(chron["longest_streaks"].get(hunter_a,0))}</text>
      <text x="875" y="392" fill="#8d8d9c" font-family="Arial,sans-serif" font-size="15">{esc(short(hunter_b,12)).upper()} BEST</text>
      <text x="1090" y="392" fill="#ffffff" font-family="Arial,sans-serif" font-size="20" font-weight="900">{int(chron["longest_streaks"].get(hunter_b,0))}</text>

      <text x="72" y="426" fill="#b8ff5a" font-family="Arial,sans-serif" font-size="15" font-weight="900">LATEST TURNING POINTS</text>
      <text x="1128" y="426" fill="#8d8d9c" font-family="Arial,sans-serif" font-size="14" text-anchor="end">COMEBACKS {int(chron.get("completed_comebacks",{}).get(hunter_a,0))}–{int(chron.get("completed_comebacks",{}).get(hunter_b,0))}</text>
      {''.join(event_lines)}

      <rect x="72" y="582" width="1056" height="1" fill="#2b2b38"/>
      <text x="72" y="611" fill="#6f6f7e" font-family="Arial,sans-serif" font-size="15">FIRST BLOOD: {esc(chron.get("first_blood") or "—")}</text>
      <text x="1128" y="611" fill="#6f6f7e" font-family="Arial,sans-serif" font-size="15" text-anchor="end">BL3 // BUILD. MEME. REPEAT.</text>
    </svg>"""
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "public, max-age=120"})


@app.route("/rivalry/<hunter_a>/<hunter_b>")
def rivalry_public_page(hunter_a, hunter_b):
    conn = db()
    a = conn.execute("SELECT username FROM users WHERE username = ?", (hunter_a,)).fetchone()
    b = conn.execute("SELECT username FROM users WHERE username = ?", (hunter_b,)).fetchone()
    conn.close()
    if a is None or b is None or hunter_a == hunter_b:
        return "Rivalry not found", 404

    h2h = _head_to_head(hunter_a, hunter_b, 8)
    milestones = _rivalry_milestones(hunter_a, hunter_b)
    escalation = _rivalry_escalation(hunter_a, hunter_b)
    escalation_tier = escalation["tier"]
    esc = lambda v: html.escape(str(v or ""))

    chronicle = _rivalry_chronicle(hunter_a, hunter_b)
    chronicle_events_html = ""
    for event in chronicle.get("events", [])[:8]:
        chronicle_events_html += (
            f'<a class="chronicle-event" href="/clash/{int(event["battle_id"])}">'
            f'<div class="chronicle-icon">{esc(event["icon"])}</div>'
            f'<div><b>{esc(event["title"])}</b><span>{esc(event["detail"])}</span></div>'
            f'<small>CLASH #{int(event["battle_id"])}</small>'
            f'</a>'
        )
    if not chronicle_events_html:
        chronicle_events_html = '<div class="empty">The Chronicle starts after the first direct Clash.</div>'

    escalation_path = [
        {"at": 1, "icon": "⚔️", "label": "FIRST BLOOD"},
        {"at": 3, "icon": "🔥", "label": "RIVALRY IGNITED"},
        {"at": 5, "icon": "😈", "label": "NEMESIS"},
        {"at": 8, "icon": "🩸", "label": "BLOOD FEUD"},
        {"at": 12, "icon": "🌠", "label": "LEGENDARY FEUD"},
    ]
    path_html = ""
    total_clashes = int(escalation.get("total") or 0)
    for step in escalation_path:
        if total_clashes >= step["at"]:
            cls = "reached"
            state = "UNLOCKED"
        elif escalation_tier.get("next_at") == step["at"]:
            cls = "next"
            state = f"{max(0, step['at'] - total_clashes)} TO GO"
        else:
            cls = "locked"
            state = f"AT {step['at']} CLASHES"
        path_html += (
            f'<div class="path-step {cls}">'
            f'<div class="path-icon">{esc(step["icon"])}</div>'
            f'<div class="path-copy"><b>{esc(step["label"])}</b><span>{esc(state)}</span></div>'
            f'</div>'
        )
    root = request.url_root.rstrip("/")
    page_url = f"{root}/rivalry/{urllib.parse.quote(hunter_a)}/{urllib.parse.quote(hunter_b)}"
    image_url = page_url + "/card.svg"
    chronicle_card_url = page_url + "/chronicle.svg"
    challenge_url = f"{root}/?challenge={urllib.parse.quote(hunter_b)}&ref={urllib.parse.quote(hunter_a)}"

    if h2h["leader"] == hunter_a:
        status = f"{hunter_a} leads"
    elif h2h["leader"] == hunter_b:
        status = f"{hunter_b} leads"
    else:
        status = "The rivalry is tied"

    rows = ""
    for battle in h2h["recent"]:
        rows += (
            f'<a class="battle" href="/clash/{battle["id"]}">'
            f'<span>⚔️ Clash #{battle["id"]}</span>'
            f'<b>👑 {esc(battle["winner"])}</b>'
            f'<small>{esc(battle["commentary"])}</small>'
            f'</a>'
        )
    if not rows:
        rows = '<div class="empty">No clashes yet. Start the first one.</div>'

    badges_html = "".join(
        f'<div class="badge-card"><div class="badge-icon">{esc(m["icon"])}</div>'
        f'<div><b>{esc(m["title"])}</b><span>{esc(m["detail"])}</span></div></div>'
        for m in milestones
    ) or '<div class="empty">Milestones unlock automatically as the rivalry grows.</div>'

    title = f"{hunter_a} vs {hunter_b} // BL3 Rivalry"
    desc = f"{hunter_a} {h2h['a_wins']} — {h2h['b_wins']} {hunter_b}. {status}. {h2h['total']} clashes on BL3."

    return f"""<!doctype html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title>
<meta name="description" content="{esc(desc)}">
<meta property="og:title" content="{esc(title)}">
<meta property="og:description" content="{esc(desc)}">
<meta property="og:image" content="{esc(image_url)}">
<meta property="og:url" content="{esc(page_url)}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{esc(title)}">
<meta name="twitter:description" content="{esc(desc)}">
<meta name="twitter:image" content="{esc(image_url)}">
<style>
:root{{--bg:#08080d;--card:#111119;--line:#292934;--muted:#9393a4;--hot:#b8ff5a;--violet:#9d7bff}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 50% -20%,#281743 0,#08080d 48%);color:#fff;font-family:Arial,sans-serif}}
.shell{{max-width:980px;margin:auto;padding:26px}}.nav{{display:flex;justify-content:space-between;align-items:center}}.brand{{font-size:24px;font-weight:900}}.brand span,.eyebrow{{color:var(--hot)}}.back{{color:#fff;text-decoration:none;border:1px solid var(--line);padding:10px 14px;border-radius:999px}}
.hero{{margin-top:56px;text-align:center}}h1{{font-size:clamp(42px,8vw,84px);margin:10px 0;letter-spacing:-4px}}.vs{{color:var(--violet)}}.score{{display:grid;grid-template-columns:1fr auto 1fr;gap:20px;align-items:center;margin:30px auto;max-width:760px}}
.side{{background:var(--card);border:1px solid var(--line);border-radius:24px;padding:26px}}.side strong{{display:block;font-size:84px;line-height:1}}.side span{{display:block;margin-top:10px;font-weight:900}}
.mid{{font-weight:900;color:var(--hot)}}.meta{{color:var(--muted)}}.actions{{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin:26px 0}}.btn{{text-decoration:none;color:#08080d;background:var(--hot);font-weight:900;padding:14px 18px;border-radius:14px}}.btn.alt{{background:var(--violet);color:#fff}}
.section{{margin-top:40px}}.milestones{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:14px}}.badge-card{{display:flex;gap:12px;align-items:flex-start;border:1px solid var(--line);background:linear-gradient(145deg,#111119,#151020);padding:16px;border-radius:18px}}.badge-icon{{font-size:28px;line-height:1}}.badge-card b{{display:block;font-size:13px;letter-spacing:1px;color:var(--hot)}}.badge-card span{{display:block;color:var(--muted);font-size:12px;margin-top:5px;line-height:1.45}}.battle{{display:grid;grid-template-columns:1fr auto;gap:6px 18px;text-decoration:none;color:#fff;border:1px solid var(--line);background:var(--card);padding:16px;border-radius:16px;margin-top:10px}}.battle small{{grid-column:1/-1;color:var(--muted)}}.empty{{color:var(--muted);padding:18px;border:1px dashed var(--line);border-radius:16px}}.escalation{{margin-top:18px;border:1px solid var(--line);border-radius:18px;padding:14px;background:rgba(255,255,255,.025)}}.escalation-top{{display:flex;justify-content:space-between;align-items:center;gap:12px}}.escalation-top b{{font-size:12px;letter-spacing:1px}}.escalation-top span{{font-size:10px;color:var(--muted)}}.escalation-bar{{height:8px;background:#09090d;border:1px solid var(--line);border-radius:999px;overflow:hidden;margin-top:10px}}.escalation-bar i{{display:block;height:100%;background:linear-gradient(90deg,#b8ff5a,#9d7bff);width:{int(escalation["progress_percent"])}%}}.escalation-meta{{display:flex;justify-content:space-between;gap:10px;margin-top:7px;font-size:9px;color:var(--muted)}}.feud-path{{margin-top:16px;border:1px solid var(--line);border-radius:18px;padding:14px;background:rgba(255,255,255,.02)}}.feud-path-head{{display:flex;justify-content:space-between;gap:10px;align-items:center;margin-bottom:11px}}.chronicle-stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:12px 0}}.chronicle-stat{{border:1px solid var(--line);border-radius:13px;padding:10px;background:rgba(255,255,255,.018);text-align:center}}.chronicle-stat b{{display:block;font-size:18px}}.chronicle-stat span{{display:block;font-size:7px;color:var(--muted);margin-top:3px;letter-spacing:.8px}}.chronicle-list{{display:grid;gap:8px}}.chronicle-event{{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;text-decoration:none;color:#fff;border:1px solid var(--line);background:rgba(255,255,255,.018);padding:11px;border-radius:14px}}.chronicle-icon{{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;background:#09090e;border:1px solid var(--line);font-size:18px}}.chronicle-event b{{display:block;font-size:9px}}.chronicle-event span{{display:block;font-size:8px;color:var(--muted);margin-top:3px}}.chronicle-event small{{font-size:7px;color:var(--muted)}}.feud-path-head b{{font-size:10px;letter-spacing:1px}}.feud-path-head span{{font-size:9px;color:var(--muted)}}.path-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:7px}}.path-step{{border:1px solid var(--line);border-radius:13px;padding:10px;background:rgba(255,255,255,.018);min-width:0}}.path-step.reached{{border-color:rgba(186,255,90,.25);background:rgba(186,255,90,.04)}}.path-step.next{{border-color:rgba(255,99,215,.34);background:rgba(255,79,216,.06);box-shadow:0 0 24px rgba(255,79,216,.06)}}.path-step.locked{{opacity:.58}}.path-icon{{font-size:20px}}.path-copy{{margin-top:7px}}.path-copy b{{display:block;font-size:8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}.path-copy span{{display:block;font-size:7px;color:var(--muted);margin-top:3px}}.escalation.legendary{{border-color:rgba(97,244,255,.28)}}.escalation.blood{{border-color:rgba(255,99,215,.28)}}.escalation.nemesis{{border-color:rgba(255,79,216,.24)}}.escalation.ignited{{border-color:rgba(255,179,77,.24)}}.footer{{text-align:center;color:#626270;padding:45px 0 20px}}
@media(max-width:900px){{.path-grid{{grid-template-columns:repeat(2,1fr)}}.chronicle-stats{{grid-template-columns:repeat(2,1fr)}}}}@media(max-width:680px){{.score{{grid-template-columns:1fr}}.mid{{order:-1}}.milestones{{grid-template-columns:1fr}}.path-grid{{grid-template-columns:1fr}}h1{{letter-spacing:-2px}}}}
</style></head><body><div class="shell">
<nav class="nav"><div class="brand">BL3<span>●</span></div><a class="back" href="/">← LIVE NETWORK</a></nav>
<section class="hero"><div class="eyebrow">PUBLIC RIVALRY // SHAREABLE RECORD</div>
<h1>{esc(hunter_a)} <span class="vs">VS</span> {esc(hunter_b)}</h1>
<div class="meta">{esc(status)} · Last winner: {esc(h2h["last_winner"] or "—")}</div>
<div class="score"><div class="side"><strong>{h2h["a_wins"]}</strong><span>{esc(hunter_a)}</span></div><div class="mid">{h2h["total"]} CLASHES</div><div class="side"><strong>{h2h["b_wins"]}</strong><span>{esc(hunter_b)}</span></div></div>
<div class="escalation {esc(escalation_tier["key"])}">
  <div class="escalation-top"><b>{esc(escalation_tier["icon"])} {esc(escalation_tier["label"])}</b><span>LEVEL {int(escalation_tier["level"])} / 5</span></div>
  <div class="escalation-bar"><i></i></div>
  <div class="escalation-meta"><span>{int(escalation["progress_percent"])}% ESCALATED</span><span>{("MAX RIVALRY TIER" if escalation_tier["next_at"] is None else str(int(escalation["clashes_to_next"])) + " CLASHES TO NEXT TIER")}</span></div>
</div>
<div class="feud-path">
  <div class="feud-path-head"><b>🌠 LEGENDARY FEUD PATH</b><span>{int(escalation["total"])} TOTAL CLASHES</span></div>
  <div class="path-grid">{path_html}</div>
</div>
<div class="actions"><a class="btn" href="{esc(challenge_url)}">⚔️ CHALLENGE {esc(hunter_b).upper()}</a><a class="btn alt" href="{esc(page_url)}">📣 SHARE RIVALRY</a><a class="btn alt" href="{esc(chronicle_card_url)}">📜 CHRONICLE CARD</a></div>
</section>
<section class="section"><div class="eyebrow">RIVALRY MILESTONES</div><h2>Badges Earned by the Story</h2><div class="milestones">{badges_html}</div></section>
<section class="section"><div class="eyebrow">📜 RIVALRY CHRONICLE // TURNING POINTS</div><h2>The Story So Far</h2>
<div class="chronicle-stats">
  <div class="chronicle-stat"><b>{int(chronicle["lead_changes"])}</b><span>LEAD CHANGES</span></div>
  <div class="chronicle-stat"><b>{int(chronicle["biggest_lead"])}</b><span>BIGGEST LEAD</span></div>
  <div class="chronicle-stat"><b>{int(chronicle["longest_streaks"].get(hunter_a,0))}</b><span>{esc(hunter_a).upper()} BEST STREAK</span></div>
  <div class="chronicle-stat"><b>{int(chronicle["longest_streaks"].get(hunter_b,0))}</b><span>{esc(hunter_b).upper()} BEST STREAK</span></div>
</div>
<div class="chronicle-stats" style="margin-top:8px">
  <div class="chronicle-stat"><b>{int(chronicle.get("completed_comebacks",{}).get(hunter_a,0))}</b><span>{esc(hunter_a).upper()} COMEBACKS</span></div>
  <div class="chronicle-stat"><b>{int(chronicle.get("completed_comebacks",{}).get(hunter_b,0))}</b><span>{esc(hunter_b).upper()} COMEBACKS</span></div>
  <div class="chronicle-stat"><b>{esc(chronicle.get("comeback_hunter") or "—")}</b><span>LATEST COMEBACK</span></div>
  <div class="chronicle-stat"><b>{int(chronicle["total"])}</b><span>COMPLETED CLASHES</span></div>
</div>
<div class="chronicle-list">{chronicle_events_html}</div></section>
<section class="section"><div class="eyebrow">RIVALRY HISTORY</div><h2>Recent Clashes</h2>{rows}</section>
<div class="footer">BL3 // BUILD. MEME. REPEAT. // V13.3 GLOBAL SEARCH</div>
</div></body></html>"""




def _hunter_unlock_snapshot(username):
    """Current unlock set derived from existing BL3 state."""
    user = _hunter_public_data(username)
    if user is None:
        return None

    items = []

    # Evolution unlocks are milestone-based so each stage can fire once.
    xp = int(user.get("xp") or 0)
    evo_milestones = [
        (100, "evolution:glitchling", "EVOLUTION", "👾", "GLITCHLING AWAKENED", "Reached 100 XP and evolved beyond the Seed stage."),
        (300, "evolution:chaos_spawn", "EVOLUTION", "😈", "CHAOS SPAWN EVOLVED", "Reached 300 XP and evolved into Chaos Spawn."),
        (700, "evolution:alpha_beast", "EVOLUTION", "🦹", "ALPHA BEAST UNLOCKED", "Reached 700 XP and entered Alpha Beast stage."),
        (1500, "evolution:crown_entity", "EVOLUTION", "👑", "CROWN ENTITY ASCENDED", "Reached 1500 XP and ascended into Crown Entity."),
    ]
    for threshold, key, kind, icon, title, detail in evo_milestones:
        if xp >= threshold:
            items.append({
                "key": key, "kind": kind, "icon": icon,
                "title": title, "detail": detail
            })

    # Trophy unlocks.
    trophy_data = _hunter_trophies(username) or {"trophies": []}
    for t in trophy_data.get("trophies", []):
        items.append({
            "key": f"trophy:{t['key']}",
            "kind": "TROPHY",
            "icon": t["icon"],
            "title": t["title"],
            "detail": t["detail"]
        })

    # Public titles backed by trophies. Skip neutral HUNTER fallback.
    for t in (_hunter_title_options(username) or []):
        if t["key"] == "hunter":
            continue
        items.append({
            "key": f"title:{t['key']}",
            "kind": "TITLE",
            "icon": t["icon"],
            "title": t["title"],
            "detail": f"New public title unlocked via {t.get('source') or 'BL3 progress'}."
        })

    # Skins.
    for s in (_hunter_skin_unlocks(username) or []):
        if not s.get("unlocked"):
            continue
        items.append({
            "key": f"skin:{s['key']}",
            "kind": "SKIN",
            "icon": s["icon"],
            "title": f"{s['name']} SKIN",
            "detail": f"{s['rarity']} Loadout skin unlocked."
        })

    # Stable order keeps first baseline deterministic.
    items.sort(key=lambda x: (x["kind"], x["key"]))
    return items


def _sync_hunter_unlocks(username):
    """
    First call silently records the current baseline.
    Later calls create feed events only for genuinely new unlocks.
    """
    snapshot = _hunter_unlock_snapshot(username)
    if snapshot is None:
        return None

    now = datetime.utcnow().isoformat()
    conn = db()
    existing_rows = conn.execute(
        "SELECT unlock_key FROM hunter_unlock_state WHERE username = ?",
        (username,)
    ).fetchall()
    existing = {r["unlock_key"] for r in existing_rows}
    is_first_sync = len(existing) == 0

    new_events = []
    for item in snapshot:
        if item["key"] in existing:
            continue

        conn.execute(
            """INSERT OR IGNORE INTO hunter_unlock_state(username, unlock_key, first_seen_at)
               VALUES (?, ?, ?)""",
            (username, item["key"], now)
        )

        # Avoid retroactive popup spam on first deployment/sync.
        if not is_first_sync:
            conn.execute(
                """INSERT OR IGNORE INTO hunter_unlock_events
                   (username, unlock_key, kind, icon, title, detail, created_at, is_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 0)""",
                (
                    username, item["key"], item["kind"], item["icon"],
                    item["title"], item["detail"], now
                )
            )
            new_events.append(item)

    conn.commit()
    conn.close()
    return new_events


@app.route("/api/unlocks/<username>")
def hunter_unlock_feed_api(username):
    if _hunter_public_data(username) is None:
        return jsonify({"success": False, "message": "Hunter not found"}), 404

    _sync_hunter_unlocks(username)

    try:
        limit = max(1, min(50, int(request.args.get("limit", 12))))
    except Exception:
        limit = 12

    conn = db()
    rows = conn.execute(
        """SELECT id, unlock_key, kind, icon, title, detail, created_at, is_seen
           FROM hunter_unlock_events
           WHERE username = ?
           ORDER BY id DESC
           LIMIT ?""",
        (username, limit)
    ).fetchall()
    unseen = int(conn.execute(
        "SELECT COUNT(*) AS n FROM hunter_unlock_events WHERE username = ? AND is_seen = 0",
        (username,)
    ).fetchone()["n"] or 0)
    conn.close()

    return jsonify({
        "success": True,
        "username": username,
        "unseen": unseen,
        "events": [dict(r) for r in rows]
    })


@app.route("/api/unlocks/<username>/seen", methods=["POST"])
def hunter_unlock_seen_api(username):
    if session.get("authenticated_username") != username:
        return jsonify({
            "success": False,
            "message": "Sign in with this Hunter ID to mark unlocks seen."
        }), 401

    payload = request.get_json(silent=True) or {}
    ids = payload.get("ids")
    conn = db()

    if isinstance(ids, list) and ids:
        clean_ids = [int(x) for x in ids if str(x).isdigit()]
        if clean_ids:
            placeholders = ",".join("?" for _ in clean_ids)
            conn.execute(
                f"""UPDATE hunter_unlock_events SET is_seen = 1
                    WHERE username = ? AND id IN ({placeholders})""",
                [username, *clean_ids]
            )
    else:
        conn.execute(
            "UPDATE hunter_unlock_events SET is_seen = 1 WHERE username = ?",
            (username,)
        )

    conn.commit()
    conn.close()
    return jsonify({"success": True})


def _hunter_progress_dashboard(username):
    """Unified next-unlock view across evolution, trophies, titles and skins."""
    conn = db()
    user = conn.execute(
        "SELECT username, xp, streak FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    if user is None:
        conn.close()
        return None

    xp = int(user["xp"] or 0)
    streak = int(user["streak"] or 0)
    rep = int(conn.execute(
        "SELECT COALESCE(SUM(points),0) AS n FROM reputation_events WHERE username = ?",
        (username,)
    ).fetchone()["n"] or 0)
    clash_wins = int(conn.execute(
        "SELECT COUNT(*) AS n FROM creature_battles WHERE winner = ?",
        (username,)
    ).fetchone()["n"] or 0)
    battles = int(conn.execute(
        "SELECT COUNT(*) AS n FROM creature_battles WHERE challenger = ? OR opponent = ?",
        (username, username)
    ).fetchone()["n"] or 0)
    referrals = int(conn.execute(
        "SELECT COUNT(*) AS n FROM referrals WHERE inviter = ?",
        (username,)
    ).fetchone()["n"] or 0)
    followers = int(conn.execute(
        "SELECT COUNT(*) AS n FROM hunter_connections WHERE target = ? AND kind = 'follow'",
        (username,)
    ).fetchone()["n"] or 0)
    arena_wins = int(conn.execute(
        "SELECT COUNT(*) AS n FROM arenas WHERE winner_username = ?",
        (username,)
    ).fetchone()["n"] or 0)
    paid_wins = int(conn.execute(
        "SELECT COUNT(*) AS n FROM arenas WHERE winner_username = ? AND paid = 1",
        (username,)
    ).fetchone()["n"] or 0)
    crown_defenses = int(conn.execute(
        "SELECT COUNT(*) AS n FROM crown_events WHERE defender = ? AND successful_defense = 1",
        (username,)
    ).fetchone()["n"] or 0)
    crown_breaks = int(conn.execute(
        "SELECT COUNT(*) AS n FROM crown_events WHERE challenger = ? AND winner = ? AND successful_defense = 0",
        (username, username)
    ).fetchone()["n"] or 0)
    conn.close()

    def pct(current, target):
        if target <= 0:
            return 100
        return max(0, min(100, round((current / target) * 100)))

    # Evolution path.
    evo_targets = [
        (100, "👾 GLITCHLING"),
        (300, "😈 CHAOS SPAWN"),
        (700, "🦹 ALPHA BEAST"),
        (1500, "👑 CROWN ENTITY"),
    ]
    next_evo = None
    for target, label in evo_targets:
        if xp < target:
            next_evo = {
                "kind": "EVOLUTION",
                "icon": "🧬",
                "title": label,
                "current": xp,
                "target": target,
                "percent": pct(xp, target),
                "detail": f"{target - xp} XP remaining"
            }
            break
    if next_evo is None:
        next_evo = {
            "kind": "EVOLUTION",
            "icon": "👑",
            "title": "CROWN ENTITY",
            "current": xp,
            "target": xp,
            "percent": 100,
            "detail": "Maximum evolution reached"
        }

    trophy_data = _hunter_trophies(username) or {"trophies": []}
    unlocked_trophy_keys = {t["key"] for t in trophy_data.get("trophies", [])}

    trophy_candidates = [
        ("reputation_100", "⚡", "100 REP", rep, 100, "Build reputation"),
        ("battle_hardened", "🛡️", "BATTLE HARDENED", battles, 10, "Complete 10 direct Clashes"),
        ("alpha_hunter", "😈", "ALPHA HUNTER", clash_wins, 10, "Win 10 direct Clashes"),
        ("network_builder", "👥", "NETWORK BUILDER", referrals, 5, "Refer 5 Hunters"),
        ("signal_magnet", "📡", "SIGNAL MAGNET", followers, 10, "Reach 10 followers"),
        ("arena_winner", "🎯", "ARENA WINNER", arena_wins, 1, "Win a project Arena"),
        ("proof_paid", "💎", "PROOF PAID", paid_wins, 1, "Have an Arena win marked paid"),
        ("crown_defender", "👑", "CROWN DEFENDER", crown_defenses, 1, "Defend the Crown"),
        ("crown_breaker", "💥", "CROWN BREAKER", crown_breaks, 1, "Break a Crown defense"),
        ("reputation_500", "🌠", "500 REP", rep, 500, "Reach 500 REP"),
        ("seven_day_flame", "🔥", "7-DAY FLAME", streak, 7, "Maintain a 7-day streak"),
        ("ascended", "👑", "ASCENDED", xp, 1500, "Reach 1500 XP"),
    ]
    locked_trophies = []
    for key, icon, title, current, target, detail in trophy_candidates:
        if key in unlocked_trophy_keys:
            continue
        locked_trophies.append({
            "key": key,
            "kind": "TROPHY",
            "icon": icon,
            "title": title,
            "current": current,
            "target": target,
            "percent": pct(current, target),
            "detail": detail
        })
    locked_trophies.sort(key=lambda x: (-x["percent"], x["target"] - x["current"]))
    next_trophy = locked_trophies[0] if locked_trophies else {
        "kind": "TROPHY", "icon": "🏆", "title": "TROPHY ROOM COMPLETE",
        "current": len(unlocked_trophy_keys), "target": len(unlocked_trophy_keys),
        "percent": 100, "detail": "No tracked Trophy unlock is closer."
    }

    # Titles come from trophies: show the strongest locked title path that is closest.
    title_options = _hunter_title_options(username) or []
    unlocked_title_keys = {t["key"] for t in title_options}
    title_map = {
        "reputation_100": ("⚡", "PROVEN HUNTER"),
        "battle_hardened": ("🛡️", "BATTLE HARDENED"),
        "alpha_hunter": ("😈", "ALPHA HUNTER"),
        "network_builder": ("👥", "NETWORK BUILDER"),
        "signal_magnet": ("📡", "SIGNAL MAGNET"),
        "arena_winner": ("🎯", "ARENA WINNER"),
        "proof_paid": ("💎", "PROOF HUNTER"),
        "crown_defender": ("👑", "CROWN DEFENDER"),
        "crown_breaker": ("💥", "CROWN BREAKER"),
        "reputation_500": ("🌠", "REPUTATION ELITE"),
        "seven_day_flame": ("🔥", "FLAMEKEEPER"),
        "ascended": ("👑", "CROWN ENTITY"),
    }
    title_candidates = []
    for item in locked_trophies:
        if item["key"] in title_map and item["key"] not in unlocked_title_keys:
            icon, title_name = title_map[item["key"]]
            title_candidates.append({
                "kind": "TITLE",
                "icon": icon,
                "title": title_name,
                "current": item["current"],
                "target": item["target"],
                "percent": item["percent"],
                "detail": f"Unlock via {item['title']}"
            })
    title_candidates.sort(key=lambda x: -x["percent"])
    next_title = title_candidates[0] if title_candidates else {
        "kind": "TITLE", "icon": "🏷️", "title": "TITLE COLLECTION ACTIVE",
        "current": len(title_options), "target": len(title_options),
        "percent": 100, "detail": "Use any unlocked title from your collection."
    }

    skin_options = _hunter_skin_unlocks(username) or []
    locked_skins = []
    for s in skin_options:
        if s.get("unlocked"):
            continue
        p = s.get("progress", {})
        locked_skins.append({
            "kind": "SKIN",
            "icon": s["icon"],
            "title": f"{s['name']} // {s['rarity']}",
            "current": int(p.get("percent", 0)),
            "target": 100,
            "percent": int(p.get("percent", 0)),
            "detail": p.get("label", s.get("requirement", ""))
        })
    locked_skins.sort(key=lambda x: -x["percent"])
    next_skin = locked_skins[0] if locked_skins else {
        "kind": "SKIN", "icon": "🎨", "title": "ALL CURRENT SKINS UNLOCKED",
        "current": 100, "target": 100, "percent": 100,
        "detail": "Every current Loadout skin is available."
    }

    cards = [next_evo, next_trophy, next_title, next_skin]
    incomplete = [c for c in cards if c["percent"] < 100]
    closest = max(incomplete, key=lambda c: c["percent"]) if incomplete else cards[0]

    return {
        "username": username,
        "closest": closest,
        "cards": cards,
        "stats": {
            "xp": xp,
            "rep": rep,
            "streak": streak,
            "clash_wins": clash_wins,
            "battles": battles
        }
    }


@app.route("/api/progress/<username>")
def hunter_progress_api(username):
    data = _hunter_progress_dashboard(username)
    if data is None:
        return jsonify({"success": False, "message": "Hunter not found"}), 404
    return jsonify({"success": True, **data})


def _loadout_skin_catalog():
    return {
        "neon": {
            "key": "neon",
            "name": "NEON",
            "icon": "⚡",
            "rarity": "COMMON",
            "requirement": "Unlocked by default",
            "unlock_any": [],
            "bg0": "#050507",
            "bg1": "#101017",
            "bg2": "#1b1028",
            "accent": "#b8ff5a",
            "accent2": "#9d7bff",
            "gold": "#ffd86b",
            "card": "#0d0d13",
            "line": "#2a2a35",
            "muted": "#8f8f9e"
        },
        "void": {
            "key": "void",
            "name": "VOID",
            "icon": "🌑",
            "rarity": "RARE",
            "requirement": "Unlock PROVEN HUNTER or REPUTATION ELITE",
            "unlock_any": ["reputation_100", "reputation_500"],
            "bg0": "#020205",
            "bg1": "#080812",
            "bg2": "#11112a",
            "accent": "#8ea1ff",
            "accent2": "#5f6dff",
            "gold": "#b9c4ff",
            "card": "#080811",
            "line": "#24243d",
            "muted": "#82829c"
        },
        "crown": {
            "key": "crown",
            "name": "CROWN",
            "icon": "👑",
            "rarity": "LEGENDARY",
            "requirement": "Unlock CROWN DEFENDER, CROWN BREAKER, or ASCENDED",
            "unlock_any": ["crown_defender", "crown_breaker", "ascended"],
            "bg0": "#090704",
            "bg1": "#181109",
            "bg2": "#2a1b09",
            "accent": "#ffd86b",
            "accent2": "#ff9f43",
            "gold": "#ffe7a3",
            "card": "#161007",
            "line": "#4a3517",
            "muted": "#b3a58b"
        },
        "chaos": {
            "key": "chaos",
            "name": "CHAOS",
            "icon": "😈",
            "rarity": "EPIC",
            "requirement": "Unlock ALPHA HUNTER or NEMESIS FOUND",
            "unlock_any": ["alpha_hunter", "nemesis_found"],
            "bg0": "#09030b",
            "bg1": "#1c071d",
            "bg2": "#280b18",
            "accent": "#ff4fd8",
            "accent2": "#ff6b35",
            "gold": "#ffcc70",
            "card": "#160817",
            "line": "#4b1e45",
            "muted": "#b38aa9"
        }
    }


def _hunter_skin_unlocks(username):
    """Return skin options with unlock state + visible progress."""
    trophies = _hunter_trophies(username)
    progress = _hunter_skin_progress(username)
    if trophies is None or progress is None:
        return None

    trophy_keys = {t["key"] for t in trophies.get("trophies", [])}
    catalog = _loadout_skin_catalog()
    options = []

    for skin in catalog.values():
        requirements = skin.get("unlock_any", [])
        unlocked = not requirements or any(key in trophy_keys for key in requirements)
        public = {k: v for k, v in skin.items() if k != "unlock_any"}
        public["unlocked"] = unlocked
        public["progress"] = {
            "percent": 100 if unlocked else int(progress.get(skin["key"], {}).get("percent", 0)),
            "label": "UNLOCKED" if unlocked else progress.get(skin["key"], {}).get("label", skin["requirement"])
        }
        options.append(public)

    return options


def _hunter_skin_progress(username):
    """Progress toward each locked skin using existing BL3 activity only."""
    conn = db()
    user = conn.execute(
        "SELECT username, xp FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    if user is None:
        conn.close()
        return None

    xp = int(user["xp"] or 0)
    rep = int(conn.execute(
        "SELECT COALESCE(SUM(points),0) AS n FROM reputation_events WHERE username = ?",
        (username,)
    ).fetchone()["n"] or 0)

    clash_wins = int(conn.execute(
        """SELECT COUNT(*) AS n
           FROM creature_battles
           WHERE winner = ?""",
        (username,)
    ).fetchone()["n"] or 0)

    strongest_rival = conn.execute(
        """SELECT COUNT(*) AS clashes
           FROM creature_battles
           WHERE challenger = ? OR opponent = ?
           GROUP BY CASE WHEN challenger = ? THEN opponent ELSE challenger END
           ORDER BY clashes DESC LIMIT 1""",
        (username, username, username)
    ).fetchone()
    rival_clashes = int(strongest_rival["clashes"] or 0) if strongest_rival else 0

    crown_defenses = int(conn.execute(
        """SELECT COUNT(*) AS n FROM crown_events
           WHERE defender = ? AND successful_defense = 1""",
        (username,)
    ).fetchone()["n"] or 0)

    crown_breaks = int(conn.execute(
        """SELECT COUNT(*) AS n FROM crown_events
           WHERE challenger = ? AND winner = ? AND successful_defense = 0""",
        (username, username)
    ).fetchone()["n"] or 0)

    conn.close()

    # For OR-based unlocks, show the closest path to completion.
    def pct(current, target):
        if target <= 0:
            return 100
        return max(0, min(100, round((current / target) * 100)))

    void_paths = [
        {"label": "REP", "current": rep, "target": 100, "percent": pct(rep, 100)},
        {"label": "REP ELITE", "current": rep, "target": 500, "percent": pct(rep, 500)},
    ]
    chaos_paths = [
        {"label": "CLASH WINS", "current": clash_wins, "target": 10, "percent": pct(clash_wins, 10)},
        {"label": "NEMESIS CLASHES", "current": rival_clashes, "target": 5, "percent": pct(rival_clashes, 5)},
    ]
    crown_paths = [
        {"label": "CROWN DEFENSE", "current": crown_defenses, "target": 1, "percent": pct(crown_defenses, 1)},
        {"label": "CROWN BREAK", "current": crown_breaks, "target": 1, "percent": pct(crown_breaks, 1)},
        {"label": "ASCENDED XP", "current": xp, "target": 1500, "percent": pct(xp, 1500)},
    ]

    def best(paths):
        return max(paths, key=lambda x: (x["percent"], x["current"]))

    return {
        "neon": {
            "percent": 100,
            "label": "Unlocked by default",
            "current": 1,
            "target": 1
        },
        "void": {
            **best(void_paths),
            "label": f"{best(void_paths)['current']} / {best(void_paths)['target']} {best(void_paths)['label']}"
        },
        "chaos": {
            **best(chaos_paths),
            "label": f"{best(chaos_paths)['current']} / {best(chaos_paths)['target']} {best(chaos_paths)['label']}"
        },
        "crown": {
            **best(crown_paths),
            "label": f"{best(crown_paths)['current']} / {best(crown_paths)['target']} {best(crown_paths)['label']}"
        }
    }


def _hunter_loadout_skin(username):
    catalog = _loadout_skin_catalog()
    unlocks = _hunter_skin_unlocks(username)
    if unlocks is None:
        return None

    unlocked_keys = {s["key"] for s in unlocks if s["unlocked"]}

    conn = db()
    row = conn.execute(
        "SELECT skin_key FROM hunter_loadout_skins WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    requested = row["skin_key"] if row else "neon"
    key = requested if requested in catalog and requested in unlocked_keys else "neon"
    return {**catalog[key], "unlocked": True}


@app.route("/api/skin-progress/<username>")
def hunter_skin_progress_api(username):
    options = _hunter_skin_unlocks(username)
    if options is None:
        return jsonify({"success": False, "message": "Hunter not found"}), 404
    return jsonify({
        "success": True,
        "username": username,
        "skins": [
            {
                "key": s["key"],
                "name": s["name"],
                "icon": s["icon"],
                "rarity": s["rarity"],
                "unlocked": s["unlocked"],
                "requirement": s["requirement"],
                "progress": s.get("progress", {"percent": 0, "label": ""})
            }
            for s in options
        ]
    })


@app.route("/api/loadout-skin/<username>", methods=["GET", "POST"])
def hunter_loadout_skin_api(username):
    current = _hunter_loadout_skin(username)
    options = _hunter_skin_unlocks(username)
    if current is None or options is None:
        return jsonify({"success": False, "message": "Hunter not found"}), 404

    if request.method == "GET":
        return jsonify({
            "success": True,
            "username": username,
            "current": current,
            "options": options
        })

    if session.get("authenticated_username") != username:
        return jsonify({
            "success": False,
            "message": "Sign in with this Hunter ID to change Loadout skin."
        }), 401

    payload = request.get_json(silent=True) or {}
    skin_key = str(payload.get("skin_key", "")).strip().lower()
    by_key = {s["key"]: s for s in options}

    if skin_key not in by_key:
        return jsonify({"success": False, "message": "Unknown Loadout skin."}), 400

    if not by_key[skin_key]["unlocked"]:
        return jsonify({
            "success": False,
            "message": f"🔒 {by_key[skin_key]['name']} is locked. {by_key[skin_key]['requirement']}."
        }), 403

    conn = db()
    conn.execute(
        """INSERT INTO hunter_loadout_skins(username, skin_key, updated_at)
           VALUES (?, ?, ?)
           ON CONFLICT(username) DO UPDATE SET
             skin_key = excluded.skin_key,
             updated_at = excluded.updated_at""",
        (username, skin_key, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"{by_key[skin_key]['icon']} Equipped {by_key[skin_key]['name']} skin",
        "current": by_key[skin_key]
    })


@app.route("/loadout/<username>/card.svg")
def hunter_loadout_card_svg(username):
    d = _hunter_public_data(username)
    if d is None:
        return Response("Hunter not found", status=404, mimetype="text/plain")

    hunter_title = _hunter_title(username) or {
        "title": "HUNTER", "icon": "👾", "tier": "UNRANKED"
    }
    showcase = _hunter_showcase(username) or {"featured": None}
    featured = showcase.get("featured")
    skin = _hunter_loadout_skin(username) or _loadout_skin_catalog()["neon"]
    esc = lambda v: html.escape(str(v or ""))

    featured_title = featured["title"] if featured else "NO FEATURED TROPHY"
    featured_icon = featured["icon"] if featured else "🏆"
    featured_tier = featured["tier"] if featured else "UNRANKED"

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
      <defs>
        <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
          <stop stop-color="{skin['bg0']}"/>
          <stop offset=".55" stop-color="{skin['bg1']}"/>
          <stop offset="1" stop-color="{skin['bg2']}"/>
        </linearGradient>
        <linearGradient id="accent" x1="0" x2="1">
          <stop stop-color="{skin['accent']}"/>
          <stop offset="1" stop-color="{skin['accent2']}"/>
        </linearGradient>
        <filter id="glow">
          <feGaussianBlur stdDeviation="8" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>

      <rect width="1200" height="630" rx="36" fill="url(#bg)"/>
      <rect x="1" y="1" width="1198" height="628" rx="35" fill="none" stroke="{skin['line']}" stroke-width="2"/>

      <text x="68" y="70" fill="{skin['accent']}" font-family="Arial,sans-serif" font-size="22" font-weight="900" letter-spacing="3">BL3 // HUNTER LOADOUT</text>
      <text x="1130" y="70" fill="{skin['muted']}" font-family="Arial,sans-serif" font-size="17" text-anchor="end">{esc(skin['icon'])} {esc(skin['name'])} SKIN</text>

      <rect x="68" y="118" width="260" height="350" rx="28" fill="{skin['card']}" stroke="{skin['line']}"/>
      <text x="198" y="245" fill="#ffffff" font-family="Arial,sans-serif" font-size="94" text-anchor="middle">{esc(d['creature']['avatar'])}</text>
      <text x="198" y="315" fill="#ffffff" font-family="Arial,sans-serif" font-size="29" font-weight="900" text-anchor="middle">{esc(d['creature']['name'])}</text>
      <text x="198" y="350" fill="{skin['accent2']}" font-family="Arial,sans-serif" font-size="18" font-weight="900" text-anchor="middle">{esc(d['creature']['stage'])}</text>
      <text x="198" y="397" fill="{skin['muted']}" font-family="Arial,sans-serif" font-size="16" text-anchor="middle">LEVEL {d['level']}  •  {d['xp']} XP</text>

      <text x="380" y="165" fill="#ffffff" font-family="Arial,sans-serif" font-size="66" font-weight="950">{esc(username)}</text>
      <text x="380" y="215" fill="url(#accent)" font-family="Arial,sans-serif" font-size="25" font-weight="900" filter="url(#glow)">{esc(hunter_title['icon'])} {esc(hunter_title['title'])}</text>
      <text x="380" y="246" fill="{skin['muted']}" font-family="Arial,sans-serif" font-size="15" font-weight="900" letter-spacing="2">{esc(hunter_title['tier'])}</text>

      <rect x="380" y="286" width="752" height="118" rx="20" fill="{skin['card']}" stroke="{skin['line']}"/>
      <text x="408" y="322" fill="{skin['gold']}" font-family="Arial,sans-serif" font-size="15" font-weight="900" letter-spacing="2">FEATURED TROPHY</text>
      <text x="408" y="362" fill="#ffffff" font-family="Arial,sans-serif" font-size="26" font-weight="900">{esc(featured_icon)} {esc(featured_title)}</text>
      <text x="408" y="389" fill="{skin['muted']}" font-family="Arial,sans-serif" font-size="14">{esc(featured_tier)}</text>

      <rect x="380" y="430" width="752" height="1" fill="{skin['line']}"/>
      <text x="380" y="477" fill="#ffffff" font-family="Arial,sans-serif" font-size="20" font-weight="900">{d['reputation']} REP</text>
      <text x="555" y="477" fill="#ffffff" font-family="Arial,sans-serif" font-size="20" font-weight="900">{d['wins']} WINS</text>
      <text x="720" y="477" fill="#ffffff" font-family="Arial,sans-serif" font-size="20" font-weight="900">{d['network']} NETWORK</text>
      <text x="930" y="477" fill="#ffffff" font-family="Arial,sans-serif" font-size="20" font-weight="900">XP RANK #{d['xp_rank'] or '—'}</text>

      <text x="68" y="559" fill="{skin['muted']}" font-family="Arial,sans-serif" font-size="17">HUNT ALPHA. EARN REPUTATION.</text>
      <text x="1130" y="559" fill="{skin['accent']}" font-family="Arial,sans-serif" font-size="17" font-weight="900" text-anchor="end">BL3MEME.COM</text>
    </svg>"""
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "public, max-age=120"})



@app.route("/progress/<username>")
def hunter_progress_page(username):
    data = _hunter_progress_dashboard(username)
    if data is None:
        return "Hunter not found", 404

    esc = lambda v: html.escape(str(v or ""))
    root = request.url_root.rstrip("/")
    profile_url = f"{root}/hunter/{urllib.parse.quote(username)}"
    loadout_url = f"{root}/loadout/{urllib.parse.quote(username)}"

    _sync_hunter_unlocks(username)
    conn = db()
    unlock_rows = conn.execute(
        """SELECT id, kind, icon, title, detail, created_at, is_seen
           FROM hunter_unlock_events
           WHERE username = ?
           ORDER BY id DESC
           LIMIT 8""",
        (username,)
    ).fetchall()
    conn.close()

    unlock_feed_html = ""
    for e in unlock_rows:
        unlock_feed_html += (
            f'<div class="unlock-row{" unseen" if not e["is_seen"] else ""}" data-unlock-id="{int(e["id"])}">'
            f'<div class="unlock-icon">{esc(e["icon"])}</div>'
            f'<div class="unlock-copy"><div class="unlock-kind">{esc(e["kind"])}</div>'
            f'<b>{esc(e["title"])}</b><span>{esc(e["detail"])}</span></div></div>'
        )
    if not unlock_feed_html:
        unlock_feed_html = '<div class="empty-feed">No new unlock events yet. Your current progress is now the baseline.</div>'

    cards_html = ""
    for c in data["cards"]:
        cards_html += (
            f'<div class="progress-card">'
            f'<div class="progress-head"><div><span>{esc(c["kind"])}</span>'
            f'<h3>{esc(c["icon"])} {esc(c["title"])}</h3></div>'
            f'<b>{int(c["percent"])}%</b></div>'
            f'<div class="bar"><i style="width:{int(c["percent"])}%"></i></div>'
            f'<div class="meta">{esc(c["detail"])}</div>'
            f'</div>'
        )

    closest = data["closest"]
    return f"""<!doctype html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(username)} // Progress Dashboard // BL3</title>
<style>
:root{{--bg:#08080d;--card:#111119;--line:#292934;--muted:#9393a4;--hot:#b8ff5a;--violet:#9d7bff}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 50% -10%,#271840 0,#08080d 48%);color:#fff;font-family:Arial,sans-serif}}
.shell{{max-width:1000px;margin:auto;padding:28px}}.nav{{display:flex;justify-content:space-between;gap:12px;align-items:center}}.brand{{font-size:24px;font-weight:900}}.brand span,.eyebrow{{color:var(--hot)}}.nav a{{color:#fff;text-decoration:none;border:1px solid var(--line);padding:10px 14px;border-radius:999px}}
.hero{{margin-top:54px}}h1{{font-size:clamp(46px,8vw,82px);letter-spacing:-4px;margin:8px 0}}.meta{{color:var(--muted)}}.closest{{margin-top:26px;border:1px solid rgba(184,255,90,.32);background:linear-gradient(145deg,rgba(184,255,90,.06),rgba(157,123,255,.07));padding:22px;border-radius:24px}}.closest strong{{display:block;font-size:30px;margin-top:6px}}.closest b{{color:var(--hot)}}
.grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-top:18px}}.progress-card{{border:1px solid var(--line);background:var(--card);padding:18px;border-radius:20px}}.progress-head{{display:flex;justify-content:space-between;gap:14px;align-items:flex-start}}.progress-head span{{font-size:9px;letter-spacing:1.5px;color:var(--muted);font-weight:900}}.progress-head h3{{margin:5px 0 0;font-size:20px}}.progress-head b{{font-size:22px;color:var(--hot)}}.bar{{height:8px;border:1px solid var(--line);background:#08080c;border-radius:999px;overflow:hidden;margin:16px 0 10px}}.bar i{{display:block;height:100%;background:linear-gradient(90deg,var(--hot),var(--violet));border-radius:999px}}
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:18px}}.stat{{border:1px solid var(--line);background:#0d0d12;padding:14px;border-radius:16px}}.stat b{{font-size:22px;display:block}}.stat span{{font-size:9px;color:var(--muted);font-weight:900;letter-spacing:1px}}.unlock-section{{margin-top:24px;border:1px solid rgba(157,123,255,.24);background:linear-gradient(145deg,rgba(157,123,255,.05),rgba(184,255,90,.03));border-radius:24px;padding:20px}}.unlock-section h2{{margin:6px 0 4px}}.unlock-list{{display:grid;gap:9px;margin-top:14px}}.unlock-row{{display:flex;gap:12px;align-items:center;border:1px solid var(--line);background:#0d0d12;padding:13px;border-radius:16px}}.unlock-row.unseen{{border-color:rgba(184,255,90,.32);box-shadow:0 0 18px rgba(184,255,90,.04)}}.unlock-icon{{font-size:26px;width:38px;text-align:center}}.unlock-copy{{display:flex;flex-direction:column;gap:3px}}.unlock-copy b{{font-size:13px}}.unlock-copy span{{font-size:10px;color:var(--muted)}}.unlock-kind{{font-size:8px;color:var(--hot);font-weight:900;letter-spacing:1.4px}}.empty-feed{{color:var(--muted);border:1px dashed var(--line);padding:16px;border-radius:14px;margin-top:12px}}.unlock-toast{{position:fixed;right:22px;bottom:22px;width:min(360px,calc(100vw - 44px));border:1px solid rgba(184,255,90,.42);background:#0d0d12;padding:16px;border-radius:18px;box-shadow:0 18px 60px rgba(0,0,0,.45);display:none;z-index:9999}}.unlock-toast.show{{display:block;animation:pop .22s ease-out}}.unlock-toast .big{{font-size:26px}}.unlock-toast b{{display:block;margin:5px 0}}.unlock-toast span{{font-size:11px;color:var(--muted)}}@keyframes pop{{from{{transform:translateY(10px);opacity:0}}to{{transform:translateY(0);opacity:1}}}}.footer{{text-align:center;color:#646473;padding:48px 0 18px}}
@media(max-width:720px){{.grid{{grid-template-columns:1fr}}.stats{{grid-template-columns:repeat(2,1fr)}}h1{{letter-spacing:-2px}}}}
</style></head><body><div class="shell">
<nav class="nav"><div class="brand">BL3<span>●</span></div><div><a href="{esc(profile_url)}">PROFILE</a> <a href="{esc(loadout_url)}">LOADOUT</a></div></nav>
<section class="hero"><div class="eyebrow">PROGRESSION RADAR // NEXT UNLOCKS</div><h1>{esc(username)}</h1><div class="meta">One place to see what your next meaningful BL3 unlock is.</div>
<div class="closest"><div class="eyebrow">CLOSEST UNLOCK</div><strong>{esc(closest["icon"])} {esc(closest["title"])}</strong><b>{int(closest["percent"])}% COMPLETE</b><div class="meta" style="margin-top:8px">{esc(closest["detail"])}</div></div>
<div class="stats"><div class="stat"><b>{data["stats"]["xp"]}</b><span>XP</span></div><div class="stat"><b>{data["stats"]["rep"]}</b><span>REP</span></div><div class="stat"><b>{data["stats"]["streak"]}</b><span>STREAK</span></div><div class="stat"><b>{data["stats"]["clash_wins"]}</b><span>CLASH WINS</span></div><div class="stat"><b>{data["stats"]["battles"]}</b><span>BATTLES</span></div></div>
<div class="grid">{cards_html}</div>
<section class="unlock-section"><div class="eyebrow">✨ UNLOCK FEED // NEW ACHIEVEMENTS</div><h2>Recent Unlocks</h2><div class="meta">New Trophy, Title, Skin, and Evolution unlocks appear here after your baseline is established.</div><div class="unlock-list" id="unlockList">{unlock_feed_html}</div></section>
</section>
<div class="footer">BL3 // BUILD. MEME. REPEAT. // V13.3 GLOBAL SEARCH</div>
</div>
<div class="unlock-toast" id="unlockToast"><div class="eyebrow">NEW UNLOCK</div><div class="big" id="unlockToastIcon">✨</div><b id="unlockToastTitle">Unlocked</b><span id="unlockToastDetail"></span></div>
<script>
const progressHunter={json.dumps(username)};
let lastUnlockId=Math.max(0,...Array.from(document.querySelectorAll('[data-unlock-id]')).map(x=>Number(x.dataset.unlockId)||0));
async function pollUnlocks(){{
  const r=await fetch('/api/unlocks/'+encodeURIComponent(progressHunter)+'?limit=8');
  let d={{}};try{{d=await r.json()}}catch(e){{}}
  if(!d.success||!Array.isArray(d.events))return;
  const newest=d.events.find(e=>Number(e.id)>lastUnlockId);
  if(newest){{
    lastUnlockId=Math.max(...d.events.map(e=>Number(e.id)||0),lastUnlockId);
    const toast=document.getElementById('unlockToast');
    document.getElementById('unlockToastIcon').textContent=newest.icon||'✨';
    document.getElementById('unlockToastTitle').textContent=(newest.kind||'UNLOCK')+' // '+(newest.title||'Unlocked');
    document.getElementById('unlockToastDetail').textContent=newest.detail||'';
    toast.classList.add('show');
    setTimeout(()=>toast.classList.remove('show'),5000);
    setTimeout(()=>location.reload(),5400);
  }}
}}
let unlockPollTimer=null;
function startUnlockPolling(){{
  if(unlockPollTimer)clearInterval(unlockPollTimer);
  unlockPollTimer=setInterval(()=>{{if(!document.hidden)pollUnlocks()}},15000);
}}
document.addEventListener('visibilitychange',()=>{{if(!document.hidden)pollUnlocks()}});
startUnlockPolling();
setTimeout(()=>{{if(!document.hidden)pollUnlocks()}},2500);
setTimeout(async()=>{{
  const unseen=[...document.querySelectorAll('.unlock-row.unseen')].map(x=>Number(x.dataset.unlockId)).filter(Boolean);
  if(!unseen.length)return;
  try{{
    await fetch('/api/unlocks/'+encodeURIComponent(progressHunter)+'/seen',{{
      method:'POST',
      headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{ids:unseen}})
    }});
  }}catch(e){{}}
}},1800);
</script></body></html>"""


@app.route("/loadout/<username>")
def hunter_loadout_page(username):
    d = _hunter_public_data(username)
    if d is None:
        return "Hunter not found", 404

    hunter_title = _hunter_title(username) or {
        "title": "HUNTER", "icon": "👾", "tier": "UNRANKED"
    }
    showcase = _hunter_showcase(username) or {"featured": None}
    featured = showcase.get("featured")
    skin = _hunter_loadout_skin(username) or {**_loadout_skin_catalog()["neon"], "unlocked": True}
    skin_options = _hunter_skin_unlocks(username) or []
    viewer = session.get("authenticated_username") or ""
    is_owner = viewer == username
    esc = lambda v: html.escape(str(v or ""))

    root = request.url_root.rstrip("/")
    page_url = f"{root}/loadout/{urllib.parse.quote(username)}"
    image_url = page_url + "/card.svg"
    profile_url = f"{root}/hunter/{urllib.parse.quote(username)}"

    featured_html = (
        f'<div class="featured"><div class="featured-icon">{esc(featured["icon"])}</div>'
        f'<div><div class="small">FEATURED TROPHY</div><h3>{esc(featured["title"])}</h3>'
        f'<div class="meta">{esc(featured["detail"])}</div>'
        f'<span>{esc(featured["tier"])}</span></div></div>'
        if featured else
        '<div class="featured"><div class="featured-icon">🏆</div><div><div class="small">FEATURED TROPHY</div><h3>None yet</h3><div class="meta">Unlock and pin a Trophy from your public Hunter profile.</div></div></div>'
    )

    skin_picker = ""
    if is_owner:
        skin_picker = '<div class="skin-panel"><div><div class="small">LOADOUT SKIN</div><div class="meta">Choose a visual identity for this public card. Locked skins show your closest unlock path in real time.</div></div><div class="skin-options">'
        for s in skin_options:
            active = s["key"] == skin["key"]
            locked = not s.get("unlocked", False)
            classes = "skin-btn" + (" active" if active else "") + (" locked" if locked else "")
            disabled = " disabled" if locked else ""
            progress = s.get("progress", {"percent": 100 if not locked else 0, "label": ""})
            skin_picker += (
                f'<div class="skin-choice">'
                f'<button class="{classes}" data-skin-key="{esc(s["key"])}"{disabled}>'
                f'{"🔒 " if locked else ""}{esc(s["icon"])} {esc(s["name"])}'
                f'<small>{esc(s.get("rarity",""))}</small></button>'
                f'<div class="skin-progress-head"><span>{esc(progress.get("label",""))}</span>'
                f'<b>{int(progress.get("percent",0))}%</b></div>'
                f'<div class="skin-progress"><i style="width:{int(progress.get("percent",0))}%"></i></div>'
                f'<span>{esc(s.get("requirement",""))}</span></div>'
            )
        skin_picker += '</div></div>'

    title = f"{username} // Hunter Loadout // BL3"
    desc = f"{skin['icon']} {skin['name']} Loadout • {hunter_title['icon']} {hunter_title['title']} • {d['creature']['name']} • {d['reputation']} REP • {d['wins']} wins."

    return f"""<!doctype html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title>
<meta name="description" content="{esc(desc)}">
<meta property="og:title" content="{esc(title)}">
<meta property="og:description" content="{esc(desc)}">
<meta property="og:image" content="{esc(image_url)}">
<meta property="og:url" content="{esc(page_url)}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{esc(title)}">
<meta name="twitter:description" content="{esc(desc)}">
<meta name="twitter:image" content="{esc(image_url)}">
<style>
:root{{--bg:{skin['bg0']};--card:{skin['card']};--line:{skin['line']};--muted:{skin['muted']};--hot:{skin['accent']};--violet:{skin['accent2']};--gold:{skin['gold']}}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 50% -15%,{skin['bg2']} 0,{skin['bg0']} 52%);color:#fff;font-family:Arial,sans-serif}}
.shell{{max-width:1000px;margin:auto;padding:28px}}.nav{{display:flex;justify-content:space-between;align-items:center}}.brand{{font-size:24px;font-weight:900}}.brand span,.eyebrow{{color:var(--hot)}}.back{{color:#fff;text-decoration:none;border:1px solid var(--line);padding:10px 14px;border-radius:999px}}
.hero{{margin-top:55px}}.eyebrow{{font-size:12px;font-weight:900;letter-spacing:2px}}h1{{font-size:clamp(48px,8vw,86px);margin:8px 0;letter-spacing:-4px}}.meta{{color:var(--muted)}}.layout{{display:grid;grid-template-columns:300px 1fr;gap:18px;margin-top:28px}}
.creature,.identity,.featured,.stat{{border:1px solid var(--line);background:var(--card);border-radius:24px}}.creature{{padding:28px;text-align:center}}.avatar{{font-size:94px}}.creature h2{{margin:16px 0 5px}}.stage{{color:var(--violet);font-weight:900;font-size:12px;letter-spacing:2px}}
.identity{{padding:24px}}.title{{display:inline-flex;gap:8px;align-items:center;color:var(--hot);font-size:15px;font-weight:900;border:1px solid rgba(184,255,90,.25);padding:9px 12px;border-radius:999px}}.tier{{font-size:9px;color:var(--muted);letter-spacing:1px}}
.featured{{display:flex;gap:15px;align-items:center;padding:18px;margin-top:16px;background:linear-gradient(145deg,#111119,#181220)}}.featured-icon{{font-size:44px}}.featured h3{{margin:4px 0}}.featured span{{display:inline-block;color:var(--gold);font-size:9px;font-weight:900;border:1px solid rgba(255,216,107,.3);padding:5px 8px;border-radius:999px;margin-top:8px}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:16px}}.stat{{padding:16px}}.stat b{{display:block;font-size:25px}}.stat span,.small{{color:var(--muted);font-size:10px;letter-spacing:1.2px;font-weight:900}}
.actions{{display:flex;gap:10px;flex-wrap:wrap;margin-top:22px}}.btn{{text-decoration:none;color:#07070b;background:var(--hot);font-weight:900;padding:13px 16px;border-radius:14px}}.btn.alt{{color:#fff;background:var(--violet)}}.skin-panel{{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-top:18px;padding:16px;border:1px solid var(--line);border-radius:20px;background:var(--card)}}.skin-options{{display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end}}.skin-choice{{display:flex;flex-direction:column;gap:5px;min-width:180px;max-width:210px}}.skin-choice span{{font-size:8px;color:var(--muted);line-height:1.25}}.skin-progress-head{{display:flex;justify-content:space-between;gap:8px;align-items:center}}.skin-progress-head b{{font-size:9px;color:var(--hot)}}.skin-progress{{height:5px;border-radius:999px;background:#08080c;border:1px solid var(--line);overflow:hidden}}.skin-progress i{{display:block;height:100%;border-radius:999px;background:linear-gradient(90deg,var(--hot),var(--violet));box-shadow:0 0 14px color-mix(in srgb,var(--hot) 30%,transparent)}}.skin-btn{{border:1px solid var(--line);background:transparent;color:#fff;padding:9px 12px;border-radius:999px;font-size:10px;font-weight:900;cursor:pointer;white-space:nowrap}}.skin-btn small{{margin-left:6px;color:var(--muted);font-size:8px;letter-spacing:1px}}.skin-btn:hover,.skin-btn.active{{border-color:var(--hot);color:var(--hot);box-shadow:0 0 18px color-mix(in srgb,var(--hot) 18%,transparent)}}.skin-btn.locked{{opacity:.48;cursor:not-allowed;filter:saturate(.45)}}.skin-btn.locked:hover{{border-color:var(--line);color:#fff;box-shadow:none}}.footer{{text-align:center;color:var(--muted);padding:50px 0 20px}}
@media(max-width:760px){{.layout{{grid-template-columns:1fr}}.stats{{grid-template-columns:repeat(2,1fr)}}.skin-panel{{align-items:flex-start;flex-direction:column}}.skin-options{{justify-content:flex-start}}h1{{letter-spacing:-2px}}}}
</style></head><body><div class="shell">
<nav class="nav"><div class="brand">BL3<span>●</span></div><a class="back" href="{esc(profile_url)}">← HUNTER PROFILE</a></nav>
<section class="hero"><div class="eyebrow">HUNTER LOADOUT // PUBLIC IDENTITY CARD // {esc(skin['icon'])} {esc(skin['name'])}</div><h1>{esc(username)}</h1><div class="meta">Creature + Title + Featured Trophy + proof stats in one shareable identity.</div>
{skin_picker}
<div class="layout"><div class="creature"><div class="avatar">{esc(d['creature']['avatar'])}</div><h2>{esc(d['creature']['name'])}</h2><div class="stage">{esc(d['creature']['stage'])}</div><div class="meta" style="margin-top:10px">LEVEL {d['level']} · {d['xp']} XP</div></div>
<div class="identity"><div class="title">{esc(hunter_title['icon'])} {esc(hunter_title['title'])} <span class="tier">{esc(hunter_title['tier'])}</span></div>
{featured_html}
<div class="stats"><div class="stat"><b>{d['reputation']}</b><span>REP</span></div><div class="stat"><b>{d['wins']}</b><span>WINS</span></div><div class="stat"><b>{d['network']}</b><span>NETWORK</span></div><div class="stat"><b>#{d['xp_rank'] or '—'}</b><span>XP RANK</span></div></div>
<div class="actions"><a class="btn" href="{esc(profile_url)}">VIEW FULL PROFILE</a><a class="btn alt" href="/progress/{urllib.parse.quote(username)}">📈 PROGRESS</a><a class="btn alt" href="{esc(page_url)}">SHARE LOADOUT</a></div></div></div></section>
<div class="footer">BL3 // BUILD. MEME. REPEAT. // V13.3 GLOBAL SEARCH</div>
</div>
<script>
document.querySelectorAll('.skin-btn:not(.locked)').forEach(btn=>btn.addEventListener('click',async()=>{{
  const key=btn.dataset.skinKey;
  const r=await fetch('/api/loadout-skin/'+encodeURIComponent({json.dumps(username)}),{{
    method:'POST',
    headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{skin_key:key}})
  }});
  let d={{}};try{{d=await r.json()}}catch(e){{}}
  if(!d.success){{alert(d.message||'Could not change skin.');return}}
  location.reload();
}}));
</script></body></html>"""


def _featured_nemesis(username):
    conn = db()
    owner = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    if owner is None:
        conn.close()
        return None
    row = conn.execute(
        "SELECT rival, updated_at FROM hunter_featured_nemesis WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    if row is None:
        return {"username": username, "featured": None}

    rival = str(row["rival"] or "").strip()
    if not rival or rival == username:
        return {"username": username, "featured": None}

    conn = db()
    rival_row = conn.execute(
        "SELECT xp FROM users WHERE username = ?",
        (rival,)
    ).fetchone()
    tracked = conn.execute(
        """SELECT 1 FROM hunter_connections
           WHERE owner = ? AND target = ? AND kind = 'rival'""",
        (username, rival)
    ).fetchone() is not None
    conn.close()

    if rival_row is None or not tracked:
        return {"username": username, "featured": None}

    escalation = _rivalry_escalation(username, rival)
    if int(escalation.get("total") or 0) < 1:
        return {"username": username, "featured": None}

    h2h = _head_to_head(username, rival, 6)
    recent = list(h2h.get("recent") or [])
    pulse = []
    for battle in recent[:6]:
        winner = str(battle.get("winner") or "")
        pulse.append({
            "battle_id": int(battle.get("id") or 0),
            "winner": winner,
            "owner_result": ("W" if winner == username else ("L" if winner == rival else "—")),
            "created_at": battle.get("created_at") or ""
        })

    current_streak_holder = None
    current_streak = 0
    for battle in recent:
        winner = str(battle.get("winner") or "")
        if not winner:
            break
        if current_streak_holder is None:
            current_streak_holder = winner
            current_streak = 1
        elif winner == current_streak_holder:
            current_streak += 1
        else:
            break

    xp = int(rival_row["xp"] or 0)
    creature = _creature_from_xp(xp)
    stakes = _rivalry_stakes(
        escalation.get("total"), escalation.get("a_wins"), escalation.get("b_wins"),
        username, rival, current_streak_holder, current_streak
    )
    return {
        "username": username,
        "featured": {
            "rival": rival,
            "avatar": creature["avatar"],
            "creature": creature["name"],
            "level": max(1, xp // 100 + 1),
            "updated_at": row["updated_at"],
            "escalation": escalation,
            "pulse": pulse,
            "current_rivalry_streak": {
                "holder": current_streak_holder,
                "count": int(current_streak or 0)
            },
            "last_winner": h2h.get("last_winner"),
            "chronicle": _rivalry_chronicle(username, rival),
            "stakes": stakes,
            "engine": "discovery-v13.2"
        }
    }


@app.route("/api/featured-nemesis/<username>", methods=["GET", "POST", "DELETE"])
def featured_nemesis_api(username):
    data = _featured_nemesis(username)
    if data is None:
        return jsonify({"success": False, "message": "Hunter not found"}), 404

    if request.method == "GET":
        return jsonify({"success": True, **data})

    if session.get("authenticated_username") != username:
        return jsonify({
            "success": False,
            "message": "🔐 Sign in with this Hunter ID to manage Featured Nemesis."
        }), 401

    if request.method == "DELETE":
        conn = db()
        row = conn.execute(
            "SELECT rival FROM hunter_featured_nemesis WHERE username = ?",
            (username,)
        ).fetchone()
        conn.execute(
            "DELETE FROM hunter_featured_nemesis WHERE username = ?",
            (username,)
        )
        conn.commit()
        conn.close()
        previous = row["rival"] if row else None
        return jsonify({
            "success": True,
            "message": (
                f"🧹 {previous} removed from Featured Nemesis."
                if previous else
                "No Featured Nemesis was active."
            ),
            "username": username,
            "featured": None
        })

    payload = request.get_json(silent=True) or {}
    rival = str(payload.get("rival", "")).strip()
    if not rival or rival == username:
        return jsonify({"success": False, "message": "Choose a tracked rival."}), 400

    conn = db()
    rival_exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (rival,)).fetchone()
    tracked = conn.execute(
        """SELECT 1 FROM hunter_connections
           WHERE owner = ? AND target = ? AND kind = 'rival'""",
        (username, rival)
    ).fetchone()
    conn.close()

    if rival_exists is None or tracked is None:
        return jsonify({
            "success": False,
            "message": "That Hunter must be in your Rival Network first."
        }), 400

    escalation = _rivalry_escalation(username, rival)
    if int(escalation.get("total") or 0) < 1:
        return jsonify({
            "success": False,
            "message": "Complete at least one direct Clash before featuring this Rivalry."
        }), 400

    now = datetime.utcnow().isoformat()
    conn = db()
    conn.execute(
        """INSERT INTO hunter_featured_nemesis(username, rival, updated_at)
           VALUES (?, ?, ?)
           ON CONFLICT(username) DO UPDATE SET
             rival = excluded.rival,
             updated_at = excluded.updated_at""",
        (username, rival, now)
    )
    conn.commit()
    conn.close()

    fresh = _featured_nemesis(username)
    return jsonify({
        "success": True,
        "message": f"😈 {rival} is now your Featured Nemesis.",
        **fresh
    })


@app.route("/hunter/<username>")
def hunter_public_page(username):
    d = _hunter_public_data(username)
    if d is None:
        return "Hunter not found", 404
    momentum = _momentum_state(d["season"]["win_streak"])
    momentum_key = momentum.get("key") or "building"
    next_at = momentum.get("next_at")
    momentum_remaining = max(0, int(next_at) - int(d["season"]["win_streak"] or 0)) if next_at else 0
    trophy_data = _hunter_trophies(username) or {"count": 0, "trophies": []}
    hunter_title = _hunter_title(username) or {"key": "hunter", "title": "HUNTER", "icon": "👾", "tier": "UNRANKED"}
    title_options = _hunter_title_options(username) or []
    showcase_data = _hunter_showcase(username) or {"featured": None, "options": []}
    featured_trophy = showcase_data.get("featured")
    featured_nemesis_data = _featured_nemesis(username) or {"featured": None}
    featured_nemesis = featured_nemesis_data.get("featured")
    esc = lambda v: html.escape(str(v or ""))
    viewer = session.get("authenticated_username") or ""
    is_owner = viewer == username
    root = request.url_root.rstrip("/")
    page_url = f"{root}/hunter/{urllib.parse.quote(username)}"
    image_url = f"{root}/hunter/{urllib.parse.quote(username)}/card.svg"
    challenge_url = f"{root}/?challenge={urllib.parse.quote(username)}&ref={urllib.parse.quote(username)}"
    title = f"{username} // {hunter_title['title']} // BL3"
    desc = f"{hunter_title['icon']} {hunter_title['title']} • {momentum['icon']} {momentum['label']} • {d['reputation']} REP • {d['wins']} wins • {d['creature']['name']} • Level {d['level']} on the BL3 Human Alpha Network."

    battles_html = ""
    for b in d["recent_battles"]:
        opponent = b["opponent"] if b["challenger"] == username else b["challenger"]
        won = b["winner"] == username
        outcome = "WIN" if won else "LOSS"
        outcome_class = "win" if won else "loss"
        battles_html += (
            f'<a class="battle" href="/clash/{b["id"]}"><div><b>⚔️ vs {esc(opponent)}</b>'
            f'<div class="meta">{esc(b["commentary"])}</div></div>'
            f'<div class="outcome {outcome_class}">{outcome}</div></a>'
        )
    if not battles_html:
        battles_html = '<div class="empty">No public clashes yet. Be the first to challenge this Hunter.</div>'

    featured_key = featured_trophy["key"] if featured_trophy else ""
    trophy_cards = ""
    for t in trophy_data["trophies"]:
        is_featured = t["key"] == featured_key
        pin_control = ""
        if is_owner:
            pin_control = (
                f'<button class="trophy-pin{" active" if is_featured else ""}" '
                f'data-trophy-key="{esc(t["key"])}">'
                f'{"FEATURED ✓" if is_featured else "PIN"}</button>'
            )
        elif is_featured:
            pin_control = '<span class="featured-label">FEATURED</span>'

        trophy_cards += (
            f'<div class="trophy trophy-{esc(t["tier"]).lower()}{" featured" if is_featured else ""}">'
            f'<div class="trophy-icon">{esc(t["icon"])}</div>'
            f'<div class="trophy-copy"><div class="trophy-top"><b>{esc(t["title"])}</b>'
            f'<span>{esc(t["tier"])}</span></div>'
            f'<p>{esc(t["detail"])}</p></div>{pin_control}</div>'
        )
    if not trophy_cards:
        trophy_cards = '<div class="empty">No trophies unlocked yet. Your first Clash or verified wallet can start the shelf.</div>'

    featured_html = (
        f'<div class="featured-showcase trophy-{esc(featured_trophy["tier"]).lower()}">'
        f'<div class="featured-big-icon">{esc(featured_trophy["icon"])}</div>'
        f'<div><div class="eyebrow">FEATURED TROPHY // PINNED PROOF</div>'
        f'<h3>{esc(featured_trophy["title"])}</h3>'
        f'<div class="meta">{esc(featured_trophy["detail"])}</div>'
        f'<span class="featured-tier">{esc(featured_trophy["tier"])}</span></div></div>'
        if featured_trophy else
        '<div class="featured-showcase"><div class="featured-big-icon">🏆</div><div><div class="eyebrow">FEATURED TROPHY</div><h3>Nothing pinned yet</h3><div class="meta">Unlock a Trophy to start your public showcase.</div></div></div>'
    )

    title_collection = ""
    for t in title_options:
        active = t["key"] == hunter_title.get("key")
        button = ""
        if is_owner:
            button = (
                f'<button class="title-equip{" active" if active else ""}" '
                f'data-title-key="{esc(t["key"])}">'
                f'{"EQUIPPED ✓" if active else "EQUIP"}</button>'
            )
        else:
            button = '<span class="title-public-state">' + ("EQUIPPED" if active else "UNLOCKED") + '</span>'
        title_collection += (
            f'<div class="title-option{" selected" if active else ""}">'
            f'<div class="title-option-icon">{esc(t["icon"])}</div>'
            f'<div class="title-option-copy"><b>{esc(t["title"])}</b>'
            f'<span>{esc(t["tier"])}</span></div>{button}</div>'
        )

    rank_text = f"#{d['season']['rank']}" if d['season']['rank'] else "—"
    crown_badge = '<span class="crown">👑 CURRENT CROWN</span>' if d['season']['is_crown'] else ''
    verified_badge = '<span class="verified">WALLET VERIFIED</span>' if d['wallet_verified'] else '<span class="muted-badge">WALLET UNVERIFIED</span>'
    momentum_badge = (
        f'<span class="momentum-badge momentum-{esc(momentum_key)}">'
        f'{esc(momentum["icon"])} {esc(momentum["label"])}</span>'
    )
    momentum_detail = (
        f'{d["season"]["win_streak"]} straight season wins · '
        + (f'{momentum_remaining} to next Momentum tier' if next_at else 'highest tracked Momentum tier')
    )

    featured_nemesis_html = ""
    if featured_nemesis:
        nemesis_escalation = featured_nemesis["escalation"]
        nemesis_tier = nemesis_escalation["tier"]
        nemesis_rival = featured_nemesis["rival"]
        nemesis_leader = nemesis_escalation.get("leader")
        if nemesis_leader == username:
            nemesis_record_note = f"{username} leads"
        elif nemesis_leader == nemesis_rival:
            nemesis_record_note = f"{nemesis_rival} leads"
        else:
            nemesis_record_note = "Rivalry tied"

        featured_nemesis_html = (
            f'<section class="section featured-nemesis">'
            f'<div class="eyebrow">😈 FEATURED NEMESIS // PUBLIC RIVALRY</div>'
            f'<div class="featured-nemesis-card">'
            f'<div class="featured-nemesis-avatar">{esc(featured_nemesis["avatar"])}</div>'
            f'<div class="featured-nemesis-copy"><h2>{esc(username)} <span class="vs">VS</span> {esc(nemesis_rival)}</h2>'
            f'<div class="meta">{esc(featured_nemesis["creature"])} · LEVEL {int(featured_nemesis["level"])} · {esc(nemesis_record_note)}</div>'
            f'<div class="featured-nemesis-tier">{esc(nemesis_tier["icon"])} {esc(nemesis_tier["label"])} · LEVEL {int(nemesis_tier["level"])}/5 · '
            f'{("MAX TIER" if nemesis_tier.get("next_at") is None else str(int(nemesis_escalation.get("clashes_to_next") or 0)) + " TO NEXT")}</div>'
            f'<div class="meta" style="margin-top:6px">LAST BLOOD: {esc(featured_nemesis.get("last_winner") or "—")} · '
            f'{esc((featured_nemesis.get("current_rivalry_streak") or {}).get("holder") or "NO ACTIVE STREAK")} '
            f'{int((featured_nemesis.get("current_rivalry_streak") or {}).get("count") or 0)} STRAIGHT</div>'
            f'</div>'
            f'<div class="featured-nemesis-score"><b>{int(nemesis_escalation["a_wins"])}</b><span>—</span><b>{int(nemesis_escalation["b_wins"])}</b>'
            f'<small>{int(nemesis_escalation["total"])} CLASHES</small></div>'
            f'</div>'
            f'<div class="actions" style="justify-content:center;margin-top:12px">'
            f'<a class="btn violet" href="/rivalry/{urllib.parse.quote(username)}/{urllib.parse.quote(nemesis_rival)}">🔥 OPEN FEATURED RIVALRY</a>'
            f'<a class="btn" href="/?challenge={urllib.parse.quote(nemesis_rival)}&ref={urllib.parse.quote(username)}">⚔️ RUN IT BACK</a>'
            f'</div>'
            f'</section>'
        )
    elif is_owner:
        featured_nemesis_html = (
            '<section class="section featured-nemesis">'
            '<div class="eyebrow">😈 FEATURED NEMESIS // PUBLIC RIVALRY</div>'
            '<div class="empty">No Featured Nemesis yet. Mark a rival, complete a Clash, then pin them from your Threat Radar.</div>'
            '</section>'
        )

    h2h_html = ""
    if viewer and viewer != username:
        h2h = _head_to_head(viewer, username, 5)
        h2h_badges = _rivalry_milestones(viewer, username)
        leader_text = "TIED"
        if h2h["leader"] == viewer:
            leader_text = f"{viewer.upper()} LEADS"
        elif h2h["leader"] == username:
            leader_text = f"{username.upper()} LEADS"

        latest = ""
        for battle in h2h["recent"]:
            mine = battle["winner"] == viewer
            outcome = "WIN" if mine else "LOSS"
            cls = "win" if mine else "loss"
            latest += (
                f'<a class="battle" href="/clash/{battle["id"]}">'
                f'<div><b>⚔️ Clash #{battle["id"]}</b>'
                f'<div class="meta">{esc(battle["commentary"])}</div></div>'
                f'<div class="outcome {cls}">{outcome}</div></a>'
            )
        if not latest:
            latest = '<div class="empty">No clashes between you yet. Start the rivalry.</div>'

        profile_badges = "".join(
            f'<span class="muted-badge">{html.escape(str(m["icon"]))} {html.escape(str(m["title"]))}</span>'
            for m in h2h_badges[:4]
        )
        h2h_html = (
            f'<section class="section rivalry">'
            f'<div class="eyebrow">🎯 RIVALRY // HEAD-TO-HEAD</div>'
            f'<h2>{esc(viewer)} <span class="vs">VS</span> {esc(username)}</h2>'
            f'<div class="h2h-grid">'
            f'<div class="h2h-score"><strong>{h2h["a_wins"]}</strong><span>{esc(viewer)}</span></div>'
            f'<div class="h2h-mid"><b>{h2h["total"]} CLASHES</b><span>{esc(leader_text)}</span></div>'
            f'<div class="h2h-score"><strong>{h2h["b_wins"]}</strong><span>{esc(username)}</span></div>'
            f'</div>'
            f'<div class="meta h2h-last">Last winner: {esc(h2h["last_winner"] or "—")}</div>'
            f'<div class="badges" style="justify-content:center;margin-top:12px">{profile_badges}</div>'
            f'<div class="actions" style="justify-content:center;margin-top:14px">'
            f'<a class="btn violet" href="/rivalry/{urllib.parse.quote(viewer)}/{urllib.parse.quote(username)}">🃏 OPEN RIVALRY CARD</a>'
            f'</div>'
            f'<div class="h2h-recent">{latest}</div>'
            f'</section>'
        )

    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#050507">
<title>{esc(title)}</title><meta name="description" content="{esc(desc)}">
<meta property="og:title" content="{esc(title)}"><meta property="og:description" content="{esc(desc)}"><meta property="og:type" content="profile"><meta property="og:url" content="{esc(page_url)}"><meta property="og:image" content="{esc(image_url)}">
<meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="{esc(title)}"><meta name="twitter:description" content="{esc(desc)}"><meta name="twitter:image" content="{esc(image_url)}">
<style>
:root{{--bg:#050507;--panel:#111116;--line:#2b2b36;--muted:#9293a4;--text:#f8f8fb;--hot:#b8ff5a;--violet:#9d7bff}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 50% -20%,#292047 0,#0b0b10 34%,var(--bg) 70%);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Arial;min-height:100vh}}body:before{{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px);background-size:42px 42px}}.shell{{width:min(1060px,100%);margin:auto;padding:22px}}.nav{{display:flex;align-items:center;justify-content:space-between;padding:10px 0 28px}}.brand{{font-weight:950;font-size:25px}}.brand span{{color:var(--hot)}}.back{{color:#fff;text-decoration:none;border:1px solid var(--line);padding:10px 14px;border-radius:999px;font-weight:800}}.hero{{border:1px solid var(--line);border-radius:30px;padding:34px;background:linear-gradient(145deg,rgba(18,18,25,.94),rgba(11,11,16,.86));box-shadow:0 30px 80px rgba(0,0,0,.35);position:relative;overflow:hidden}}.hero:after{{content:"";position:absolute;right:-120px;top:-130px;width:340px;height:340px;border-radius:50%;filter:blur(60px);opacity:.45;pointer-events:none}}.hero.aura-building:after{{background:rgba(157,123,255,.13)}}.hero.aura-hot:after{{background:rgba(255,159,67,.2)}}.hero.aura-dominating:after{{background:rgba(255,79,216,.2)}}.hero.aura-unstoppable:after{{background:rgba(255,214,107,.2)}}.hero.aura-mythic:after{{background:rgba(97,244,255,.2)}}.eyebrow{{color:var(--hot);font-size:11px;letter-spacing:2px;font-weight:950}}.top{{display:grid;grid-template-columns:auto 1fr;gap:24px;align-items:center;margin-top:18px}}.avatar{{width:130px;height:130px;border-radius:32px;border:1px solid #3b3b48;background:radial-gradient(circle at 40% 30%,rgba(184,255,90,.16),rgba(157,123,255,.12),#0c0c11);display:grid;place-items:center;font-size:68px;box-shadow:inset 0 0 40px rgba(157,123,255,.08)}}h1{{font-size:clamp(44px,8vw,86px);line-height:.92;letter-spacing:-4px;margin:0}}.subtitle{{margin-top:12px;color:#b7b7c4;font-weight:800}}.badges{{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}}.verified,.crown,.muted-badge,.momentum-badge{{font-size:11px;font-weight:950;letter-spacing:1px;border-radius:999px;padding:8px 10px}}.verified{{color:var(--hot);border:1px solid rgba(184,255,90,.3);background:rgba(184,255,90,.06)}}.crown{{color:#ffd75a;border:1px solid rgba(255,215,90,.3);background:rgba(255,215,90,.06)}}.muted-badge{{color:#88899a;border:1px solid var(--line)}}.momentum-badge{{border:1px solid var(--line);background:rgba(255,255,255,.03)}}.momentum-building{{color:#a8a8b8}}.momentum-hot{{color:#ffb34d;border-color:rgba(255,179,77,.35)}}.momentum-dominating{{color:#ff63d7;border-color:rgba(255,99,215,.35)}}.momentum-unstoppable{{color:#ffd66b;border-color:rgba(255,214,107,.38)}}.momentum-mythic{{color:#8ef7ff;border-color:rgba(142,247,255,.4)}}.status-aura{{position:relative;z-index:2;margin-top:16px;border:1px solid var(--line);border-radius:18px;padding:14px;background:rgba(9,9,14,.7);display:flex;align-items:center;justify-content:space-between;gap:14px}}.status-aura-left{{display:flex;gap:11px;align-items:center}}.status-aura-icon{{width:42px;height:42px;border-radius:13px;display:grid;place-items:center;background:#0a0a0f;border:1px solid var(--line);font-size:23px}}.status-aura b{{font-size:12px;letter-spacing:1px}}.status-aura span{{display:block;color:var(--muted);font-size:9px;margin-top:3px}}.status-aura strong{{font-size:13px;color:var(--hot);white-space:nowrap}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:26px}}.stat{{border:1px solid var(--line);border-radius:18px;padding:16px;background:#0d0d12}}.num{{font-size:26px;font-weight:950}}.label{{font-size:10px;color:var(--muted);letter-spacing:1.4px;margin-top:4px}}.evo{{margin-top:18px}}.bar{{height:10px;background:#20202a;border-radius:99px;overflow:hidden;margin-top:8px}}.bar>i{{display:block;height:100%;width:{d['evolution']['percent']}%;background:linear-gradient(90deg,var(--hot),var(--violet));border-radius:99px}}.season{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:18px}}.social-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:12px}}.social-stat{{border:1px solid var(--line);border-radius:14px;padding:12px;background:rgba(255,255,255,.018);display:flex;align-items:baseline;justify-content:space-between;gap:10px}}.social-stat b{{font-size:19px}}.social-stat span{{font-size:9px;color:var(--muted);letter-spacing:1.2px}}.actions{{display:flex;gap:10px;flex-wrap:wrap;margin-top:22px}}.btn{{flex:1;min-width:220px;text-align:center;text-decoration:none;border-radius:16px;padding:16px;font-weight:950}}.hot{{background:var(--hot);color:#08080b}}.violet{{background:var(--violet);color:#fff}}.social-btn{{border:1px solid var(--line);background:#17171e;color:#fff;cursor:pointer}}.section{{margin-top:24px;border:1px solid var(--line);border-radius:24px;padding:24px;background:rgba(17,17,22,.82)}}.section h2{{margin:5px 0 16px;font-size:30px}}.battle{{display:flex;justify-content:space-between;gap:18px;align-items:center;color:#fff;text-decoration:none;border-top:1px solid var(--line);padding:15px 0}}.battle:first-of-type{{border-top:0}}.meta{{font-size:13px;color:var(--muted);line-height:1.5;margin-top:5px}}.outcome{{font-size:12px;font-weight:950;border-radius:999px;padding:8px 10px}}.win{{color:var(--hot);border:1px solid rgba(184,255,90,.3)}}.loss{{color:#ff7a9d;border:1px solid rgba(255,122,157,.3)}}.empty{{color:var(--muted);padding:12px 0}}.hunter-title{{display:inline-flex;align-items:center;gap:8px;margin-top:10px;padding:8px 12px;border-radius:999px;border:1px solid rgba(184,255,90,.28);background:rgba(184,255,90,.06);color:var(--hot);font-size:12px;font-weight:900;letter-spacing:1.3px}}.hunter-title small{{color:var(--muted);font-size:9px;letter-spacing:1px}}.title-collection{{border-color:rgba(184,255,90,.18);background:linear-gradient(145deg,rgba(184,255,90,.035),rgba(157,123,255,.035))}}.title-grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:14px}}.title-option{{display:flex;align-items:center;gap:12px;border:1px solid var(--line);background:#0d0d12;border-radius:17px;padding:13px}}.title-option.selected{{border-color:rgba(184,255,90,.42);box-shadow:0 0 24px rgba(184,255,90,.05)}}.title-option-icon{{font-size:26px}}.title-option-copy{{flex:1;min-width:0}}.title-option-copy b{{display:block;font-size:12px;letter-spacing:.8px}}.title-option-copy span{{display:block;color:var(--muted);font-size:9px;margin-top:4px;letter-spacing:1px}}.title-equip{{border:1px solid var(--line);background:#17171f;color:#fff;border-radius:999px;padding:8px 10px;font-size:9px;font-weight:900;cursor:pointer}}.title-equip:hover,.title-equip.active{{border-color:var(--hot);color:var(--hot)}}.title-public-state{{font-size:9px;font-weight:900;color:var(--muted);letter-spacing:1px}}.featured-showcase{{display:flex;gap:16px;align-items:center;margin-top:18px;border:1px solid var(--line);border-radius:22px;padding:18px;background:linear-gradient(145deg,#111119,#17131e)}}.featured-big-icon{{width:72px;height:72px;display:grid;place-items:center;border-radius:20px;background:#0a0a0f;border:1px solid var(--line);font-size:38px;flex:0 0 auto}}.featured-showcase h3{{margin:4px 0 2px;font-size:24px}}.featured-tier,.featured-label{{display:inline-block;margin-top:8px;font-size:9px;font-weight:900;letter-spacing:1.2px;color:#ffd86b;border:1px solid rgba(255,216,107,.3);padding:5px 8px;border-radius:999px}}.trophy-room{{border-color:rgba(157,123,255,.28);background:linear-gradient(145deg,rgba(157,123,255,.05),rgba(184,255,90,.025))}}.trophy-grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:14px}}.trophy{{display:flex;gap:13px;align-items:flex-start;border:1px solid var(--line);background:#0d0d12;padding:15px;border-radius:18px}}.trophy.featured{{box-shadow:0 0 28px rgba(255,216,107,.06);border-color:rgba(255,216,107,.38)}}.trophy-pin{{align-self:center;border:1px solid var(--line);background:#17171f;color:#fff;border-radius:999px;padding:8px 10px;font-size:9px;font-weight:900;cursor:pointer;white-space:nowrap}}.trophy-pin:hover,.trophy-pin.active{{border-color:#ffd86b;color:#ffd86b}}.trophy-icon{{font-size:30px;line-height:1}}.trophy-copy{{min-width:0;flex:1}}.trophy-top{{display:flex;justify-content:space-between;gap:10px;align-items:center}}.trophy-top b{{font-size:13px;letter-spacing:.8px}}.trophy-top span{{font-size:9px;font-weight:900;letter-spacing:1px;color:var(--muted);border:1px solid var(--line);padding:4px 7px;border-radius:999px}}.trophy p{{margin:7px 0 0;color:var(--muted);font-size:12px;line-height:1.45}}.trophy-gold{{border-color:rgba(255,212,79,.3)}}.trophy-legendary{{border-color:rgba(184,255,90,.42);box-shadow:0 0 30px rgba(184,255,90,.05)}}.rivalry{{border-color:rgba(184,255,90,.24);background:linear-gradient(145deg,rgba(184,255,90,.04),rgba(157,123,255,.04))}}.rivalry h2{{font-size:clamp(28px,5vw,48px);letter-spacing:-2px}}.vs{{color:var(--hot);font-size:.55em;letter-spacing:2px;margin:0 10px}}.h2h-grid{{display:grid;grid-template-columns:1fr auto 1fr;gap:12px;align-items:center;margin-top:18px}}.h2h-score{{border:1px solid var(--line);border-radius:20px;background:#0d0d12;padding:18px;text-align:center}}.h2h-score strong{{display:block;font-size:42px;line-height:1;color:#fff}}.h2h-score span{{display:block;margin-top:7px;font-size:11px;color:var(--muted);font-weight:900;letter-spacing:1.2px}}.h2h-mid{{text-align:center;min-width:130px}}.h2h-mid b{{display:block;color:var(--hot);font-size:13px}}.h2h-mid span{{display:block;color:var(--muted);font-size:10px;margin-top:5px;letter-spacing:1px}}.h2h-last{{text-align:center;margin-top:12px}}.h2h-recent{{margin-top:10px}}.featured-nemesis-card{{display:grid;grid-template-columns:auto 1fr auto;gap:14px;align-items:center;border:1px solid rgba(255,79,216,.22);border-radius:20px;padding:16px;background:linear-gradient(120deg,rgba(255,79,216,.07),rgba(157,123,255,.04))}}.featured-nemesis-avatar{{width:64px;height:64px;border-radius:20px;display:grid;place-items:center;background:#09090e;border:1px solid var(--line);font-size:34px}}.featured-nemesis-copy h2{{margin:0;font-size:22px}}.featured-nemesis-tier{{margin-top:8px;color:#ff63d7;font-size:10px;font-weight:950;letter-spacing:1px}}.featured-nemesis-score{{display:grid;grid-template-columns:auto auto auto;gap:7px;align-items:center;text-align:center}}.featured-nemesis-score b{{font-size:25px}}.featured-nemesis-score span{{color:var(--muted)}}.featured-nemesis-score small{{grid-column:1/-1;color:var(--muted);font-size:8px;letter-spacing:1px}}.footer{{text-align:center;color:#626270;padding:40px 0 20px;font-size:12px}}@media(max-width:760px){{.top{{grid-template-columns:1fr}}.title-grid{{grid-template-columns:1fr}}.trophy-grid{{grid-template-columns:1fr}}.h2h-grid{{grid-template-columns:1fr}}.h2h-mid{{order:-1}}.avatar{{width:98px;height:98px;font-size:52px}}.grid,.season{{grid-template-columns:repeat(2,1fr)}}.social-grid{{grid-template-columns:1fr}}.featured-nemesis-card{{grid-template-columns:1fr;text-align:center}}.featured-nemesis-avatar{{margin:auto}}h1{{letter-spacing:-2px}}}}
</style></head><body><div class="shell"><nav class="nav"><div class="brand">BL3<span>●</span> HUMAN ALPHA NETWORK</div><a class="back" href="/">← LIVE NETWORK</a></nav>
<section class="hero aura-{esc(momentum_key)}"><div class="eyebrow">PUBLIC HUNTER ID // SEASON {esc(d['season']['key'])}</div><div class="top"><div class="avatar">{esc(d['creature']['avatar'])}</div><div><h1>{esc(d['username'])}</h1><div class="hunter-title">{esc(hunter_title['icon'])} {esc(hunter_title['title'])} <small>{esc(hunter_title['tier'])}</small></div><div class="subtitle">{esc(d['creature']['name'])} // {esc(d['creature']['stage'])} // LEVEL {d['level']}</div><div class="badges">{verified_badge}{crown_badge}{momentum_badge}</div></div></div>
<div class="status-aura"><div class="status-aura-left"><div class="status-aura-icon">{esc(momentum["icon"])}</div><div><b>{esc(momentum["label"])}</b><span>{esc(momentum_detail)}</span></div></div><strong>🔥 {d["season"]["win_streak"]} STREAK</strong></div>
<div class="grid"><div class="stat"><div class="num">{d['reputation']}</div><div class="label">REPUTATION</div></div><div class="stat"><div class="num">{d['xp']}</div><div class="label">XP</div></div><div class="stat"><div class="num">{d['wins']}</div><div class="label">TOTAL WINS</div></div><div class="stat"><div class="num">{d['network']}</div><div class="label">NETWORK</div></div></div>
<div class="social-grid"><div class="social-stat"><b id="followersCount">{d['followers']}</b><span>FOLLOWERS</span></div><div class="social-stat"><b>{d['following']}</b><span>FOLLOWING</span></div><div class="social-stat"><b>{d['rivals']}</b><span>RIVALS TRACKED</span></div></div>
<div class="evo"><div style="display:flex;justify-content:space-between;font-size:12px;color:var(--muted)"><b>EVOLUTION</b><span>{d['evolution']['current']} / {d['evolution']['target']} XP</span></div><div class="bar"><i></i></div></div>
<div class="season"><div class="stat"><div class="num">{rank_text}</div><div class="label">CROWN RANK</div></div><div class="stat"><div class="num">{d['season']['wins']}-{d['season']['losses']}</div><div class="label">SEASON W-L</div></div><div class="stat"><div class="num">🔥 {d['season']['win_streak']}</div><div class="label">WIN STREAK</div></div><div class="stat"><div class="num">#{d['xp_rank'] or '—'}</div><div class="label">XP RANK</div></div></div>
<div class="actions"><a class="btn hot" href="{esc(challenge_url)}">⚔️ CHALLENGE {esc(username).upper()}</a><a class="btn violet" href="/loadout/{urllib.parse.quote(username)}">🧬 HUNTER LOADOUT</a><a class="btn violet" href="/progress/{urllib.parse.quote(username)}">📈 NEXT UNLOCKS</a><a class="btn violet" href="{esc(page_url)}">🔗 SHARE PROFILE</a><button class="btn social-btn" id="followBtn">👁️ FOLLOW</button><button class="btn social-btn" id="rivalBtn">🎯 MARK RIVAL</button></div>{featured_html}</section>
{featured_nemesis_html}
<section class="section title-collection"><div class="eyebrow">🏷️ TITLE COLLECTION // IDENTITY LOADOUT</div><h2>Choose Your Public Title <span class="small">{len(title_options)} AVAILABLE</span></h2><div class="meta">Unlocked titles come from real Trophy Room achievements. The equipped title appears on your public profile and Hunter share card.</div><div class="title-grid">{title_collection}</div></section>
<section class="section trophy-room"><div class="eyebrow">🏆 TROPHY ROOM // PROOF OF HISTORY</div><h2>Achievement Shelf <span class="small">{trophy_data["count"]} UNLOCKED</span></h2><div class="meta">Current public title: <b style="color:var(--hot)">{esc(hunter_title["icon"])} {esc(hunter_title["title"])}</b>. Pin any unlocked Trophy to feature one piece of proof at the top of your Hunter identity.</div><div class="trophy-grid">{trophy_cards}</div></section>
{h2h_html}
<section class="section"><div class="eyebrow">RECENT COMBAT</div><h2>Latest Alpha Clashes</h2>{battles_html}</section>
<div class="footer">BL3 // BUILD. MEME. REPEAT. // V13.3 GLOBAL SEARCH</div></div>
<script>
const hunterName={json.dumps(username)};
let socialState={{is_following:false,is_rival:false}};
async function socialFetch(url,options){{const r=await fetch(url,options);let d={{}};try{{d=await r.json()}}catch(e){{}}return d}}
function paintSocial(){{
 const f=document.getElementById('followBtn'),r=document.getElementById('rivalBtn');
 if(f)f.textContent=socialState.is_following?'✓ FOLLOWING':'👁️ FOLLOW';
 if(r)r.textContent=socialState.is_rival?'🎯 RIVAL ✓':'🎯 MARK RIVAL';
}}
async function loadSocial(){{const d=await socialFetch('/api/hunter/'+encodeURIComponent(hunterName)+'/social');if(!d.success)return;socialState=d;const c=document.getElementById('followersCount');if(c)c.textContent=d.followers;paintSocial()}}
async function toggleSocial(kind){{
 const enabled=kind==='follow'?!socialState.is_following:!socialState.is_rival;
 const d=await socialFetch('/api/hunter/'+encodeURIComponent(hunterName)+'/social',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{kind:kind,enabled:enabled}})}});
 if(!d.success){{alert(d.message||'Sign in to BL3 first.');return}}
 if(kind==='follow')socialState.is_following=enabled;else socialState.is_rival=enabled;
 const c=document.getElementById('followersCount');if(c&&d.followers!==undefined)c.textContent=d.followers;paintSocial();
}}
document.getElementById('followBtn')?.addEventListener('click',()=>toggleSocial('follow'));
document.getElementById('rivalBtn')?.addEventListener('click',()=>toggleSocial('rival'));
document.querySelectorAll('.title-equip').forEach(btn=>btn.addEventListener('click',async()=>{{
 const key=btn.dataset.titleKey;
 const d=await socialFetch('/api/title/'+encodeURIComponent(hunterName),{{
   method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{title_key:key}})
 }});
 if(!d.success){{alert(d.message||'Could not equip title.');return}}
 location.reload();
}}));
document.querySelectorAll('.trophy-pin').forEach(btn=>btn.addEventListener('click',async()=>{{
 const key=btn.dataset.trophyKey;
 const d=await socialFetch('/api/showcase/'+encodeURIComponent(hunterName),{{
   method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{trophy_key:key}})
 }});
 if(!d.success){{alert(d.message||'Could not feature Trophy.');return}}
 location.reload();
}}));
loadSocial();
</script></body></html>'''


def _battle_record(battle_id):
    conn = db()
    row = conn.execute("""SELECT id, challenger, opponent, winner, challenger_power, opponent_power,
                               commentary, created_at
                        FROM creature_battles WHERE id = ?""", (battle_id,)).fetchone()
    if row is None:
        conn.close()
        return None
    d = dict(row)
    cx = conn.execute("SELECT xp FROM users WHERE username = ?", (d["challenger"],)).fetchone()
    ox = conn.execute("SELECT xp FROM users WHERE username = ?", (d["opponent"],)).fetchone()
    conn.close()
    d["challenger_avatar"] = _creature_avatar_from_xp(cx["xp"] if cx else 0)
    d["opponent_avatar"] = _creature_avatar_from_xp(ox["xp"] if ox else 0)
    return d


@app.route("/clash/<int:battle_id>/card.svg")
def clash_card_svg(battle_id):
    b = _battle_record(battle_id)
    if not b:
        return Response("Battle not found", status=404, mimetype="text/plain")
    esc = lambda v: html.escape(str(v or ""))
    winner = esc(b["winner"])
    challenger = esc(b["challenger"])
    opponent = esc(b["opponent"])
    commentary = esc(b["commentary"])
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
      <defs>
        <linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#08080b"/><stop offset="1" stop-color="#171725"/></linearGradient>
        <linearGradient id="a" x1="0" y1="0" x2="1" y2="0"><stop stop-color="#b8ff5a"/><stop offset="1" stop-color="#8b5cf6"/></linearGradient>
      </defs>
      <rect width="1200" height="630" rx="36" fill="url(#g)"/>
      <rect x="34" y="34" width="1132" height="562" rx="30" fill="none" stroke="#30303a" stroke-width="2"/>
      <text x="72" y="98" fill="#b8ff5a" font-family="Arial,sans-serif" font-size="27" font-weight="800">BL3 // ALPHA CLASH #{battle_id}</text>
      <text x="72" y="155" fill="#777785" font-family="Arial,sans-serif" font-size="20" letter-spacing="3">PROOF &gt; NOISE // BATTLE RESULT</text>
      <text x="190" y="292" fill="#ffffff" font-family="Arial,sans-serif" font-size="47" font-weight="900" text-anchor="middle">{challenger}</text>
      <text x="190" y="348" fill="#b8ff5a" font-family="Arial,sans-serif" font-size="34" font-weight="900" text-anchor="middle">POWER {b['challenger_power']}</text>
      <text x="600" y="315" fill="url(#a)" font-family="Arial,sans-serif" font-size="70" font-weight="900" text-anchor="middle">VS</text>
      <text x="1010" y="292" fill="#ffffff" font-family="Arial,sans-serif" font-size="47" font-weight="900" text-anchor="middle">{opponent}</text>
      <text x="1010" y="348" fill="#8b5cf6" font-family="Arial,sans-serif" font-size="34" font-weight="900" text-anchor="middle">POWER {b['opponent_power']}</text>
      <text x="600" y="438" fill="#ffffff" font-family="Arial,sans-serif" font-size="32" font-weight="900" text-anchor="middle">CROWN: {winner}</text>
      <text x="600" y="493" fill="#9b9baa" font-family="Arial,sans-serif" font-size="21" text-anchor="middle">{commentary[:86]}</text>
      <text x="72" y="560" fill="#656675" font-family="Arial,sans-serif" font-size="18">BL3 HUMAN ALPHA NETWORK</text>
      <text x="1128" y="560" fill="#b8ff5a" font-family="Arial,sans-serif" font-size="18" text-anchor="end">CHALLENGE THE HUNTER</text>
    </svg>"""
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "public, max-age=300"})


@app.route("/clash/<int:battle_id>")
def clash_public_page(battle_id):
    b = _battle_record(battle_id)
    if not b:
        return "Battle not found", 404
    esc = lambda v: html.escape(str(v or ""))
    root = request.url_root.rstrip("/")
    page_url = f"{root}/clash/{battle_id}"
    image_url = f"{root}/clash/{battle_id}/card.svg"
    challenge_url = f"{root}/?challenge={urllib.parse.quote(b['challenger'])}&ref={urllib.parse.quote(b['challenger'])}&from_battle={battle_id}"
    title = f"BL3 Alpha Clash #{battle_id}: {b['challenger']} vs {b['opponent']}"
    desc = f"{b['winner']} took the crown. {b['challenger_power']}-{b['opponent_power']}. Challenge the hunter on BL3."
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title><meta name="description" content="{esc(desc)}">
<meta property="og:title" content="{esc(title)}"><meta property="og:description" content="{esc(desc)}"><meta property="og:type" content="website"><meta property="og:url" content="{esc(page_url)}"><meta property="og:image" content="{esc(image_url)}">
<meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="{esc(title)}"><meta name="twitter:description" content="{esc(desc)}"><meta name="twitter:image" content="{esc(image_url)}">
<style>*{{box-sizing:border-box}}body{{margin:0;background:#08080b;color:#fff;font-family:Arial,sans-serif;min-height:100vh;display:grid;place-items:center;padding:24px}}.wrap{{width:min(920px,100%)}}.brand{{font-weight:950;font-size:27px}}.brand span{{color:#b8ff5a}}.card{{margin-top:18px;border:1px solid #30303a;border-radius:28px;padding:30px;background:linear-gradient(145deg,#111116,#181824)}}.eyebrow{{color:#b8ff5a;font-size:12px;font-weight:900;letter-spacing:2px}}h1{{font-size:clamp(34px,7vw,72px);line-height:.95;margin:18px 0}}.vs{{display:grid;grid-template-columns:1fr auto 1fr;gap:18px;align-items:center;margin:30px 0}}.fighter{{padding:20px;border:1px solid #30303a;border-radius:20px;text-align:center}}.fighter b{{font-size:28px}}.power{{font-size:20px;color:#b8ff5a;margin-top:8px}}.center{{font-size:34px;font-weight:950;color:#8b5cf6}}.winner{{padding:18px;border:1px solid rgba(184,255,90,.3);border-radius:18px;background:rgba(184,255,90,.05)}}.meta{{color:#9b9baa;line-height:1.6}}.btn{{display:block;text-align:center;text-decoration:none;color:#09090c;background:#b8ff5a;font-weight:950;padding:16px;border-radius:16px;margin-top:18px}}.sub{{display:block;text-align:center;text-decoration:none;color:#fff;border:1px solid #30303a;font-weight:800;padding:14px;border-radius:16px;margin-top:9px}}@media(max-width:650px){{.vs{{grid-template-columns:1fr}}.center{{text-align:center}}}}</style></head>
<body><div class="wrap"><div class="brand">BL3<span>●</span> HUMAN ALPHA NETWORK</div><div class="card"><div class="eyebrow">PUBLIC BATTLE CARD // #{battle_id}</div><h1>{esc(b['challenger'])}<br><span style="color:#8b5cf6">VS {esc(b['opponent'])}</span></h1><div class="vs"><div class="fighter"><b>{esc(b['challenger_avatar'])} {esc(b['challenger'])}</b><div class="power">POWER {b['challenger_power']}</div></div><div class="center">VS</div><div class="fighter"><b>{esc(b['opponent_avatar'])} {esc(b['opponent'])}</b><div class="power">POWER {b['opponent_power']}</div></div></div><div class="winner"><div class="eyebrow">CROWN HOLDER</div><h2>👑 {esc(b['winner'])}</h2><div class="meta">{esc(b['commentary'])}</div></div><a class="btn" href="{esc(challenge_url)}">⚔️ CHALLENGE {esc(b['challenger']).upper()}</a><a class="sub" href="/">BACK TO LIVE ARENAS</a></div></div></body></html>"""


def _resolve_battle(challenger, opponent):
    """Resolve one authenticated/accepted Alpha Clash and persist all season/Crown side effects."""
    conn = db()
    c = conn.execute("SELECT * FROM users WHERE username = ?", (challenger,)).fetchone()
    o = conn.execute("SELECT * FROM users WHERE username = ?", (opponent,)).fetchone()
    conn.close()
    if c is None:
        return {"success": False, "message": "Challenger profile not found."}, 404
    if o is None:
        return {"success": False, "message": "Opponent is not a BL3 hunter yet. Invite them first."}, 404

    cxp, oxp = int(c["xp"] or 0), int(o["xp"] or 0)
    c_roll = secrets.randbelow(41)
    o_roll = secrets.randbelow(41)
    c_power = 50 + min(150, cxp // 10) + c_roll
    o_power = 50 + min(150, oxp // 10) + o_roll
    winner = challenger if c_power >= o_power else opponent

    def avatar(xp):
        if xp >= 1500: return "👑"
        if xp >= 700: return "🦹"
        if xp >= 300: return "😈"
        if xp >= 100: return "👾"
        return "🥚"

    if winner == challenger:
        commentary = f"{challenger} cracked the arena and stole the crown from {opponent}."
    else:
        commentary = f"UPSET: {opponent} survived the chaos and sent {challenger} back to evolution."

    now_dt = datetime.utcnow()
    now = now_dt.isoformat()
    season_key = now_dt.strftime("%Y-%m")
    conn = db()
    board_before = _season_rows(conn, season_key)
    crown_before = board_before[0]["username"] if board_before and int(board_before[0].get("wins") or 0) > 0 else None
    cursor = conn.execute("""INSERT INTO creature_battles
        (challenger, opponent, winner, challenger_power, opponent_power, commentary, created_at, season_key)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (challenger, opponent, winner, c_power, o_power, commentary, now, season_key))
    battle_id = cursor.lastrowid
    crown_attack = bool(crown_before and opponent == crown_before and challenger != crown_before)
    if crown_attack:
        conn.execute("""INSERT OR IGNORE INTO crown_events
            (battle_id, season_key, defender, challenger, winner, successful_defense, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (battle_id, season_key, crown_before, challenger, winner, 1 if winner == crown_before else 0, now))

    # V7.0 REP is separate from XP. Clash wins are capped to 3 REP-awarding wins/day.
    rep_awarded = _add_rep(conn, winner, 3, "Clash win", f"battle:{battle_id}:win", daily_cap=3, daily_prefix="Clash win")
    if crown_attack:
        if winner == crown_before:
            crown_rep = _add_rep(conn, winner, 10, "Crown defense", f"battle:{battle_id}:crown-defense", daily_cap=1, daily_prefix="Crown defense")
            _notify(conn, crown_before, "crown", "👑 Crown defended", f"You stopped {challenger} in Clash #{battle_id}.", f"/clash/{battle_id}")
            _notify(conn, challenger, "crown", "🛡️ Crown attack stopped", f"{crown_before} defended the Crown in Clash #{battle_id}.", f"/clash/{battle_id}")
        else:
            crown_rep = _add_rep(conn, winner, 12, "Crown takeover", f"battle:{battle_id}:crown-takeover", daily_cap=1, daily_prefix="Crown takeover")
            _notify(conn, challenger, "crown", "👑 You broke the Crown defense", f"You beat {crown_before} in Clash #{battle_id}.", f"/clash/{battle_id}")
            _notify(conn, crown_before, "crown", "🔥 Crown defense broken", f"{challenger} beat you in Clash #{battle_id}.", f"/clash/{battle_id}")
    _notify(conn, challenger, "battle", f"⚔️ Clash #{battle_id}: {challenger} vs {opponent}", f"Winner: {winner}." + (" +3 REP signal." if rep_awarded and winner == challenger else ""), f"/clash/{battle_id}")
    _notify(conn, opponent, "battle", f"⚔️ Clash #{battle_id}: {challenger} vs {opponent}", f"Winner: {winner}." + (" +3 REP signal." if rep_awarded and winner == opponent else ""), f"/clash/{battle_id}")
    feud_event = _record_feud_escalation_event(conn, battle_id, challenger, opponent, winner, now)
    feud_moment = _record_feud_moment(conn, battle_id, challenger, opponent, winner, c_power, o_power, now)
    conn.commit()
    # V12.3: the just-persisted Clash changes both season and all-time Feud snapshots.
    _invalidate_rivalry_cache()

    # V9.9: combo effects are cosmetic and derived from the real current-season streak.
    winner_streak = _season_win_streak(conn, winner, season_key)
    if winner_streak >= 12:
        combo = {"key": "mythic", "icon": "🌠", "label": "MYTHIC RUN", "tier": 4}
    elif winner_streak >= 8:
        combo = {"key": "unstoppable", "icon": "👑", "label": "UNSTOPPABLE", "tier": 3}
    elif winner_streak >= 5:
        combo = {"key": "dominating", "icon": "😈", "label": "DOMINATING", "tier": 2}
    elif winner_streak >= 3:
        combo = {"key": "hot", "icon": "🔥", "label": "HOT STREAK", "tier": 1}
    else:
        combo = {"key": "standard", "icon": "⚔️", "label": "CLASH WIN", "tier": 0}

    conn.close()
    return {
        "success": True, "battle_id": battle_id, "winner": winner, "commentary": commentary,
        "season_key": season_key, "crown_attack": crown_attack, "crown_before": crown_before,
        "winner_streak": winner_streak, "combo": combo, "feud_event": feud_event, "feud_moment": feud_moment,
        "challenger": {"username": challenger, "avatar": avatar(cxp), "power": c_power},
        "opponent": {"opponent": opponent, "avatar": avatar(oxp), "power": o_power}
    }, 200


@app.route("/api/battle", methods=["POST"])
def battle_api():
    data = request.get_json(silent=True) or {}
    challenger = str(data.get("challenger", "")).strip()
    opponent = str(data.get("opponent", "")).strip()
    if not challenger or not opponent:
        return jsonify({"success": False, "message": "Challenger and opponent are required."}), 400
    if challenger == opponent:
        return jsonify({"success": False, "message": "You cannot battle yourself."}), 400
    if session.get("authenticated_username") != challenger:
        return jsonify({"success": False, "message": "🔐 Sign in with the challenger wallet before starting a clash."}), 401
    payload, status = _resolve_battle(challenger, opponent)
    return jsonify(payload), status


@app.route("/api/battles/<username>")
def battle_history_api(username):
    conn = db()
    rows = conn.execute("""SELECT challenger, opponent, winner, challenger_power, opponent_power, commentary, created_at
                           FROM creature_battles WHERE challenger = ? OR opponent = ?
                           ORDER BY id DESC LIMIT 10""", (username, username)).fetchall()
    wins = conn.execute("SELECT COUNT(*) AS n FROM creature_battles WHERE winner = ?", (username,)).fetchone()["n"]
    conn.close()
    return jsonify({"success": True, "wins": wins, "battles": [dict(r) for r in rows]})



def _current_season_key():
    return datetime.utcnow().strftime("%Y-%m")


def _season_rows(conn, season_key):
    rows = conn.execute("""
        WITH participants AS (
            SELECT challenger AS username FROM creature_battles WHERE season_key = ?
            UNION
            SELECT opponent AS username FROM creature_battles WHERE season_key = ?
        )
        SELECT p.username,
               SUM(CASE WHEN b.winner = p.username THEN 1 ELSE 0 END) AS wins,
               SUM(CASE WHEN (b.challenger = p.username OR b.opponent = p.username) AND b.winner <> p.username THEN 1 ELSE 0 END) AS losses,
               SUM(CASE WHEN b.challenger = p.username OR b.opponent = p.username THEN 1 ELSE 0 END) AS battles
        FROM participants p
        LEFT JOIN creature_battles b
          ON b.season_key = ? AND (b.challenger = p.username OR b.opponent = p.username)
        GROUP BY p.username
        ORDER BY wins DESC, battles ASC, p.username COLLATE NOCASE ASC
    """, (season_key, season_key, season_key)).fetchall()
    return [dict(r) for r in rows]


def _season_win_streak(conn, username, season_key):
    rows = conn.execute("""SELECT winner FROM creature_battles
                           WHERE season_key = ? AND (challenger = ? OR opponent = ?)
                           ORDER BY id DESC LIMIT 100""", (season_key, username, username)).fetchall()
    streak = 0
    for r in rows:
        if r["winner"] == username:
            streak += 1
        else:
            break
    return streak


def _momentum_state(streak):
    streak = max(0, int(streak or 0))
    if streak >= 12:
        return {"key": "mythic", "icon": "🌠", "label": "MYTHIC RUN", "tier": 4, "next_at": None}
    if streak >= 8:
        return {"key": "unstoppable", "icon": "👑", "label": "UNSTOPPABLE", "tier": 3, "next_at": 12}
    if streak >= 5:
        return {"key": "dominating", "icon": "😈", "label": "DOMINATING", "tier": 2, "next_at": 8}
    if streak >= 3:
        return {"key": "hot", "icon": "🔥", "label": "HOT STREAK", "tier": 1, "next_at": 5}
    return {"key": "building", "icon": "⚔️", "label": "BUILDING MOMENTUM", "tier": 0, "next_at": 3}


@app.route("/api/momentum/<username>")
def hunter_momentum_api(username):
    conn = db()
    exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    if exists is None:
        conn.close()
        return jsonify({"success": False, "message": "Hunter not found"}), 404

    season_key = _current_season_key()
    streak = _season_win_streak(conn, username, season_key)
    recent = [dict(r) for r in conn.execute(
        """SELECT id, challenger, opponent, winner, created_at
           FROM creature_battles
           WHERE season_key = ? AND (challenger = ? OR opponent = ?)
           ORDER BY id DESC LIMIT 5""",
        (season_key, username, username)
    ).fetchall()]
    conn.close()

    state = _momentum_state(streak)
    next_at = state["next_at"]
    remaining = max(0, next_at - streak) if next_at else 0
    return jsonify({
        "success": True,
        "username": username,
        "season_key": season_key,
        "win_streak": streak,
        "momentum": state,
        "wins_to_next": remaining,
        "recent": recent
    })


@app.route("/api/momentum-board")
def momentum_board_api():
    season_key = _current_season_key()
    conn = db()
    participants = conn.execute(
        """SELECT username FROM (
             SELECT challenger AS username FROM creature_battles WHERE season_key = ?
             UNION
             SELECT opponent AS username FROM creature_battles WHERE season_key = ?
           ) ORDER BY username COLLATE NOCASE""",
        (season_key, season_key)
    ).fetchall()

    board = []
    for row in participants:
        username = row["username"]
        streak = _season_win_streak(conn, username, season_key)
        if streak <= 0:
            continue
        u = conn.execute("SELECT xp FROM users WHERE username = ?", (username,)).fetchone()
        xp = int(u["xp"] or 0) if u else 0
        creature = _creature_from_xp(xp)
        board.append({
            "username": username,
            "win_streak": streak,
            "momentum": _momentum_state(streak),
            "avatar": creature["avatar"],
            "creature": creature["name"],
            "level": max(1, xp // 100 + 1)
        })

    conn.close()
    board.sort(key=lambda x: (x["win_streak"], x["username"].lower()), reverse=True)
    return jsonify({"success": True, "season_key": season_key, "hunters": board[:8]})


@app.route("/api/crown-war")
def crown_war_api():
    season_key = _current_season_key()
    conn = db()
    board = _season_rows(conn, season_key)
    crown = board[0]["username"] if board and int(board[0].get("wins") or 0) > 0 else None

    if not crown:
        conn.close()
        return jsonify({
            "success": True,
            "active": False,
            "season_key": season_key,
            "crown": None,
            "pending_visible": False,
            "pending_attacks": None,
            "recent_attacks": [],
            "message": "No Crown holder yet."
        })

    viewer = session.get("authenticated_username") or ""
    pending = []
    if viewer == crown:
        pending = [dict(r) for r in conn.execute(
            """SELECT id, challenger, opponent, created_at
               FROM challenge_requests
               WHERE opponent = ? AND status = 'pending'
               ORDER BY id DESC LIMIT 8""",
            (crown,)
        ).fetchall()]

    recent = [dict(r) for r in conn.execute(
        """SELECT id, battle_id, defender, challenger, winner,
                  successful_defense, created_at
           FROM crown_events
           WHERE season_key = ?
           ORDER BY id DESC LIMIT 8""",
        (season_key,)
    ).fetchall()]

    crown_user = conn.execute(
        "SELECT xp FROM users WHERE username = ?",
        (crown,)
    ).fetchone()
    crown_xp = int(crown_user["xp"] or 0) if crown_user else 0
    creature = _creature_from_xp(crown_xp)

    conn.close()

    return jsonify({
        "success": True,
        "active": True,
        "season_key": season_key,
        "crown": {
            "username": crown,
            "avatar": creature["avatar"],
            "creature": creature["name"],
            "level": max(1, crown_xp // 100 + 1)
        },
        "pending_visible": viewer == crown,
        "pending_attacks": len(pending) if viewer == crown else None,
        "pending": pending if viewer == crown else [],
        "recent_attacks": recent,
        "status": ("UNDER ATTACK" if pending else "CROWN STABLE") if viewer == crown else "CROWN ACTIVE"
    })


@app.route("/api/season-command")
def season_command_api():
    season_key = _current_season_key()
    now = datetime.utcnow()

    if now.month == 12:
        next_month = datetime(now.year + 1, 1, 1)
    else:
        next_month = datetime(now.year, now.month + 1, 1)

    remaining_seconds = max(0, int((next_month - now).total_seconds()))
    days = remaining_seconds // 86400
    hours = (remaining_seconds % 86400) // 3600
    minutes = (remaining_seconds % 3600) // 60

    conn = db()
    board = _season_rows(conn, season_key)
    crown = board[0] if board and int(board[0].get("wins") or 0) > 0 else None

    leaders = []
    for i, row in enumerate(board[:3], 1):
        username = row["username"]
        streak = _season_win_streak(conn, username, season_key)
        user = conn.execute(
            "SELECT xp FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        xp = int(user["xp"] or 0) if user else 0
        creature = _creature_from_xp(xp)
        leaders.append({
            "rank": i,
            "username": username,
            "wins": int(row.get("wins") or 0),
            "losses": int(row.get("losses") or 0),
            "battles": int(row.get("battles") or 0),
            "win_streak": int(streak or 0),
            "avatar": creature["avatar"],
            "creature": creature["name"]
        })

    crown_stats = None
    if crown:
        crown_name = crown["username"]
        attacks = int(conn.execute(
            "SELECT COUNT(*) AS n FROM crown_events WHERE season_key = ? AND defender = ?",
            (season_key, crown_name)
        ).fetchone()["n"] or 0)
        defenses = int(conn.execute(
            """SELECT COUNT(*) AS n FROM crown_events
               WHERE season_key = ? AND defender = ? AND successful_defense = 1""",
            (season_key, crown_name)
        ).fetchone()["n"] or 0)
        crown_stats = {
            "username": crown_name,
            "wins": int(crown.get("wins") or 0),
            "losses": int(crown.get("losses") or 0),
            "attacks": attacks,
            "successful_defenses": defenses
        }

    total_battles = int(conn.execute(
        "SELECT COUNT(*) AS n FROM creature_battles WHERE season_key = ?",
        (season_key,)
    ).fetchone()["n"] or 0)
    active_hunters = int(conn.execute(
        """SELECT COUNT(DISTINCT hunter) AS n FROM (
             SELECT challenger AS hunter FROM creature_battles WHERE season_key = ?
             UNION
             SELECT opponent AS hunter FROM creature_battles WHERE season_key = ?
           )""",
        (season_key, season_key)
    ).fetchone()["n"] or 0)

    conn.close()

    return jsonify({
        "success": True,
        "season_key": season_key,
        "crown": crown_stats,
        "leaders": leaders,
        "total_battles": total_battles,
        "active_hunters": active_hunters,
        "remaining": {
            "seconds": remaining_seconds,
            "days": days,
            "hours": hours,
            "minutes": minutes,
            "label": f"{days}d {hours}h {minutes}m"
        }
    })


@app.route("/api/season")
def season_api():
    season_key = _current_season_key()
    conn = db()
    board = _season_rows(conn, season_key)
    conn.close()
    crown = board[0] if board and int(board[0].get("wins") or 0) > 0 else None
    return jsonify({"success": True, "season_key": season_key, "season_label": season_key, "crown": crown, "leaderboard": board[:20]})


@app.route("/api/season/<username>")
def season_user_api(username):
    season_key = _current_season_key()
    conn = db()
    board = _season_rows(conn, season_key)
    user_row = next((r for r in board if r["username"] == username), {"username": username, "wins": 0, "losses": 0, "battles": 0})
    rank = next((i for i, r in enumerate(board, 1) if r["username"] == username), None)
    streak = _season_win_streak(conn, username, season_key)
    conn.close()
    crown = board[0] if board and int(board[0].get("wins") or 0) > 0 else None
    user_row = dict(user_row)
    user_row["rank"] = rank
    user_row["win_streak"] = streak
    return jsonify({"success": True, "season_key": season_key, "season_label": season_key,
                    "crown": crown, "user": user_row, "leaderboard": board[:10]})


@app.route("/api/crown/defense/<username>")
def crown_defense_api(username):
    season_key = _current_season_key()
    conn = db()
    attacks = conn.execute("SELECT COUNT(*) AS n FROM crown_events WHERE season_key = ? AND defender = ?", (season_key, username)).fetchone()["n"]
    successful = conn.execute("SELECT COUNT(*) AS n FROM crown_events WHERE season_key = ? AND defender = ? AND successful_defense = 1", (season_key, username)).fetchone()["n"]
    challenges = conn.execute("SELECT COUNT(*) AS n FROM crown_events WHERE season_key = ? AND challenger = ?", (season_key, username)).fetchone()["n"]
    conn.close()
    return jsonify({"success": True, "season_key": season_key, "username": username,
                    "attacks": attacks, "successful_defenses": successful, "crown_challenges": challenges})


@app.route("/api/daily/<username>")
def daily_missions_api(username):
    today = datetime.utcnow().strftime("%Y-%m-%d")
    season_key = _current_season_key()
    conn = db()
    board = _season_rows(conn, season_key)
    crown = board[0]["username"] if board and int(board[0].get("wins") or 0) > 0 else None
    checked_in = conn.execute("SELECT 1 FROM quests WHERE username = ? AND quest = 'checkin' AND date = ? LIMIT 1", (username, today)).fetchone() is not None
    shared = conn.execute("SELECT 1 FROM share_claims WHERE username = ? AND date = ? LIMIT 1", (username, today)).fetchone() is not None
    clashed = conn.execute("SELECT 1 FROM creature_battles WHERE (challenger = ? OR opponent = ?) AND substr(created_at,1,10) = ? LIMIT 1", (username, username, today)).fetchone() is not None
    if crown == username:
        crown_done = conn.execute("SELECT 1 FROM crown_events WHERE defender = ? AND successful_defense = 1 AND substr(created_at,1,10) = ? LIMIT 1", (username, today)).fetchone() is not None
        crown_label = "Defend the Crown"
        crown_icon = "👑"
    elif crown:
        crown_done = conn.execute("SELECT 1 FROM crown_events WHERE challenger = ? AND defender = ? AND substr(created_at,1,10) = ? LIMIT 1", (username, crown, today)).fetchone() is not None
        crown_label = f"Challenge the Crown ({crown})"
        crown_icon = "⚔️"
    else:
        crown_done = False
        crown_label = "Create the first Crown race win"
        crown_icon = "👑"
    conn.close()
    missions = [
        {"key": "checkin", "icon": "🔥", "label": "Daily Check-in", "complete": checked_in},
        {"key": "share", "icon": "📣", "label": "Verify one BL3 Cast", "complete": shared},
        {"key": "clash", "icon": "👾", "label": "Complete one Alpha Clash", "complete": clashed},
        {"key": "crown", "icon": crown_icon, "label": crown_label, "complete": crown_done},
    ]
    completed = sum(1 for m in missions if m["complete"])
    return jsonify({"success": True, "date": today, "crown": crown, "missions": missions, "completed": completed, "total": len(missions)})



@app.route("/api/challenges", methods=["POST"])
def create_challenge_api():
    data = request.get_json(silent=True) or {}
    challenger = str(data.get("challenger", "")).strip()
    opponent = str(data.get("opponent", "")).strip()
    if not challenger or not opponent:
        return jsonify({"success": False, "message": "Challenger and opponent are required."}), 400
    if challenger == opponent:
        return jsonify({"success": False, "message": "You cannot challenge yourself."}), 400
    if session.get("authenticated_username") != challenger:
        return jsonify({"success": False, "message": "🔐 Sign in with the challenger wallet before sending a request."}), 401
    conn = db()
    c = conn.execute("SELECT 1 FROM users WHERE username = ?", (challenger,)).fetchone()
    o = conn.execute("SELECT 1 FROM users WHERE username = ?", (opponent,)).fetchone()
    if c is None or o is None:
        conn.close()
        return jsonify({"success": False, "message": "Both hunters must already have BL3 profiles."}), 404
    existing = conn.execute("""SELECT id FROM challenge_requests
                               WHERE challenger = ? AND opponent = ? AND status = 'pending'
                               ORDER BY id DESC LIMIT 1""", (challenger, opponent)).fetchone()
    if existing:
        conn.close()
        return jsonify({"success": True, "challenge_id": existing["id"], "message": "📨 Challenge already waiting in their inbox."})
    now = datetime.utcnow().isoformat()
    cur = conn.execute("""INSERT INTO challenge_requests
                          (challenger, opponent, status, created_at)
                          VALUES (?, ?, 'pending', ?)""", (challenger, opponent, now))
    challenge_id = cur.lastrowid
    _notify(conn, opponent, "challenge", f"⚔️ {challenger} challenged you",
            f"Challenge request #{challenge_id} is waiting in your Inbox.", "/#challenge-inbox")
    conn.commit()
    conn.close()
    return jsonify({"success": True, "challenge_id": challenge_id, "message": f"📨 Challenge sent to {opponent}."})


@app.route("/api/challenges/<username>")
def challenge_inbox_api(username):
    if session.get("authenticated_username") != username:
        return jsonify({"success": False, "message": "🔐 Sign in as this Hunter ID to open the challenge inbox."}), 401
    conn = db()
    incoming = [dict(r) for r in conn.execute("""SELECT id, challenger, opponent, status, created_at, responded_at, battle_id
                                                 FROM challenge_requests
                                                 WHERE opponent = ? AND status = 'pending'
                                                 ORDER BY id DESC LIMIT 30""", (username,)).fetchall()]
    outgoing = [dict(r) for r in conn.execute("""SELECT id, challenger, opponent, status, created_at, responded_at, battle_id
                                                 FROM challenge_requests
                                                 WHERE challenger = ?
                                                 ORDER BY id DESC LIMIT 15""", (username,)).fetchall()]
    conn.close()
    return jsonify({"success": True, "incoming": incoming, "outgoing": outgoing, "unread": len(incoming)})


@app.route("/api/challenges/<int:challenge_id>/accept", methods=["POST"])
def accept_challenge_api(challenge_id):
    conn = db()
    row = conn.execute("SELECT * FROM challenge_requests WHERE id = ?", (challenge_id,)).fetchone()
    conn.close()
    if row is None:
        return jsonify({"success": False, "message": "Challenge request not found."}), 404
    if row["status"] != "pending":
        return jsonify({"success": False, "message": "This challenge is no longer pending."}), 409
    if session.get("authenticated_username") != row["opponent"]:
        return jsonify({"success": False, "message": "🔐 Only the challenged hunter can accept this request."}), 401
    payload, status = _resolve_battle(row["challenger"], row["opponent"])
    if not payload.get("success"):
        return jsonify(payload), status
    now = datetime.utcnow().isoformat()
    conn = db()
    conn.execute("""UPDATE challenge_requests SET status = 'accepted', responded_at = ?, battle_id = ?
                    WHERE id = ? AND status = 'pending'""", (now, payload["battle_id"], challenge_id))
    _add_rep(conn, row["challenger"], 1, f"Accepted challenge #{challenge_id} participation", f"challenge:{challenge_id}:challenger")
    _add_rep(conn, row["opponent"], 1, f"Accepted challenge #{challenge_id} participation", f"challenge:{challenge_id}:opponent")
    _notify(conn, row["challenger"], "challenge", f"⚔️ {row['opponent']} accepted your challenge",
            f"Clash #{payload['battle_id']} resolved. Winner: {payload['winner']}.", f"/clash/{payload['battle_id']}")
    _notify(conn, row["opponent"], "battle", f"👑 Clash #{payload['battle_id']} resolved",
            f"Winner: {payload['winner']}. Open the public Battle Card.", f"/clash/{payload['battle_id']}")
    conn.commit()
    conn.close()
    payload["challenge_id"] = challenge_id
    payload["message"] = "⚔️ Challenge accepted and resolved."
    return jsonify(payload)


@app.route("/api/challenges/<int:challenge_id>/decline", methods=["POST"])
def decline_challenge_api(challenge_id):
    conn = db()
    row = conn.execute("SELECT * FROM challenge_requests WHERE id = ?", (challenge_id,)).fetchone()
    if row is None:
        conn.close()
        return jsonify({"success": False, "message": "Challenge request not found."}), 404
    if row["status"] != "pending":
        conn.close()
        return jsonify({"success": False, "message": "This challenge is no longer pending."}), 409
    if session.get("authenticated_username") != row["opponent"]:
        conn.close()
        return jsonify({"success": False, "message": "🔐 Only the challenged hunter can decline this request."}), 401
    conn.execute("UPDATE challenge_requests SET status = 'declined', responded_at = ? WHERE id = ?", (datetime.utcnow().isoformat(), challenge_id))
    _notify(conn, row["challenger"], "challenge", f"Challenge #{challenge_id} declined",
            f"{row['opponent']} declined the request. Pick another hunter or try later.", "")
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Challenge declined."})


@app.route("/api/notifications/<username>")
def notifications_api(username):
    if session.get("authenticated_username") != username:
        return jsonify({"success": False, "message": "🔐 Sign in as this Hunter ID to read private signals."}), 401
    conn = db()
    rows = [dict(r) for r in conn.execute(
        """SELECT id, username, kind, title, detail, link, is_read, created_at
           FROM notifications WHERE username = ? ORDER BY id DESC LIMIT 40""", (username,)
    ).fetchall()]
    unread = conn.execute("SELECT COUNT(*) AS n FROM notifications WHERE username = ? AND is_read = 0", (username,)).fetchone()["n"]
    conn.close()
    return jsonify({"success": True, "notifications": rows, "unread": unread})


@app.route("/api/notifications/<username>/read-all", methods=["POST"])
def notifications_read_all_api(username):
    if session.get("authenticated_username") != username:
        return jsonify({"success": False, "message": "🔐 Sign in as this Hunter ID first."}), 401
    conn = db()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "✓ All Hunter signals marked read."})


@app.route("/api/network-heat")
def network_heat_api():
    """
    Public 7-day BL3 activity signal.
    Uses only public/completed events and exposes transparent activity counts.
    """
    conn = db()
    cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()
    heat = {}

    def touch(username, kind, count_activity=True):
        username = str(username or "").strip()
        if not username:
            return
        item = heat.setdefault(username, {
            "username": username,
            "activity_count": 0,
            "battles": 0,
            "wins": 0,
            "unlocks": 0,
            "proofs": 0,
            "followers": 0
        })
        if count_activity:
            item["activity_count"] += 1
        if kind in item:
            item[kind] += 1

    battles = conn.execute(
        """SELECT challenger, opponent, winner
           FROM creature_battles
           WHERE created_at >= ?
           ORDER BY id DESC""",
        (cutoff,)
    ).fetchall()
    for r in battles:
        touch(r["challenger"], "battles")
        touch(r["opponent"], "battles")
        if r["winner"]:
            # Battle participation already counted as activity; wins are a stat only.
            touch(r["winner"], "wins", count_activity=False)

    unlocks = conn.execute(
        """SELECT username FROM hunter_unlock_events
           WHERE created_at >= ?
           ORDER BY id DESC""",
        (cutoff,)
    ).fetchall()
    for r in unlocks:
        touch(r["username"], "unlocks")

    proofs = conn.execute(
        """SELECT username FROM arena_submissions
           WHERE created_at >= ?
           ORDER BY id DESC""",
        (cutoff,)
    ).fetchall()
    for r in proofs:
        touch(r["username"], "proofs")

    follower_rows = conn.execute(
        """SELECT target, COUNT(*) AS n
           FROM hunter_connections
           WHERE kind = 'follow'
           GROUP BY target"""
    ).fetchall()
    follower_map = {str(r["target"]): int(r["n"] or 0) for r in follower_rows}

    users = {
        r["username"]: r
        for r in conn.execute("SELECT username, xp FROM users").fetchall()
    }

    rivalry = {}
    for r in conn.execute(
        """SELECT challenger, opponent, winner
           FROM creature_battles
           WHERE created_at >= ?
           ORDER BY id DESC""",
        (cutoff,)
    ).fetchall():
        a, b = sorted([str(r["challenger"]), str(r["opponent"])])
        if not a or not b or a == b:
            continue
        key = (a, b)
        item = rivalry.setdefault(key, {
            "hunter_a": a, "hunter_b": b,
            "clashes": 0, "a_wins": 0, "b_wins": 0
        })
        item["clashes"] += 1
        if r["winner"] == a:
            item["a_wins"] += 1
        elif r["winner"] == b:
            item["b_wins"] += 1

    conn.close()

    hunters = []
    for username, item in heat.items():
        user = users.get(username)
        xp = int(user["xp"] or 0) if user else 0
        creature = _creature_from_xp(xp)
        item["followers"] = follower_map.get(username, 0)
        hunters.append({
            **item,
            "xp": xp,
            "avatar": creature["avatar"],
            "creature": creature["name"],
            "level": max(1, xp // 100 + 1)
        })

    hunters.sort(
        key=lambda h: (h["activity_count"], h["wins"], h["battles"], h["followers"]),
        reverse=True
    )
    top = hunters[:8]
    max_activity = max([h["activity_count"] for h in top], default=1)
    for h in top:
        h["heat_percent"] = max(
            5,
            round((h["activity_count"] / max_activity) * 100)
        ) if h["activity_count"] else 0

    rivalries = list(rivalry.values())
    rivalries.sort(
        key=lambda x: (x["clashes"], x["a_wins"] + x["b_wins"]),
        reverse=True
    )
    rivalries = rivalries[:5]
    max_clashes = max([r["clashes"] for r in rivalries], default=1)
    for r in rivalries:
        r["heat_percent"] = max(
            8,
            round((r["clashes"] / max_clashes) * 100)
        )

    return jsonify({
        "success": True,
        "window_days": 7,
        "hunters": top,
        "rivalries": rivalries,
        "method": "Public activity in the last 7 days: completed Clashes, unlocks, and Arena proof submissions. Followers are shown separately and do not increase activity_count."
    })


@app.route("/api/activity")
def activity_api():
    try:
        limit = max(1, min(50, int(request.args.get("limit", 18))))
    except Exception:
        limit = 18
    conn = db()
    events = []

    def add(kind, icon, title, detail, created_at, event_id=0):
        events.append({
            "kind": kind, "icon": icon, "title": title, "detail": detail,
            "created_at": created_at or "", "event_id": int(event_id or 0)
        })

    for r in conn.execute("""SELECT id, challenger, opponent, winner, commentary, created_at
                           FROM creature_battles ORDER BY id DESC LIMIT 25""").fetchall():
        add("battle", "⚔️", f"{r['challenger']} challenged {r['opponent']}",
            f"👑 {r['winner']} won · {r['commentary']}", r["created_at"], r["id"])

    for r in conn.execute("""SELECT id, challenger, defender, winner, successful_defense, created_at
                           FROM crown_events ORDER BY id DESC LIMIT 15""").fetchall():
        detail = (f"👑 {r['defender']} defended the Crown" if r["successful_defense"]
                  else f"🔥 {r['challenger']} broke the Crown defense")
        add("crown", "👑", f"Crown attack: {r['challenger']} → {r['defender']}", detail, r["created_at"], r["id"])

    for r in conn.execute("""SELECT id, creator, title, category, bounty_amount, bounty_asset, created_at
                           FROM arenas ORDER BY id DESC LIMIT 15""").fetchall():
        add("arena", "🎯", f"{r['creator']} launched an Arena", r["title"] + f" · {r['bounty_amount']:g} {r['bounty_asset']} · {r['category']}", r["created_at"], r["id"])

    for r in conn.execute("""SELECT id, username, arena_id, created_at
                           FROM arena_submissions ORDER BY id DESC LIMIT 15""").fetchall():
        add("proof", "🧠", f"{r['username']} submitted proof", f"Arena #{r['arena_id']}", r["created_at"], r["id"])

    for r in conn.execute("""SELECT id, invited, date FROM referrals ORDER BY id DESC LIMIT 15""").fetchall():
        add("referral", "👥", f"{r['invited']} joined the network", "New Hunter joined BL3", (r["date"] or "") + "T12:00:00", r["id"])

    for r in conn.execute("""SELECT id, username, date FROM share_claims ORDER BY id DESC LIMIT 15""").fetchall():
        add("share", "📣", f"{r['username']} verified a BL3 cast", "Social proof added to the network", (r["date"] or "") + "T12:00:00", r["id"])

    for r in conn.execute("""SELECT id, username, kind, icon, title, detail, created_at
                           FROM hunter_unlock_events ORDER BY id DESC LIMIT 20""").fetchall():
        add(
            "unlock",
            r["icon"] or "✨",
            f"{r['username']} unlocked {r['title']}",
            f"{r['kind']} · {r['detail']}",
            r["created_at"],
            r["id"]
        )

    conn.close()
    events.sort(key=lambda e: (e["created_at"], e["event_id"]), reverse=True)
    return jsonify({"success": True, "events": events[:limit]})


@app.route("/api/revenge-queue/<username>")
def revenge_queue_api(username):
    if session.get("authenticated_username") != username:
        return jsonify({
            "success": False,
            "message": "🔐 Sign in with this Hunter ID to open the Revenge Queue."
        }), 401

    conn = db()
    exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    if exists is None:
        conn.close()
        return jsonify({"success": False, "message": "Hunter not found"}), 404

    tracked = {
        r["target"] for r in conn.execute(
            """SELECT target FROM hunter_connections
               WHERE owner = ? AND kind = 'rival'""",
            (username,)
        ).fetchall()
    }

    rows = conn.execute(
        """SELECT id, challenger, opponent, winner, created_at
           FROM creature_battles
           WHERE challenger = ? OR opponent = ?
           ORDER BY id DESC LIMIT 200""",
        (username, username)
    ).fetchall()

    users = {}
    if tracked:
        placeholders = ",".join("?" for _ in tracked)
        for r in conn.execute(
            f"SELECT username, xp FROM users WHERE username IN ({placeholders})",
            tuple(tracked)
        ).fetchall():
            users[r["username"]] = r
    conn.close()

    by_rival = {}
    for row in rows:
        rival = row["opponent"] if row["challenger"] == username else row["challenger"]
        if rival not in tracked:
            continue

        item = by_rival.setdefault(rival, {
            "username": rival,
            "last_battle_id": int(row["id"]),
            "last_created_at": row["created_at"],
            "last_winner": row["winner"],
            "loss_streak": 0,
            "seen_first": False
        })

        # First row per rival is their latest direct Clash.
        if not item["seen_first"]:
            item["last_battle_id"] = int(row["id"])
            item["last_created_at"] = row["created_at"]
            item["last_winner"] = row["winner"]
            item["seen_first"] = True

        # Count consecutive direct losses from the newest result backward.
        if item["loss_streak"] >= 0:
            if row["winner"] != username:
                item["loss_streak"] += 1
            else:
                item["loss_streak"] = -item["loss_streak"] - 1

    queue = []
    for rival, item in by_rival.items():
        # Decode sentinel: only rivals whose latest run begins with one or more losses.
        if item["last_winner"] == username:
            continue

        raw = item["loss_streak"]
        loss_streak = raw if raw >= 0 else (-raw - 1)
        if loss_streak <= 0:
            continue

        user = users.get(rival)
        xp = int(user["xp"] or 0) if user else 0
        creature = _creature_from_xp(xp)

        if loss_streak >= 3:
            state = {"key": "blood", "icon": "🩸", "label": "BLOOD FEUD"}
        elif loss_streak == 2:
            state = {"key": "urgent", "icon": "🔥", "label": "REVENGE DUE"}
        else:
            state = {"key": "open", "icon": "⚔️", "label": "RUN IT BACK"}

        queue.append({
            "username": rival,
            "avatar": creature["avatar"],
            "creature": creature["name"],
            "level": max(1, xp // 100 + 1),
            "loss_streak": loss_streak,
            "last_battle_id": item["last_battle_id"],
            "last_created_at": item["last_created_at"],
            "state": state
        })

    queue.sort(
        key=lambda x: (x["loss_streak"], x["last_battle_id"]),
        reverse=True
    )

    return jsonify({
        "success": True,
        "username": username,
        "count": len(queue),
        "targets": queue[:8],
        "method": "Tracked rivals only. Queue contains rivals who won the latest direct Clash against you; urgency grows with consecutive direct losses."
    })


@app.route("/api/ops-pulse/<username>")
def ops_pulse_api(username):
    if session.get("authenticated_username") != username:
        return jsonify({
            "success": False,
            "message": "🔐 Sign in with this Hunter ID to open Ops Pulse."
        }), 401

    conn = db()
    exists = conn.execute(
        "SELECT 1 FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    if exists is None:
        conn.close()
        return jsonify({"success": False, "message": "Hunter not found"}), 404

    since = (datetime.utcnow() - timedelta(hours=24)).isoformat()

    battles = conn.execute(
        """SELECT id, challenger, opponent, winner, created_at
           FROM creature_battles
           WHERE (challenger = ? OR opponent = ?)
             AND created_at >= ?
           ORDER BY id DESC""",
        (username, username, since)
    ).fetchall()

    wins = 0
    losses = 0
    latest = []
    for row in battles:
        rival = row["opponent"] if row["challenger"] == username else row["challenger"]
        won = row["winner"] == username
        wins += 1 if won else 0
        losses += 0 if won else 1
        if len(latest) < 4:
            latest.append({
                "kind": "clash",
                "icon": "⚔️",
                "title": f"{'WIN' if won else 'LOSS'} vs {rival}",
                "detail": f"Clash #{int(row['id'])}",
                "target": f"/clash/{int(row['id'])}",
                "created_at": row["created_at"]
            })

    unlocks = conn.execute(
        """SELECT id, icon, title, kind, created_at
           FROM hunter_unlock_events
           WHERE username = ? AND created_at >= ?
           ORDER BY id DESC LIMIT 4""",
        (username, since)
    ).fetchall()

    for row in unlocks:
        latest.append({
            "kind": "unlock",
            "icon": row["icon"] or "✨",
            "title": row["title"] or "NEW UNLOCK",
            "detail": row["kind"] or "UNLOCK",
            "target": f"/progress/{urllib.parse.quote(username)}",
            "created_at": row["created_at"]
        })

    pending = int(conn.execute(
        """SELECT COUNT(*) AS n
           FROM challenge_requests
           WHERE opponent = ? AND status = 'pending'""",
        (username,)
    ).fetchone()["n"] or 0)

    conn.close()
    latest.sort(key=lambda e: e.get("created_at") or "", reverse=True)

    return jsonify({
        "success": True,
        "username": username,
        "window_hours": 24,
        "clashes": len(battles),
        "wins": wins,
        "losses": losses,
        "unlocks": len(unlocks),
        "pending_challenges": pending,
        "latest": latest[:5]
    })


@app.route("/api/mission-control/<username>")
def mission_control_api(username):
    if session.get("authenticated_username") != username:
        return jsonify({
            "success": False,
            "message": "🔐 Sign in with this Hunter ID to open Mission Control."
        }), 401

    conn = db()
    user = conn.execute(
        "SELECT username, xp FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    if user is None:
        conn.close()
        return jsonify({"success": False, "message": "Hunter not found"}), 404

    season_key = _current_season_key()
    season_streak = _season_win_streak(conn, username, season_key)

    pending_inbox = int(conn.execute(
        """SELECT COUNT(*) AS n FROM challenge_requests
           WHERE opponent = ? AND status = 'pending'""",
        (username,)
    ).fetchone()["n"] or 0)

    unseen_unlocks = int(conn.execute(
        """SELECT COUNT(*) AS n FROM hunter_unlock_events
           WHERE username = ? AND is_seen = 0""",
        (username,)
    ).fetchone()["n"] or 0)

    crown_board = _season_rows(conn, season_key)
    crown_name = (
        crown_board[0]["username"]
        if crown_board and int(crown_board[0].get("wins") or 0) > 0
        else None
    )
    is_crown = crown_name == username

    featured_row = conn.execute(
        "SELECT rival FROM hunter_featured_nemesis WHERE username = ?",
        (username,)
    ).fetchone()
    featured_rival = featured_row["rival"] if featured_row else None

    # Top revenge target from tracked rivals only.
    tracked = {
        r["target"] for r in conn.execute(
            """SELECT target FROM hunter_connections
               WHERE owner = ? AND kind = 'rival'""",
            (username,)
        ).fetchall()
    }
    battle_rows = conn.execute(
        """SELECT id, challenger, opponent, winner, created_at
           FROM creature_battles
           WHERE challenger = ? OR opponent = ?
           ORDER BY id DESC LIMIT 200""",
        (username, username)
    ).fetchall()
    conn.close()

    by_rival = {}
    for row in battle_rows:
        rival = row["opponent"] if row["challenger"] == username else row["challenger"]
        if rival not in tracked:
            continue
        item = by_rival.setdefault(rival, {
            "last_battle_id": int(row["id"]),
            "last_winner": row["winner"],
            "loss_streak": 0,
            "closed": False
        })
        if item["closed"]:
            continue
        if row["winner"] != username:
            item["loss_streak"] += 1
        else:
            item["closed"] = True

    revenge = []
    for rival, item in by_rival.items():
        if item["last_winner"] == username:
            continue
        if int(item["loss_streak"] or 0) <= 0:
            continue
        revenge.append({
            "username": rival,
            "loss_streak": int(item["loss_streak"]),
            "last_battle_id": int(item["last_battle_id"])
        })
    revenge.sort(
        key=lambda x: (x["loss_streak"], x["last_battle_id"]),
        reverse=True
    )
    top_revenge = revenge[0] if revenge else None

    progress = _hunter_progress_dashboard(username) or {}
    closest = progress.get("closest") or {}

    # Deterministic next action; this is navigation guidance, not a reward.
    if pending_inbox > 0:
        next_action = {
            "key": "inbox",
            "icon": "📨",
            "title": "ANSWER YOUR CHALLENGE",
            "detail": f"{pending_inbox} pending challenge{'s' if pending_inbox != 1 else ''} waiting.",
            "target": "#challengeInbox"
        }
    elif top_revenge:
        next_action = {
            "key": "revenge",
            "icon": "🩸",
            "title": f"RUN IT BACK VS {top_revenge['username']}",
            "detail": f"{top_revenge['loss_streak']} direct loss{'es' if top_revenge['loss_streak'] != 1 else ''} in the current revenge run.",
            "target": "#revengeQueue"
        }
    elif unseen_unlocks > 0:
        next_action = {
            "key": "unlocks",
            "icon": "✨",
            "title": "REVIEW NEW UNLOCKS",
            "detail": f"{unseen_unlocks} unseen unlock{'s' if unseen_unlocks != 1 else ''}.",
            "target": f"/progress/{urllib.parse.quote(username)}"
        }
    elif featured_rival:
        next_action = {
            "key": "nemesis",
            "icon": "😈",
            "title": f"PRESSURE {featured_rival}",
            "detail": "Your Featured Nemesis is active.",
            "target": "#nemesisDuel"
        }
    else:
        next_action = {
            "key": "progress",
            "icon": closest.get("icon") or "📈",
            "title": closest.get("title") or "BUILD YOUR HUNTER",
            "detail": closest.get("detail") or "Keep progressing through BL3.",
            "target": f"/progress/{urllib.parse.quote(username)}"
        }

    action_deck = []
    if pending_inbox > 0:
        action_deck.append({
            "icon": "📨",
            "title": "CHALLENGE INBOX",
            "detail": f"{pending_inbox} pending",
            "target": "#challengeInbox"
        })
    if top_revenge:
        action_deck.append({
            "icon": "🩸",
            "title": f"REVENGE: {top_revenge['username']}",
            "detail": f"{top_revenge['loss_streak']} straight loss{'es' if top_revenge['loss_streak'] != 1 else ''}",
            "target": "#revengeQueue"
        })
    if featured_rival:
        action_deck.append({
            "icon": "😈",
            "title": f"NEMESIS: {featured_rival}",
            "detail": "Open your featured feud",
            "target": "#nemesisDuel"
        })
    if closest:
        action_deck.append({
            "icon": closest.get("icon") or "📈",
            "title": closest.get("title") or "NEXT UNLOCK",
            "detail": f"{int(closest.get('percent') or 0)}% progress",
            "target": f"/progress/{urllib.parse.quote(username)}"
        })

    return jsonify({
        "success": True,
        "username": username,
        "season_key": season_key,
        "season_streak": int(season_streak or 0),
        "pending_inbox": pending_inbox,
        "unseen_unlocks": unseen_unlocks,
        "is_crown": bool(is_crown),
        "crown": crown_name,
        "featured_nemesis": featured_rival,
        "top_revenge": top_revenge,
        "closest": closest,
        "next_action": next_action,
        "action_deck": action_deck[:3]
    })


@app.route("/api/threat-radar/<username>")
def threat_radar_api(username):
    if session.get("authenticated_username") != username:
        return jsonify({
            "success": False,
            "message": "🔐 Sign in with this Hunter ID to open the Nemesis Threat Radar."
        }), 401

    conn = db()
    exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    if exists is None:
        conn.close()
        return jsonify({"success": False, "message": "Hunter not found"}), 404

    rival_rows = conn.execute(
        """SELECT target FROM hunter_connections
           WHERE owner = ? AND kind = 'rival'
           ORDER BY created_at DESC
           LIMIT 16""",
        (username,)
    ).fetchall()
    rivals = [r["target"] for r in rival_rows]
    rival_xp = {}
    if rivals:
        placeholders = ",".join("?" for _ in rivals)
        rival_xp = {
            r["username"]: int(r["xp"] or 0)
            for r in conn.execute(
                f"SELECT username, xp FROM users WHERE username IN ({placeholders})",
                tuple(rivals)
            ).fetchall()
        }
    featured_row = conn.execute(
        "SELECT rival FROM hunter_featured_nemesis WHERE username = ?",
        (username,)
    ).fetchone()
    featured_nemesis = featured_row["rival"] if featured_row else None
    season_key = _current_season_key()
    conn.close()

    threats = []
    for rival in rivals:
        h2h = _head_to_head(username, rival, 5)
        my_wins = int(h2h.get("a_wins") or 0)
        rival_wins = int(h2h.get("b_wins") or 0)
        total = int(h2h.get("total") or 0)
        lead = rival_wins - my_wins

        conn = db()
        rival_streak = _season_win_streak(conn, rival, season_key)
        conn.close()

        xp = int(rival_xp.get(rival, 0))
        creature = _creature_from_xp(xp)
        momentum = _momentum_state(rival_streak)

        if total >= 5:
            status = {"key": "nemesis", "icon": "😈", "label": "NEMESIS"}
        elif lead >= 2:
            status = {"key": "pressure", "icon": "🚨", "label": "UNDER PRESSURE"}
        elif rival_streak >= 3:
            status = {"key": "hot", "icon": "🔥", "label": "HOT RIVAL"}
        elif total >= 2 and my_wins == rival_wins:
            status = {"key": "even", "icon": "⚖️", "label": "DEAD EVEN"}
        elif my_wins > rival_wins:
            status = {"key": "ahead", "icon": "🛡️", "label": "YOU LEAD"}
        else:
            status = {"key": "tracked", "icon": "🎯", "label": "TRACKED RIVAL"}

        threats.append({
            "username": rival,
            "avatar": creature["avatar"],
            "creature": creature["name"],
            "level": max(1, xp // 100 + 1),
            "clashes": total,
            "your_wins": my_wins,
            "rival_wins": rival_wins,
            "rival_lead": lead,
            "last_winner": h2h.get("last_winner"),
            "rival_streak": int(rival_streak or 0),
            "momentum": momentum,
            "status": status
        })

    def threat_sort_key(item):
        status_key = item["status"]["key"]
        priority = {
            "nemesis": 6,
            "pressure": 5,
            "hot": 4,
            "even": 3,
            "tracked": 2,
            "ahead": 1,
        }.get(status_key, 0)
        return (
            priority,
            max(0, int(item.get("rival_lead") or 0)),
            int(item.get("rival_streak") or 0),
            int(item.get("clashes") or 0)
        )

    threats.sort(key=threat_sort_key, reverse=True)
    return jsonify({
        "success": True,
        "username": username,
        "season_key": season_key,
        "rivals": threats[:8],
        "count": len(threats),
        "featured_nemesis": featured_nemesis,
        "method": "Tracked rivals only; status uses direct Clash record, current season win streak, and rivalry depth."
    })


@app.route("/api/rivals/<username>/activity")
def rival_activity_api(username):
    if session.get("authenticated_username") != username:
        return jsonify({"success": False, "message": "🔐 Sign in with this Hunter ID to open Rival Watch"}), 401
    try:
        limit = max(1, min(40, int(request.args.get("limit", 16))))
    except Exception:
        limit = 16
    conn = db()
    rivals = [r["target"] for r in conn.execute(
        "SELECT target FROM hunter_connections WHERE owner = ? AND kind = 'rival' ORDER BY created_at DESC",
        (username,)
    ).fetchall()]
    if not rivals:
        conn.close()
        return jsonify({"success": True, "rivals": [], "events": []})
    events = []
    rival_set = set(rivals)

    def add(kind, icon, title, detail, created_at, event_id=0):
        events.append({
            "kind": kind, "icon": icon, "title": title, "detail": detail,
            "created_at": created_at or "", "event_id": int(event_id or 0)
        })

    for r in conn.execute("SELECT id, challenger, opponent, status, created_at FROM challenge_requests ORDER BY id DESC LIMIT 80").fetchall():
        if r["challenger"] in rival_set or r["opponent"] in rival_set:
            detail = "Waiting for response" if r["status"] == "pending" else f"Status: {r['status']}"
            add("challenge", "📨", f"{r['challenger']} challenged {r['opponent']}", detail, r["created_at"], r["id"])

    for r in conn.execute("SELECT id, challenger, opponent, winner, commentary, created_at FROM creature_battles ORDER BY id DESC LIMIT 100").fetchall():
        if r["challenger"] in rival_set or r["opponent"] in rival_set:
            add("battle", "⚔️", f"{r['challenger']} vs {r['opponent']}", f"👑 {r['winner']} won · {r['commentary']}", r["created_at"], r["id"])

    for r in conn.execute("SELECT id, challenger, defender, winner, successful_defense, created_at FROM crown_events ORDER BY id DESC LIMIT 60").fetchall():
        if r["challenger"] in rival_set or r["defender"] in rival_set:
            detail = f"👑 {r['defender']} defended the Crown" if r["successful_defense"] else f"🔥 {r['challenger']} broke the Crown defense"
            add("crown", "👑", f"Crown move: {r['challenger']} → {r['defender']}", detail, r["created_at"], r["id"])

    for r in conn.execute("SELECT id, creator, title, category, bounty_amount, bounty_asset, created_at FROM arenas ORDER BY id DESC LIMIT 60").fetchall():
        if r["creator"] in rival_set:
            add("arena", "🎯", f"{r['creator']} launched an Arena", r["title"] + f" · {r['bounty_amount']:g} {r['bounty_asset']} · {r['category']}", r["created_at"], r["id"])

    for r in conn.execute("SELECT id, username, arena_id, created_at FROM arena_submissions ORDER BY id DESC LIMIT 80").fetchall():
        if r["username"] in rival_set:
            add("proof", "🧠", f"{r['username']} submitted proof", f"Arena #{r['arena_id']}", r["created_at"], r["id"])

    for r in conn.execute("SELECT id, username, date FROM share_claims ORDER BY id DESC LIMIT 60").fetchall():
        if r["username"] in rival_set:
            add("share", "📣", f"{r['username']} verified a BL3 cast", "Rival social proof added", (r["date"] or "") + "T12:00:00", r["id"])

    conn.close()
    events.sort(key=lambda e: (e["created_at"], e["event_id"]), reverse=True)
    return jsonify({"success": True, "rivals": rivals, "events": events[:limit]})


@app.route("/rivals/<username>")
def rival_directory_page(username):
    if session.get("authenticated_username") != username:
        return "Sign in with this Hunter ID to view Rivals", 401
    conn = db()
    rows = conn.execute(
        """SELECT hc.target, hc.created_at, COALESCE(u.xp,0) AS xp
           FROM hunter_connections hc LEFT JOIN users u ON u.username = hc.target
           WHERE hc.owner = ? AND hc.kind = 'rival'
           ORDER BY hc.created_at DESC""", (username,)
    ).fetchall()
    conn.close()
    esc = lambda v: html.escape(str(v or ""))
    cards = ""
    for r in rows:
        h2h = _head_to_head(username, r["target"], 1)
        record = f'{h2h["a_wins"]}-{h2h["b_wins"]}' if h2h["total"] else '0-0'
        cards += (
            f'<a class="r" href="/hunter/{urllib.parse.quote(r["target"])}">'
            f'<b>🎯 {esc(r["target"])}</b>'
            f'<span>H2H {record} · {int(r["xp"] or 0)} XP · VIEW HUNTER →</span></a>'
        )
    if not cards:
        cards = '<div class="empty">No Rivals yet. Mark Hunters as Rival from their public profile.</div>'
    return f"""<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(username)} Rivals // BL3</title><style>body{{margin:0;background:#08080d;color:#fff;font-family:Arial,sans-serif}}.shell{{max-width:820px;margin:auto;padding:28px}}.brand{{font-size:24px;font-weight:900}}.brand span,.eyebrow{{color:#b8ff5a}}h1{{font-size:48px;margin:38px 0 8px}}.meta,.r span{{color:#9292a3}}.r{{display:flex;justify-content:space-between;gap:18px;text-decoration:none;color:#fff;border:1px solid #2a2a34;background:#111119;padding:20px;border-radius:18px;margin-top:12px}}.r:hover{{border-color:#b8ff5a}}.back{{color:#b8ff5a;text-decoration:none}}.empty{{margin-top:20px;color:#9292a3;border:1px dashed #333;padding:20px;border-radius:16px}}@media(max-width:620px){{h1{{font-size:38px}}.r{{flex-direction:column}}}}</style></head><body><div class="shell"><div class="brand">BL3 ● <span>RIVAL NETWORK</span></div><h1>{esc(username)}'s Rivals</h1><div class="meta">Hunters you chose to watch closely. Their moves appear in your private Rival Feed.</div>{cards}<div style="margin-top:30px"><a class="back" href="/">← BACK TO LIVE NETWORK</a></div></div></body></html>"""


@app.route("/api/reputation/<username>")
def reputation_api(username):
    conn = db()
    total = conn.execute(
        "SELECT COALESCE(SUM(points), 0) AS rep FROM reputation_events WHERE username = ?",
        (username,)
    ).fetchone()["rep"]
    submissions = conn.execute(
        "SELECT COUNT(*) AS n FROM arena_submissions WHERE username = ?",
        (username,)
    ).fetchone()["n"]
    arena_wins = conn.execute(
        "SELECT COUNT(*) AS n FROM arenas WHERE winner_username = ?",
        (username,)
    ).fetchone()["n"]
    clash_wins = conn.execute(
        "SELECT COUNT(*) AS n FROM creature_battles WHERE winner = ?",
        (username,)
    ).fetchone()["n"]
    wins = arena_wins + clash_wins
    earned = conn.execute(
        "SELECT COALESCE(SUM(bounty_amount), 0) AS amount FROM arenas WHERE winner_username = ? AND paid = 1",
        (username,)
    ).fetchone()["amount"]
    conn.close()
    return jsonify({
        "success": True,
        "username": username,
        "reputation": total,
        "submissions": submissions,
        "wins": wins,
        "earned": earned
    })



@app.route("/api/discovery/<username>")
def hunter_discovery_api(username):
    viewer = session.get("authenticated_username") or ""
    if viewer != username:
        return jsonify({
            "success": False,
            "message": "🔐 Sign in with this Hunter ID to discover matched Hunters."
        }), 401

    try:
        limit = max(1, min(12, int(request.args.get("limit", 6))))
    except Exception:
        limit = 6

    conn = db()
    me = conn.execute("SELECT username, xp FROM users WHERE username = ?", (username,)).fetchone()
    if me is None:
        conn.close()
        return jsonify({"success": False, "message": "Hunter not found"}), 404

    my_xp = int(me["xp"] or 0)
    my_rep = int(conn.execute(
        "SELECT COALESCE(SUM(points), 0) AS n FROM reputation_events WHERE username = ?",
        (username,)
    ).fetchone()["n"] or 0)

    candidates = []
    users = conn.execute(
        "SELECT username, xp FROM users WHERE username <> ? ORDER BY xp DESC LIMIT 100",
        (username,)
    ).fetchall()

    for row in users:
        target = row["username"]
        xp = int(row["xp"] or 0)
        rep = int(conn.execute(
            "SELECT COALESCE(SUM(points), 0) AS n FROM reputation_events WHERE username = ?",
            (target,)
        ).fetchone()["n"] or 0)
        wins = int(conn.execute(
            """SELECT
                 (SELECT COUNT(*) FROM creature_battles WHERE winner = ?) +
                 (SELECT COUNT(*) FROM arenas WHERE winner_username = ?) AS n""",
            (target, target)
        ).fetchone()["n"] or 0)
        activity = int(conn.execute(
            """SELECT
                 (SELECT COUNT(*) FROM creature_battles WHERE challenger = ? OR opponent = ?) +
                 (SELECT COUNT(*) FROM arena_submissions WHERE username = ?) +
                 (SELECT COUNT(*) FROM arenas WHERE creator = ?) +
                 (SELECT COUNT(*) FROM share_claims WHERE username = ?) AS n""",
            (target, target, target, target, target)
        ).fetchone()["n"] or 0)
        followers = int(conn.execute(
            "SELECT COUNT(*) AS n FROM hunter_connections WHERE target = ? AND kind = 'follow'",
            (target,)
        ).fetchone()["n"] or 0)
        is_following = conn.execute(
            "SELECT 1 FROM hunter_connections WHERE owner = ? AND target = ? AND kind = 'follow'",
            (username, target)
        ).fetchone() is not None
        is_rival = conn.execute(
            "SELECT 1 FROM hunter_connections WHERE owner = ? AND target = ? AND kind = 'rival'",
            (username, target)
        ).fetchone() is not None

        xp_gap = abs(my_xp - xp)
        rep_gap = abs(my_rep - rep)
        closeness = max(0, 70 - min(70, xp_gap // 10))
        rep_closeness = max(0, 20 - min(20, rep_gap // 5))
        active_bonus = min(25, activity * 3)
        social_bonus = min(10, followers)
        new_rival_bonus = 8 if not is_rival else 0
        score = int(closeness + rep_closeness + active_bonus + social_bonus + new_rival_bonus)

        creature = _creature_from_xp(xp)
        level = max(1, (xp // 100) + 1)
        candidates.append({
            "username": target,
            "xp": xp,
            "reputation": rep,
            "wins": wins,
            "activity": activity,
            "followers": followers,
            "is_following": is_following,
            "is_rival": is_rival,
            "avatar": creature["avatar"],
            "level": level,
            "match_score": score
        })

    conn.close()
    candidates.sort(
        key=lambda h: (h["match_score"], h["activity"], h["reputation"], h["xp"]),
        reverse=True
    )
    return jsonify({
        "success": True,
        "username": username,
        "hunters": candidates[:limit]
    })



# ===== V13.3 GLOBAL SEARCH =====
def _public_origin():
    configured = (os.environ.get("BL3_PUBLIC_URL") or "").strip().rstrip("/")
    return configured or request.url_root.rstrip("/")


@app.after_request
def quality_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.path.startswith("/api/") or request.path in ("/healthz", "/status"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.route("/api/global-search")
def global_search_api():
    q = str(request.args.get("q") or "").strip()[:80]
    q_lower = q.lower()
    limit = 6

    commands = [
        {"type": "command", "icon": "📡", "title": "Discovery Engine", "subtitle": "Find Feuds and Hunters worth watching", "url": "#discoveryEngine", "keywords": "discovery explore hunters feuds"},
        {"type": "command", "icon": "📈", "title": "Trending Feuds", "subtitle": "See the Rivalries gaining momentum", "url": "#trendingFeuds", "keywords": "trending viral score hot feuds"},
        {"type": "command", "icon": "🏛️", "title": "Hall of Feuds", "subtitle": "Open all-time Rivalry records", "url": "#hallOfFeuds", "keywords": "hall records rivalry feuds"},
        {"type": "command", "icon": "🛰️", "title": "Mission Control", "subtitle": "Open your private next moves", "url": "#missionControl", "keywords": "mission private next move"},
        {"type": "command", "icon": "⚔️", "title": "Alpha Clash", "subtitle": "Challenge another Hunter", "url": "#clashCard", "keywords": "battle clash challenge fight"},
        {"type": "command", "icon": "🎯", "title": "Live Arenas", "subtitle": "Browse live proof opportunities", "url": "#arenaSection", "keywords": "arenas quests proof bounty"},
        {"type": "command", "icon": "👾", "title": "Hunter Passport", "subtitle": "Open identity and progression", "url": "#passportCard", "keywords": "passport profile identity hunter"},
        {"type": "command", "icon": "🔥", "title": "Network Heat", "subtitle": "Scan hot Hunters and matchups", "url": "#networkHeatmap", "keywords": "heat network hot hunters rivalry"},
    ]

    results = []
    for item in commands:
        hay = (item["title"] + " " + item["subtitle"] + " " + item["keywords"]).lower()
        if not q or q_lower in hay:
            results.append({k: v for k, v in item.items() if k != "keywords"})

    if q:
        like = "%" + q + "%"
        conn = db()
        hunters = conn.execute(
            """SELECT username, xp FROM users WHERE username LIKE ? COLLATE NOCASE ORDER BY xp DESC, username ASC LIMIT ?""",
            (like, limit)
        ).fetchall()
        for row in hunters:
            username = str(row["username"] or "")
            results.append({
                "type": "hunter", "icon": "👾", "title": username,
                "subtitle": f'{int(row["xp"] or 0)} XP · public Hunter profile',
                "url": "/hunter/" + urllib.parse.quote(username, safe="")
            })

        arenas = conn.execute(
            """SELECT id, title, category, status FROM arenas
               WHERE title LIKE ? COLLATE NOCASE OR description LIKE ? COLLATE NOCASE OR category LIKE ? COLLATE NOCASE
               ORDER BY CASE WHEN status='live' THEN 0 ELSE 1 END, id DESC LIMIT ?""",
            (like, like, like, limit)
        ).fetchall()
        for row in arenas:
            results.append({
                "type": "arena", "icon": "🎯", "title": str(row["title"] or f'Arena #{row["id"]}'),
                "subtitle": f'{str(row["category"] or "Alpha")} · {str(row["status"] or "live").upper()} · Arena #{int(row["id"])}',
                "url": "#arenaSection"
            })

        battle_params = [like, like]
        battle_sql = """SELECT id, challenger, opponent, winner, created_at FROM creature_battles
                        WHERE challenger LIKE ? COLLATE NOCASE OR opponent LIKE ? COLLATE NOCASE"""
        if q.isdigit():
            battle_sql += " OR id = ?"
            battle_params.append(int(q))
        battle_sql += " ORDER BY id DESC LIMIT ?"
        battle_params.append(limit)
        battles = conn.execute(battle_sql, tuple(battle_params)).fetchall()
        seen_pairs = set()
        for row in battles:
            challenger = str(row["challenger"] or "")
            opponent = str(row["opponent"] or "")
            results.append({
                "type": "clash", "icon": "💥", "title": f'Clash #{int(row["id"])} · {challenger} vs {opponent}',
                "subtitle": f'Winner: {str(row["winner"] or "—")}',
                "url": f'/clash/{int(row["id"])}'
            })
            if challenger and opponent and challenger != opponent:
                pair = tuple(sorted((challenger, opponent), key=lambda x: x.lower()))
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    results.append({
                        "type": "rivalry", "icon": "⚔️", "title": f'{pair[0]} vs {pair[1]}',
                        "subtitle": "Open Rivalry Chronicle",
                        "url": "/rivalry/" + urllib.parse.quote(pair[0], safe="") + "/" + urllib.parse.quote(pair[1], safe="")
                    })

        moments = conn.execute(
            """SELECT id, battle_id, label, winner, loser, intensity FROM feud_moments
               WHERE label LIKE ? COLLATE NOCASE OR detail LIKE ? COLLATE NOCASE OR winner LIKE ? COLLATE NOCASE OR loser LIKE ? COLLATE NOCASE
               ORDER BY id DESC LIMIT ?""",
            (like, like, like, like, limit)
        ).fetchall()
        for row in moments:
            results.append({
                "type": "moment", "icon": "🎬", "title": str(row["label"] or f'Moment #{row["id"]}'),
                "subtitle": f'{str(row["winner"] or "Hunter")} vs {str(row["loser"] or "Rival")} · Heat {int(row["intensity"] or 1)}/5',
                "url": f'/feud-moment/{int(row["id"])}'
            })
        conn.close()

    type_order = {"command": 0, "hunter": 1, "rivalry": 2, "clash": 3, "moment": 4, "arena": 5}
    results.sort(key=lambda item: (type_order.get(item.get("type"), 9), str(item.get("title") or "").lower()))
    return jsonify({
        "success": True,
        "query": q,
        "results": results[:28],
        "count": min(len(results), 28),
        "engine": "global-search-v13.3"
    })


@app.route("/favicon.svg")
def favicon_svg():
    svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="16" fill="#08080d"/><circle cx="32" cy="32" r="21" fill="#baff5a"/><text x="32" y="39" text-anchor="middle" font-family="Arial,sans-serif" font-size="21" font-weight="900" fill="#08080d">BL3</text></svg>"""
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control":"public, max-age=86400"})


@app.route("/manifest.webmanifest")
def web_manifest():
    return jsonify({
        "name": "BL3 // Human Alpha Network", "short_name": "BL3",
        "description": "Hunter identity, rivalries, Clash moments and discovery.",
        "start_url": "/", "scope": "/", "display": "standalone",
        "background_color": "#040406", "theme_color": "#050507",
        "icons": [{"src":"/favicon.svg","sizes":"any","type":"image/svg+xml","purpose":"any maskable"}]
    })


@app.route("/robots.txt")
def robots_txt():
    return Response(f"User-agent: *\nAllow: /\nSitemap: {_public_origin()}/sitemap.xml\n", mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap_xml():
    base = html.escape(_public_origin(), quote=True)
    body = "".join(f"<url><loc>{base}{path}</loc></url>" for path in ("/", "/status", "/transparency"))
    return Response(f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{body}</urlset>', mimetype="application/xml")


@app.route("/healthz")
def healthz():
    ok, db_status = True, "ok"
    try:
        conn = db(); conn.execute("SELECT 1").fetchone(); conn.close()
    except Exception:
        ok, db_status = False, "error"
    return jsonify({"ok":ok,"service":"bl3","version":"13.3","release":"GLOBAL SEARCH","database":db_status,"utc":datetime.utcnow().isoformat()+"Z"}), (200 if ok else 503)


@app.route("/api/meta")
def api_meta():
    return jsonify({
        "success": True, "name": "BL3 // Human Alpha Network", "version": "13.3", "release": "GLOBAL SEARCH",
        "public_endpoints": ["/healthz","/api/global-search","/api/discovery","/api/trending-feuds","/api/feud-events","/api/feud-moments","/api/leaderboard"],
        "principles": ["real completed Clash data","no paid Discovery boost","privacy-light viral attribution"]
    })


@app.route("/status")
def status_page():
    conn = db()
    users = int(conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"] or 0)
    battles = int(conn.execute("SELECT COUNT(*) AS n FROM creature_battles WHERE winner = challenger OR winner = opponent").fetchone()["n"] or 0)
    moments = int(conn.execute("SELECT COUNT(*) AS n FROM feud_moments").fetchone()["n"] or 0)
    conn.close()
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#050507"><title>BL3 System Status</title><style>*{{box-sizing:border-box}}body{{margin:0;background:#050507;color:#fff;font-family:Inter,system-ui,Arial;padding:24px}}.wrap{{max-width:900px;margin:auto}}.brand{{font-weight:950;font-size:25px}}.brand span{{color:#baff5a}}.card{{margin-top:24px;border:1px solid #2b2b36;border-radius:26px;padding:26px;background:linear-gradient(145deg,#111119,#0a0a0f)}}.ok{{color:#baff5a;font-weight:950}}h1{{font-size:clamp(42px,8vw,78px);margin:12px 0}}.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:22px}}.stat{{border:1px solid #2b2b36;border-radius:16px;padding:16px}}.stat b{{display:block;font-size:28px}}.stat span,.muted{{color:#9091a1;font-size:11px}}a{{color:#baff5a}}@media(max-width:620px){{.grid{{grid-template-columns:1fr}}}}</style></head><body><div class="wrap"><div class="brand">BL3<span>●</span> GLOBAL SEARCH</div><div class="card"><div class="ok">● OPERATIONAL</div><h1>System Status</h1><div class="muted">V13.3 · database reachable · live network endpoints available</div><div class="grid"><div class="stat"><b>{users}</b><span>HUNTERS</span></div><div class="stat"><b>{battles}</b><span>VALID CLASHES</span></div><div class="stat"><b>{moments}</b><span>FEUD MOMENTS</span></div></div><p class="muted">Health probe: <a href="/healthz">/healthz</a> · API metadata: <a href="/api/meta">/api/meta</a></p><p><a href="/">← Back to BL3</a></p></div></div></body></html>"""


@app.route("/transparency")
def transparency_page():
    return """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#050507"><title>BL3 Transparency</title><style>*{box-sizing:border-box}body{margin:0;background:#050507;color:#fff;font-family:Inter,system-ui,Arial;padding:24px}.wrap{max-width:850px;margin:auto}.brand{font-weight:950;font-size:25px}.brand span,a{color:#baff5a}.card{margin-top:24px;border:1px solid #2b2b36;border-radius:26px;padding:26px;background:#101017}h1{font-size:clamp(42px,8vw,72px);margin:12px 0}.item{border-top:1px solid #292933;padding:18px 0}.item:first-of-type{border-top:0}.item b{display:block;margin-bottom:6px}.item span{color:#9a9bab;line-height:1.6}</style></head><body><div class="wrap"><div class="brand">BL3<span>●</span> TRANSPARENCY</div><div class="card"><h1>How BL3 ranks & tracks.</h1><div class="item"><b>Discovery</b><span>Discovery and Trending are driven by in-product activity signals. No wallet-value or paid placement is used as a ranking boost.</span></div><div class="item"><b>Rivalries</b><span>Feud records use valid completed direct Clashes where the winner is one of the two participants.</span></div><div class="item"><b>Viral attribution</b><span>Moment CTA attribution tracks the action, source Moment and target Hunter; it is designed not to require IP or wallet-value tracking.</span></div><div class="item"><b>Status</b><span>Operational health is exposed at /healthz so deployments can be monitored without scraping the UI.</span></div><p><a href="/">← Back to BL3</a></p></div></div></body></html>"""


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return jsonify({"success":False,"error":"not_found","message":"BL3 endpoint not found"}), 404
    return """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>404 // BL3</title><style>body{margin:0;background:#050507;color:white;font-family:system-ui;min-height:100vh;display:grid;place-items:center;padding:24px}.c{text-align:center}.n{font-size:100px;font-weight:950;color:#baff5a;line-height:1}p{color:#999aaa}a{display:inline-block;color:#050507;background:#baff5a;padding:13px 17px;border-radius:13px;text-decoration:none;font-weight:900}</style></head><body><div class="c"><div class="n">404</div><h1>Signal lost.</h1><p>This BL3 route does not exist or has moved.</p><a href="/">RETURN TO NETWORK</a></div></body></html>""", 404


@app.errorhandler(500)
def server_error(error):
    if request.path.startswith("/api/"):
        return jsonify({"success":False,"error":"server_error","message":"BL3 hit an internal error"}), 500
    return """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>500 // BL3</title><style>body{margin:0;background:#050507;color:white;font-family:system-ui;min-height:100vh;display:grid;place-items:center;padding:24px}.c{text-align:center}.n{font-size:100px;font-weight:950;color:#ff7a9d;line-height:1}p{color:#999aaa}a{color:#baff5a}</style></head><body><div class="c"><div class="n">500</div><h1>Core signal interrupted.</h1><p>The network hit an internal error. Try again, or check system status.</p><p><a href="/status">SYSTEM STATUS</a> · <a href="/">NETWORK HOME</a></p></div></body></html>""", 500


@app.route("/api/leaderboard")
def leaderboard_api():

    conn = db()

    rows = conn.execute(
        """
        SELECT username, xp
        FROM users
        ORDER BY xp DESC
        LIMIT 50
        """
    ).fetchall()

    conn.close()

    return jsonify([
        {
            "username": row["username"],
            "xp": row["xp"]
        }
        for row in rows
    ])


if __name__ == "__main__":

    init_db()

    print("")
    print("📡 BL3 ARENA V13.2 // QUALITY LAYER")
    print("💾 SQLite enabled")
    print("🎯 Quest system enabled")
    print("🏆 Leaderboard enabled")
    print("👛 Wallet profile enabled")
    print("")
    print("🚀 http://127.0.0.1:5000")
    print("")

    port = int(os.environ.get("PORT", "5000"))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
