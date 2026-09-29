from flask import Flask, jsonify, request, session, Response
import sqlite3
import os
import secrets
import time
import json
import urllib.parse
import urllib.request
import urllib.error
import html
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
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#050507">
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
</style>
</head>
<body>
<div class="shell">
  <nav class="nav">
    <div class="brand">BL3<span>●</span></div>
    <div class="pill">THE HUMAN ALPHA NETWORK</div>
    <div class="nav-right"><div class="pill" id="signalBadge">SIGNALS 0</div><div class="pill" id="inboxBadge">INBOX 0</div><div class="pill" id="navAuth">WALLET OFFLINE</div></div>
  </nav>

  <section class="hero">
    <div class="eyebrow">PROOF &gt; NOISE</div>
    <h1>HUNT ALPHA.<br><span class="grad">EARN REPUTATION.</span></h1>
    <div class="lead">A live market for crypto research, product feedback, memes and human intelligence. Projects post funded opportunities. Hunters submit proof. Reputation compounds.</div>
    <div class="ticker">
      <div class="pill"><b id="liveArenas">0</b> LIVE ARENAS</div>
      <div class="pill"><b id="totalBounty">0</b> USDC LISTED</div>
      <div class="pill"><b id="totalHunters">0</b> HUNTERS</div>
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

  <div class="grid">
    <main id="arenaSection">
      <div class="section-title"><div><div class="eyebrow">DISCOVER</div><h2>Live Arenas</h2></div><button class="btn tab" onclick="loadArenas()">↻ Refresh</button></div>
      <div id="arenas"><div class="card">Scanning the network…</div></div>
    </main>

    <aside>
      <div class="card creature-card" id="passportCard">
        <div class="eyebrow">HUNTER ID // LIVING PASSPORT</div>
        <h2 style="margin-top:8px">Your Passport</h2>
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

  <div class="footer">BL3 // BUILD. MEME. REPEAT. // V8.0 HUNTER TITLES</div>
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
function jumpToPassport(){document.getElementById("passportCard")?.scrollIntoView({behavior:"smooth",block:"center"});document.getElementById("username")?.focus()}
function jumpToWallet(){document.getElementById("walletCard")?.scrollIntoView({behavior:"smooth",block:"center"})}
function jumpToAction(){document.getElementById("arenaSection")?.scrollIntoView({behavior:"smooth",block:"start"})}
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
 await loadLeaderboard(); await claimReferral(); await authStatus(); await loadArenas(); await loadSeason(); await loadDailyMissions(); await loadActivity(); await loadRivalFeed(); await loadDiscovery(); await loadInbox(); await loadSignals(); await loadOnboarding();
}
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
 const el=document.getElementById("battleOpponent");el.value=currentCrown;el.scrollIntoView({behavior:"smooth",block:"center"});show("👑 Crown target locked: "+currentCrown);
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
 show(won?"Your creature took the crown 👑":"Chaos chose your opponent this round.");
 await loadSeason();
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
 show("⚔️ Challenge detected: "+target+" is waiting in the arena.");
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
 const mine=d.challenger,them=d.opponent;
 const el=document.getElementById("battleResult");
 el.classList.remove("hidden");
 el.innerHTML='<div class="small">CHALLENGE ACCEPTED // 👑 '+escapeHtml(d.winner)+' WON</div><div class="battle-vs">'+escapeHtml(mine.avatar)+' '+escapeHtml(mine.username)+' <span class="meta">VS</span> '+escapeHtml(them.opponent)+' '+escapeHtml(them.avatar)+'</div><div class="battle-log">POWER '+mine.power+' — '+them.power+'<br>'+escapeHtml(d.commentary)+'</div><a href="/clash/'+d.battle_id+'" target="_blank" style="display:block;text-decoration:none;color:inherit;margin-top:10px"><div class="proof">🃏 OPEN BATTLE CARD #'+d.battle_id+' ↗</div></a>';
 await loadInbox(); await loadSeason(); await loadActivity(); await loadUser();
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


def _hunter_title(username):
    """Choose one public title from the Hunter's strongest unlocked trophy."""
    data = _hunter_trophies(username)
    if data is None:
        return None

    trophies = data.get("trophies", [])
    by_key = {t["key"]: t for t in trophies}

    # Curated title priority: identity/status first, then combat/social progression.
    priority = [
        ("ascended", "CROWN ENTITY", "👑", "LEGENDARY"),
        ("crown_breaker", "CROWN BREAKER", "💥", "GOLD"),
        ("crown_defender", "CROWN DEFENDER", "👑", "GOLD"),
        ("proof_paid", "PROOF HUNTER", "💎", "GOLD"),
        ("alpha_hunter", "ALPHA HUNTER", "😈", "GOLD"),
        ("seven_day_flame", "FLAMEKEEPER", "🔥", "GOLD"),
        ("nemesis_found", "NEMESIS", "🔥", "SILVER"),
        ("arena_winner", "ARENA WINNER", "🎯", "SILVER"),
        ("signal_magnet", "SIGNAL MAGNET", "📡", "SILVER"),
        ("network_builder", "NETWORK BUILDER", "👥", "SILVER"),
        ("reputation_500", "REPUTATION ELITE", "🌠", "GOLD"),
        ("reputation_100", "PROVEN HUNTER", "⚡", "SILVER"),
        ("battle_hardened", "BATTLE HARDENED", "🛡️", "SILVER"),
        ("clash_victor", "CLASH VICTOR", "🩸", "BRONZE"),
        ("verified_hunter", "VERIFIED HUNTER", "🔐", "BRONZE"),
        ("first_clash", "NEW BLOOD", "⚔️", "BRONZE"),
    ]

    for key, title, icon, tier in priority:
        if key in by_key:
            return {
                "key": key,
                "title": title,
                "icon": icon,
                "tier": tier,
                "source": by_key[key]["title"]
            }

    return {
        "key": "hunter",
        "title": "HUNTER",
        "icon": "👾",
        "tier": "UNRANKED",
        "source": None
    }


@app.route("/api/title/<username>")
def hunter_title_api(username):
    title = _hunter_title(username)
    if title is None:
        return jsonify({"success": False, "message": "Hunter not found"}), 404
    return jsonify({"success": True, "username": username, **title})


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
    season_rank = f"#{d['season']['rank']}" if d['season']['rank'] else "—"
    crown = "CURRENT CROWN" if d['season']['is_crown'] else "HUNTER"
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
      <defs>
        <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#050507"/><stop offset=".55" stop-color="#141221"/><stop offset="1" stop-color="#09090e"/></linearGradient>
        <linearGradient id="accent" x1="0" y1="0" x2="1" y2="0"><stop stop-color="#b8ff5a"/><stop offset="1" stop-color="#9d7bff"/></linearGradient>
      </defs>
      <rect width="1200" height="630" rx="38" fill="url(#bg)"/>
      <rect x="34" y="34" width="1132" height="562" rx="30" fill="none" stroke="#30303a" stroke-width="2"/>
      <text x="70" y="92" fill="#b8ff5a" font-family="Arial,sans-serif" font-size="26" font-weight="900">BL3 // PUBLIC HUNTER PROFILE</text>
      <text x="70" y="142" fill="#777785" font-family="Arial,sans-serif" font-size="18" letter-spacing="3">THE HUMAN ALPHA NETWORK // {esc(crown)}</text>
      <text x="72" y="258" fill="#ffffff" font-family="Arial,sans-serif" font-size="70" font-weight="950">{esc(d['username'])}</text>
      <text x="72" y="304" fill="#b8ff5a" font-family="Arial,sans-serif" font-size="24" font-weight="900" letter-spacing="2">{esc(hunter_title['icon'])} {esc(hunter_title['title'])}</text>
      <text x="72" y="346" fill="url(#accent)" font-family="Arial,sans-serif" font-size="28" font-weight="900">{esc(d['creature']['avatar'])} {esc(d['creature']['name'])} // LVL {d['level']}</text>
      <text x="72" y="386" fill="#a7a7b6" font-family="Arial,sans-serif" font-size="22">{d['reputation']} REP   •   {d['xp']} XP   •   {d['wins']} WINS   •   {d['network']} NETWORK</text>
      <rect x="72" y="433" width="1056" height="1" fill="#30303a"/>
      <text x="72" y="486" fill="#ffffff" font-family="Arial,sans-serif" font-size="21" font-weight="800">SEASON {esc(d['season']['key'])}</text>
      <text x="72" y="528" fill="#9d7bff" font-family="Arial,sans-serif" font-size="25" font-weight="900">RANK {season_rank}   •   {d['season']['wins']}W / {d['season']['losses']}L   •   {d['season']['win_streak']} WIN STREAK</text>
      <text x="72" y="570" fill="#666677" font-family="Arial,sans-serif" font-size="17">HUNT ALPHA. EARN REPUTATION.</text>
      <text x="1128" y="570" fill="#b8ff5a" font-family="Arial,sans-serif" font-size="17" font-weight="900" text-anchor="end">CHALLENGE THIS HUNTER →</text>
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
           WHERE (challenger = ? AND opponent = ?)
              OR (challenger = ? AND opponent = ?)
           ORDER BY id DESC LIMIT ?""",
        (a, b, b, a, max(1, min(int(limit or 6), 20)))
    ).fetchall()

    totals = conn.execute(
        """SELECT
             COUNT(*) AS total,
             SUM(CASE WHEN winner = ? THEN 1 ELSE 0 END) AS a_wins,
             SUM(CASE WHEN winner = ? THEN 1 ELSE 0 END) AS b_wins
           FROM creature_battles
           WHERE (challenger = ? AND opponent = ?)
              OR (challenger = ? AND opponent = ?)""",
        (a, b, a, b, b, a)
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
           WHERE (challenger = ? AND opponent = ?)
              OR (challenger = ? AND opponent = ?)
           ORDER BY id ASC""",
        (a, b, b, a)
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
          <stop offset="1" stop-color="#9d7bff"/>
        </linearGradient>
        <filter id="glow"><feGaussianBlur stdDeviation="8" result="c"/><feMerge><feMergeNode in="c"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
      </defs>
      <rect width="1200" height="630" rx="36" fill="url(#bg)"/>
      <rect x="1" y="1" width="1198" height="628" rx="35" fill="none" stroke="#2b2b38" stroke-width="2"/>
      <text x="70" y="74" fill="#b8ff5a" font-family="Arial,sans-serif" font-size="22" font-weight="900" letter-spacing="3">BL3 // RIVALRY CARD</text>
      <text x="1130" y="74" fill="#6d6d7d" font-family="Arial,sans-serif" font-size="18" text-anchor="end">THE HUMAN ALPHA NETWORK</text>

      <text x="235" y="215" fill="#ffffff" font-family="Arial,sans-serif" font-size="54" text-anchor="middle">{esc(a_avatar)}</text>
      <text x="235" y="280" fill="#ffffff" font-family="Arial,sans-serif" font-size="42" font-weight="900" text-anchor="middle">{esc(hunter_a)}</text>
      <text x="235" y="405" fill="#ffffff" font-family="Arial,sans-serif" font-size="120" font-weight="900" text-anchor="middle">{h2h["a_wins"]}</text>

      <text x="600" y="250" fill="url(#hot)" font-family="Arial,sans-serif" font-size="64" font-weight="900" text-anchor="middle" filter="url(#glow)">VS</text>
      <text x="600" y="323" fill="#b8ff5a" font-family="Arial,sans-serif" font-size="26" font-weight="900" text-anchor="middle">{h2h["total"]} CLASHES</text>
      <text x="600" y="362" fill="#9d7bff" font-family="Arial,sans-serif" font-size="22" font-weight="900" text-anchor="middle">{esc(status)}</text>

      <text x="965" y="215" fill="#ffffff" font-family="Arial,sans-serif" font-size="54" text-anchor="middle">{esc(b_avatar)}</text>
      <text x="965" y="280" fill="#ffffff" font-family="Arial,sans-serif" font-size="42" font-weight="900" text-anchor="middle">{esc(hunter_b)}</text>
      <text x="965" y="405" fill="#ffffff" font-family="Arial,sans-serif" font-size="120" font-weight="900" text-anchor="middle">{h2h["b_wins"]}</text>

      <rect x="70" y="482" width="1060" height="1" fill="#2b2b38"/>
      <text x="70" y="522" fill="#a7a7b6" font-family="Arial,sans-serif" font-size="20">LAST WINNER: {esc(last)}</text>
      <text x="1130" y="522" fill="#b8ff5a" font-family="Arial,sans-serif" font-size="20" font-weight="900" text-anchor="end">SETTLE IT IN BL3 →</text>
      <text x="70" y="558" fill="#9d7bff" font-family="Arial,sans-serif" font-size="16" font-weight="900">{esc(badge_line)}</text>
      <text x="70" y="596" fill="#666677" font-family="Arial,sans-serif" font-size="17">HUNT ALPHA. EARN REPUTATION.</text>
      <text x="1130" y="586" fill="#666677" font-family="Arial,sans-serif" font-size="17" text-anchor="end">bl3meme.com</text>
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
    esc = lambda v: html.escape(str(v or ""))
    root = request.url_root.rstrip("/")
    page_url = f"{root}/rivalry/{urllib.parse.quote(hunter_a)}/{urllib.parse.quote(hunter_b)}"
    image_url = page_url + "/card.svg"
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
.section{{margin-top:40px}}.milestones{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:14px}}.badge-card{{display:flex;gap:12px;align-items:flex-start;border:1px solid var(--line);background:linear-gradient(145deg,#111119,#151020);padding:16px;border-radius:18px}}.badge-icon{{font-size:28px;line-height:1}}.badge-card b{{display:block;font-size:13px;letter-spacing:1px;color:var(--hot)}}.badge-card span{{display:block;color:var(--muted);font-size:12px;margin-top:5px;line-height:1.45}}.battle{{display:grid;grid-template-columns:1fr auto;gap:6px 18px;text-decoration:none;color:#fff;border:1px solid var(--line);background:var(--card);padding:16px;border-radius:16px;margin-top:10px}}.battle small{{grid-column:1/-1;color:var(--muted)}}.empty{{color:var(--muted);padding:18px;border:1px dashed var(--line);border-radius:16px}}.footer{{text-align:center;color:#626270;padding:45px 0 20px}}
@media(max-width:680px){{.score{{grid-template-columns:1fr}}.mid{{order:-1}}.milestones{{grid-template-columns:1fr}}h1{{letter-spacing:-2px}}}}
</style></head><body><div class="shell">
<nav class="nav"><div class="brand">BL3<span>●</span></div><a class="back" href="/">← LIVE NETWORK</a></nav>
<section class="hero"><div class="eyebrow">PUBLIC RIVALRY // SHAREABLE RECORD</div>
<h1>{esc(hunter_a)} <span class="vs">VS</span> {esc(hunter_b)}</h1>
<div class="meta">{esc(status)} · Last winner: {esc(h2h["last_winner"] or "—")}</div>
<div class="score"><div class="side"><strong>{h2h["a_wins"]}</strong><span>{esc(hunter_a)}</span></div><div class="mid">{h2h["total"]} CLASHES</div><div class="side"><strong>{h2h["b_wins"]}</strong><span>{esc(hunter_b)}</span></div></div>
<div class="actions"><a class="btn" href="{esc(challenge_url)}">⚔️ CHALLENGE {esc(hunter_b).upper()}</a><a class="btn alt" href="{esc(page_url)}">📣 SHARE RIVALRY</a></div>
</section>
<section class="section"><div class="eyebrow">RIVALRY MILESTONES</div><h2>Badges Earned by the Story</h2><div class="milestones">{badges_html}</div></section>
<section class="section"><div class="eyebrow">RIVALRY HISTORY</div><h2>Recent Clashes</h2>{rows}</section>
<div class="footer">BL3 // BUILD. MEME. REPEAT. // V8.0 HUNTER TITLES</div>
</div></body></html>"""


@app.route("/hunter/<username>")
def hunter_public_page(username):
    d = _hunter_public_data(username)
    if d is None:
        return "Hunter not found", 404
    trophy_data = _hunter_trophies(username) or {"count": 0, "trophies": []}
    hunter_title = _hunter_title(username) or {"title": "HUNTER", "icon": "👾", "tier": "UNRANKED"}
    esc = lambda v: html.escape(str(v or ""))
    root = request.url_root.rstrip("/")
    page_url = f"{root}/hunter/{urllib.parse.quote(username)}"
    image_url = f"{root}/hunter/{urllib.parse.quote(username)}/card.svg"
    challenge_url = f"{root}/?challenge={urllib.parse.quote(username)}&ref={urllib.parse.quote(username)}"
    title = f"{username} // {hunter_title['title']} // BL3"
    desc = f"{hunter_title['icon']} {hunter_title['title']} • {d['reputation']} REP • {d['wins']} wins • {d['creature']['name']} • Level {d['level']} on the BL3 Human Alpha Network."

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

    trophy_cards = "".join(
        f'<div class="trophy trophy-{esc(t["tier"]).lower()}">'
        f'<div class="trophy-icon">{esc(t["icon"])}</div>'
        f'<div class="trophy-copy"><div class="trophy-top"><b>{esc(t["title"])}</b>'
        f'<span>{esc(t["tier"])}</span></div>'
        f'<p>{esc(t["detail"])}</p></div></div>'
        for t in trophy_data["trophies"]
    )
    if not trophy_cards:
        trophy_cards = '<div class="empty">No trophies unlocked yet. Your first Clash or verified wallet can start the shelf.</div>'

    rank_text = f"#{d['season']['rank']}" if d['season']['rank'] else "—"
    crown_badge = '<span class="crown">👑 CURRENT CROWN</span>' if d['season']['is_crown'] else ''
    verified_badge = '<span class="verified">WALLET VERIFIED</span>' if d['wallet_verified'] else '<span class="muted-badge">WALLET UNVERIFIED</span>'

    viewer = session.get("authenticated_username") or ""
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
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 50% -20%,#292047 0,#0b0b10 34%,var(--bg) 70%);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Arial;min-height:100vh}}body:before{{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px);background-size:42px 42px}}.shell{{width:min(1060px,100%);margin:auto;padding:22px}}.nav{{display:flex;align-items:center;justify-content:space-between;padding:10px 0 28px}}.brand{{font-weight:950;font-size:25px}}.brand span{{color:var(--hot)}}.back{{color:#fff;text-decoration:none;border:1px solid var(--line);padding:10px 14px;border-radius:999px;font-weight:800}}.hero{{border:1px solid var(--line);border-radius:30px;padding:34px;background:linear-gradient(145deg,rgba(18,18,25,.94),rgba(11,11,16,.86));box-shadow:0 30px 80px rgba(0,0,0,.35)}}.eyebrow{{color:var(--hot);font-size:11px;letter-spacing:2px;font-weight:950}}.top{{display:grid;grid-template-columns:auto 1fr;gap:24px;align-items:center;margin-top:18px}}.avatar{{width:130px;height:130px;border-radius:32px;border:1px solid #3b3b48;background:radial-gradient(circle at 40% 30%,rgba(184,255,90,.16),rgba(157,123,255,.12),#0c0c11);display:grid;place-items:center;font-size:68px;box-shadow:inset 0 0 40px rgba(157,123,255,.08)}}h1{{font-size:clamp(44px,8vw,86px);line-height:.92;letter-spacing:-4px;margin:0}}.subtitle{{margin-top:12px;color:#b7b7c4;font-weight:800}}.badges{{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}}.verified,.crown,.muted-badge{{font-size:11px;font-weight:950;letter-spacing:1px;border-radius:999px;padding:8px 10px}}.verified{{color:var(--hot);border:1px solid rgba(184,255,90,.3);background:rgba(184,255,90,.06)}}.crown{{color:#ffd75a;border:1px solid rgba(255,215,90,.3);background:rgba(255,215,90,.06)}}.muted-badge{{color:#88899a;border:1px solid var(--line)}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:26px}}.stat{{border:1px solid var(--line);border-radius:18px;padding:16px;background:#0d0d12}}.num{{font-size:26px;font-weight:950}}.label{{font-size:10px;color:var(--muted);letter-spacing:1.4px;margin-top:4px}}.evo{{margin-top:18px}}.bar{{height:10px;background:#20202a;border-radius:99px;overflow:hidden;margin-top:8px}}.bar>i{{display:block;height:100%;width:{d['evolution']['percent']}%;background:linear-gradient(90deg,var(--hot),var(--violet));border-radius:99px}}.season{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:18px}}.social-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:12px}}.social-stat{{border:1px solid var(--line);border-radius:14px;padding:12px;background:rgba(255,255,255,.018);display:flex;align-items:baseline;justify-content:space-between;gap:10px}}.social-stat b{{font-size:19px}}.social-stat span{{font-size:9px;color:var(--muted);letter-spacing:1.2px}}.actions{{display:flex;gap:10px;flex-wrap:wrap;margin-top:22px}}.btn{{flex:1;min-width:220px;text-align:center;text-decoration:none;border-radius:16px;padding:16px;font-weight:950}}.hot{{background:var(--hot);color:#08080b}}.violet{{background:var(--violet);color:#fff}}.social-btn{{border:1px solid var(--line);background:#17171e;color:#fff;cursor:pointer}}.section{{margin-top:24px;border:1px solid var(--line);border-radius:24px;padding:24px;background:rgba(17,17,22,.82)}}.section h2{{margin:5px 0 16px;font-size:30px}}.battle{{display:flex;justify-content:space-between;gap:18px;align-items:center;color:#fff;text-decoration:none;border-top:1px solid var(--line);padding:15px 0}}.battle:first-of-type{{border-top:0}}.meta{{font-size:13px;color:var(--muted);line-height:1.5;margin-top:5px}}.outcome{{font-size:12px;font-weight:950;border-radius:999px;padding:8px 10px}}.win{{color:var(--hot);border:1px solid rgba(184,255,90,.3)}}.loss{{color:#ff7a9d;border:1px solid rgba(255,122,157,.3)}}.empty{{color:var(--muted);padding:12px 0}}.hunter-title{{display:inline-flex;align-items:center;gap:8px;margin-top:10px;padding:8px 12px;border-radius:999px;border:1px solid rgba(184,255,90,.28);background:rgba(184,255,90,.06);color:var(--hot);font-size:12px;font-weight:900;letter-spacing:1.3px}}.hunter-title small{{color:var(--muted);font-size:9px;letter-spacing:1px}}.trophy-room{{border-color:rgba(157,123,255,.28);background:linear-gradient(145deg,rgba(157,123,255,.05),rgba(184,255,90,.025))}}.trophy-grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:14px}}.trophy{{display:flex;gap:13px;align-items:flex-start;border:1px solid var(--line);background:#0d0d12;padding:15px;border-radius:18px}}.trophy-icon{{font-size:30px;line-height:1}}.trophy-copy{{min-width:0;flex:1}}.trophy-top{{display:flex;justify-content:space-between;gap:10px;align-items:center}}.trophy-top b{{font-size:13px;letter-spacing:.8px}}.trophy-top span{{font-size:9px;font-weight:900;letter-spacing:1px;color:var(--muted);border:1px solid var(--line);padding:4px 7px;border-radius:999px}}.trophy p{{margin:7px 0 0;color:var(--muted);font-size:12px;line-height:1.45}}.trophy-gold{{border-color:rgba(255,212,79,.3)}}.trophy-legendary{{border-color:rgba(184,255,90,.42);box-shadow:0 0 30px rgba(184,255,90,.05)}}.rivalry{{border-color:rgba(184,255,90,.24);background:linear-gradient(145deg,rgba(184,255,90,.04),rgba(157,123,255,.04))}}.rivalry h2{{font-size:clamp(28px,5vw,48px);letter-spacing:-2px}}.vs{{color:var(--hot);font-size:.55em;letter-spacing:2px;margin:0 10px}}.h2h-grid{{display:grid;grid-template-columns:1fr auto 1fr;gap:12px;align-items:center;margin-top:18px}}.h2h-score{{border:1px solid var(--line);border-radius:20px;background:#0d0d12;padding:18px;text-align:center}}.h2h-score strong{{display:block;font-size:42px;line-height:1;color:#fff}}.h2h-score span{{display:block;margin-top:7px;font-size:11px;color:var(--muted);font-weight:900;letter-spacing:1.2px}}.h2h-mid{{text-align:center;min-width:130px}}.h2h-mid b{{display:block;color:var(--hot);font-size:13px}}.h2h-mid span{{display:block;color:var(--muted);font-size:10px;margin-top:5px;letter-spacing:1px}}.h2h-last{{text-align:center;margin-top:12px}}.h2h-recent{{margin-top:10px}}.footer{{text-align:center;color:#626270;padding:40px 0 20px;font-size:12px}}@media(max-width:760px){{.top{{grid-template-columns:1fr}}.trophy-grid{{grid-template-columns:1fr}}.h2h-grid{{grid-template-columns:1fr}}.h2h-mid{{order:-1}}.avatar{{width:98px;height:98px;font-size:52px}}.grid,.season{{grid-template-columns:repeat(2,1fr)}}.social-grid{{grid-template-columns:1fr}}h1{{letter-spacing:-2px}}}}
</style></head><body><div class="shell"><nav class="nav"><div class="brand">BL3<span>●</span> HUMAN ALPHA NETWORK</div><a class="back" href="/">← LIVE NETWORK</a></nav>
<section class="hero"><div class="eyebrow">PUBLIC HUNTER ID // SEASON {esc(d['season']['key'])}</div><div class="top"><div class="avatar">{esc(d['creature']['avatar'])}</div><div><h1>{esc(d['username'])}</h1><div class="hunter-title">{esc(hunter_title['icon'])} {esc(hunter_title['title'])} <small>{esc(hunter_title['tier'])}</small></div><div class="subtitle">{esc(d['creature']['name'])} // {esc(d['creature']['stage'])} // LEVEL {d['level']}</div><div class="badges">{verified_badge}{crown_badge}</div></div></div>
<div class="grid"><div class="stat"><div class="num">{d['reputation']}</div><div class="label">REPUTATION</div></div><div class="stat"><div class="num">{d['xp']}</div><div class="label">XP</div></div><div class="stat"><div class="num">{d['wins']}</div><div class="label">TOTAL WINS</div></div><div class="stat"><div class="num">{d['network']}</div><div class="label">NETWORK</div></div></div>
<div class="social-grid"><div class="social-stat"><b id="followersCount">{d['followers']}</b><span>FOLLOWERS</span></div><div class="social-stat"><b>{d['following']}</b><span>FOLLOWING</span></div><div class="social-stat"><b>{d['rivals']}</b><span>RIVALS TRACKED</span></div></div>
<div class="evo"><div style="display:flex;justify-content:space-between;font-size:12px;color:var(--muted)"><b>EVOLUTION</b><span>{d['evolution']['current']} / {d['evolution']['target']} XP</span></div><div class="bar"><i></i></div></div>
<div class="season"><div class="stat"><div class="num">{rank_text}</div><div class="label">CROWN RANK</div></div><div class="stat"><div class="num">{d['season']['wins']}-{d['season']['losses']}</div><div class="label">SEASON W-L</div></div><div class="stat"><div class="num">🔥 {d['season']['win_streak']}</div><div class="label">WIN STREAK</div></div><div class="stat"><div class="num">#{d['xp_rank'] or '—'}</div><div class="label">XP RANK</div></div></div>
<div class="actions"><a class="btn hot" href="{esc(challenge_url)}">⚔️ CHALLENGE {esc(username).upper()}</a><a class="btn violet" href="{esc(page_url)}">🔗 SHARE PROFILE</a><button class="btn social-btn" id="followBtn" onclick="toggleSocial('follow')">👁️ FOLLOW</button><button class="btn social-btn" id="rivalBtn" onclick="toggleSocial('rival')">🎯 MARK RIVAL</button></div></section>
<section class="section trophy-room"><div class="eyebrow">🏆 TROPHY ROOM // PROOF OF HISTORY</div><h2>Achievement Shelf <span class="small">{trophy_data["count"]} UNLOCKED</span></h2><div class="meta">Current public title: <b style="color:var(--hot)">{esc(hunter_title["icon"])} {esc(hunter_title["title"])}</b> — titles upgrade automatically as stronger trophies unlock.</div><div class="trophy-grid">{trophy_cards}</div></section>
{h2h_html}
<section class="section"><div class="eyebrow">RECENT COMBAT</div><h2>Latest Alpha Clashes</h2>{battles_html}</section>
<div class="footer">BL3 // BUILD. MEME. REPEAT. // V8.0 HUNTER TITLES</div></div>
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
    conn.commit()
    conn.close()
    return {
        "success": True, "battle_id": battle_id, "winner": winner, "commentary": commentary,
        "season_key": season_key, "crown_attack": crown_attack, "crown_before": crown_before,
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

    for r in conn.execute("""SELECT id, challenger, opponent, status, created_at
                           FROM challenge_requests ORDER BY id DESC LIMIT 20""").fetchall():
        detail = ("Waiting for response" if r["status"] == "pending" else f"Status: {r['status']}")
        add("challenge", "📨", f"{r['challenger']} challenged {r['opponent']}", detail, r["created_at"], r["id"])

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

    for r in conn.execute("""SELECT id, inviter, invited, date FROM referrals ORDER BY id DESC LIMIT 15""").fetchall():
        add("referral", "👥", f"{r['invited']} joined the network", f"Invited by {r['inviter']}", (r["date"] or "") + "T12:00:00", r["id"])

    for r in conn.execute("""SELECT id, username, date FROM share_claims ORDER BY id DESC LIMIT 15""").fetchall():
        add("share", "📣", f"{r['username']} verified a BL3 cast", "Social proof added to the network", (r["date"] or "") + "T12:00:00", r["id"])

    conn.close()
    events.sort(key=lambda e: (e["created_at"], e["event_id"]), reverse=True)
    return jsonify({"success": True, "events": events[:limit]})


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
    print("🏷️ BL3 ARENA V8.0 // HUNTER TITLES")
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
