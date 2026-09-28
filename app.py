from flask import Flask, jsonify, request, session
import sqlite3
import os
import secrets
import time
import json
import urllib.parse
import urllib.request
import urllib.error
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

    conn.commit()
    conn.close()


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

    return """
<!DOCTYPE html>
<html>
<head>

<meta name="viewport" content="width=device-width, initial-scale=1">

<title>BL3 Hub</title>

<style>

body {
    background: #0d0d12;
    color: white;
    font-family: Arial;
    margin: 0;
}

.container {
    max-width: 500px;
    margin: auto;
    padding: 20px;
}

.header {
    text-align: center;
    padding: 20px;
}

.logo {
    font-size: 55px;
}

.title {
    font-size: 32px;
    font-weight: bold;
}

.subtitle {
    color: #999;
}

.badge {
    display: inline-block;
    margin-top: 10px;
    padding: 6px 10px;
    border: 1px solid #3a3a4b;
    border-radius: 999px;
    font-size: 12px;
    color: #bbb;
}

.card {
    background: #191922;
    padding: 20px;
    border-radius: 20px;
    margin-top: 15px;
}

.stats {
    display: flex;
    justify-content: space-around;
    text-align: center;
}

.number {
    font-size: 25px;
    font-weight: bold;
    margin: 5px;
}

.quest {
    background: #24242f;
    padding: 15px;
    border-radius: 15px;
    margin-top: 10px;
}

button {
    width: 100%;
    padding: 14px;
    margin-top: 8px;
    border: none;
    border-radius: 12px;
    font-size: 16px;
    font-weight: bold;
}

input {
    width: 100%;
    box-sizing: border-box;
    padding: 14px;
    border-radius: 12px;
    border: none;
    margin-top: 8px;
    font-size: 16px;
}

.rank {
    display: flex;
    justify-content: space-between;
    background: #24242f;
    padding: 12px;
    border-radius: 10px;
    margin-top: 8px;
}

.message {
    text-align: center;
    margin: 20px;
}

</style>

</head>

<body>

<div class="container">

<div class="header">

<div class="logo">👑</div>

<div class="title">BL3 HUB</div>

<div class="subtitle">
Build. Meme. Repeat.
</div>
<div class="badge">V5.3 • Verified Farcaster Shares</div>

</div>


<div class="card">

<h3>👤 Profile</h3>

<input
id="username"
value="demo_user"
placeholder="Username"
>

<button onclick="loadUser()">
Load Profile
</button>

</div>
<div class="card">

<div class="stats">

<div>
⭐
<div class="number" id="xp">0</div>
XP
</div>

<div>
🔥
<div class="number" id="streak">0</div>
Streak

<div id="streakReward"
     style="font-size:11px;color:#999;margin-top:5px;">
    🔥 Next: 3-Day Flame
</div>

<button id="streakClaimButton"
        onclick="claimStreakReward()"
        style="display:none;font-size:12px;padding:8px;margin-top:6px;">
    🎁 Claim Reward
</button>


</div>

<div>
🏆
<div class="number" id="rank">-</div>
Rank
</div>

</div>
</div>

<div class="card">

<h2>🎯 Quests</h2>

<div class="quest">

<b>🔥 Daily Check-in</b>

<p>Reward: +10 XP</p>

<button onclick="quest('checkin')">
Complete
</button>

</div>


<div class="quest">

<b>📢 Share BL3</b>

<p>Reward: +25 XP</p>

<button onclick="share()">
Share
</button>

<input id="castUrl" placeholder="Paste your Farcaster cast URL after sharing">

<button onclick="verifyShare()">
✅ Verify Share +25 XP
</button>

</div>


<div class="quest">

<b>👥 Invite Friend</b>

<p>Reward: +50 XP</p>

<button onclick="invite()">
Invite
</button>

</div>

</div>


<div class="card">

<h2>🏆 Leaderboard</h2>

<div id="leaderboard">
Loading...
</div>

</div>


<div class="card">

<h2>👛 Wallet</h2>

<input
id="wallet"
placeholder="Wallet address"
readonly
>

<button onclick="connectWallet()">
🔗 Connect Wallet
</button>

<button onclick="signInWallet()">
🔐 Sign In with Wallet
</button>

<div id="authStatus" style="margin-top:10px;color:#aaa;">
Not signed in
</div>



</div>


<div class="message" id="message"></div>

</div>


<script>

let username = "demo_user";


function currentUser() {

    username =
        document.getElementById(
            "username"
        ).value.trim();

    if (!username) {
        username = "demo_user";
    }

    return username;
}


async function loadUser() {

    currentUser();

    const response =
        await fetch(
            "/api/user/" +
            encodeURIComponent(username)
        );

    const data =
        await response.json();

    update(data);

    loadLeaderboard();

    await claimReferral();
}


async function quest(name) {

    currentUser();

    const response =
        await fetch(
            "/api/quest",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                    "application/json"
                },

                body: JSON.stringify({
                    user: username,
                    quest: name
                })
            }
        );

    const data =
        await response.json();

    update(data);

    show(data.message);

    loadLeaderboard();
}


function share() {

    const text = encodeURIComponent(
        "BL3 — Build. Meme. Repeat. 👑"
    );

    window.open(
        "https://warpcast.com/~/compose?text=" + text,
        "_blank"
    );

    show(
        "📢 Post the cast, then paste its URL below and verify it."
    );
}

async function verifyShare() {
    currentUser();
    const castUrl = document.getElementById("castUrl").value.trim();

    if (!castUrl) {
        show("❌ Paste your Farcaster cast URL first.");
        return;
    }

    const response = await fetch("/api/share/verify", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({user: username, cast_url: castUrl})
    });

    const data = await response.json();
    if (data.xp !== undefined) update(data);
    show(data.message || "Share verification finished.");
    if (data.success) loadLeaderboard();
}

function invite() {

    const user = currentUser();
    const referralLink =
        window.location.origin +
        "/?ref=" +
        encodeURIComponent(user);

    if (navigator.clipboard) {
        navigator.clipboard.writeText(referralLink);
        show("👥 Referral link copied: " + referralLink);
    } else {
        show("👥 Your referral link: " + referralLink);
    }
}


async function claimReferral() {

    const params = new URLSearchParams(window.location.search);
    const inviter = (params.get("ref") || "").trim();
    const invited = currentUser();

    if (!inviter) {
        return;
    }

    if (!invited || invited === "demo_user") {
        show("👥 Referral detected. Enter your username and press Load Profile.");
        return;
    }

    if (inviter === invited) {
        show("❌ You cannot use your own referral link.");
        return;
    }

    const response = await fetch(
        "/api/referral",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                inviter: inviter,
                invited: invited
            })
        }
    );

    const data = await response.json();
    show(data.message);

    if (data.success) {
        loadLeaderboard();
        history.replaceState({}, "", window.location.pathname);
    }
}



async function connectWallet() {

    if (!window.ethereum) {
        show("❌ No browser wallet detected. Install a compatible wallet extension.");
        return;
    }

    try {
        const accounts = await window.ethereum.request({
            method: "eth_requestAccounts"
        });

        if (!accounts || !accounts.length) {
            show("❌ No wallet account returned.");
            return;
        }

        const wallet = accounts[0];
        document.getElementById("wallet").value = wallet;

        show("👛 Wallet connected. Now press Sign In with Wallet.");

    } catch (error) {
        show("❌ Wallet connection cancelled or failed.");
    }
}


async function signInWallet() {

    if (!window.ethereum) {
        show("❌ No browser wallet detected.");
        return;
    }

    try {
        currentUser();

        if (!username || username === "demo_user") {
            show("❌ Enter your BL3 username first, then press Load Profile.");
            return;
        }

        const accounts = await window.ethereum.request({
            method: "eth_requestAccounts"
        });

        if (!accounts || !accounts.length) {
            show("❌ No wallet account returned.");
            return;
        }

        const wallet = accounts[0];
        document.getElementById("wallet").value = wallet;

        const nonceResponse = await fetch(
            "/api/auth/nonce?wallet=" +
            encodeURIComponent(wallet) +
            "&user=" +
            encodeURIComponent(username)
        );

        const nonceData = await nonceResponse.json();

        if (!nonceData.success) {
            show(nonceData.message || "❌ Could not create sign-in challenge.");
            return;
        }

        const message = nonceData.message;

        const signature = await window.ethereum.request({
            method: "personal_sign",
            params: [message, wallet]
        });

        const verifyResponse = await fetch(
            "/api/auth/verify",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    wallet: wallet,
                    username: username,
                    message: message,
                    signature: signature
                })
            }
        );

        const data = await verifyResponse.json();

        if (data.success) {
            document.getElementById("authStatus").innerText =
                "Verified: " + wallet.slice(0, 6) + "…" + wallet.slice(-4);

            document.getElementById("wallet").value = wallet;
            await loadUser();
        }

        show(data.message);

    } catch (error) {
        show("❌ Wallet sign-in cancelled or failed.");
    }
}


async function loadLeaderboard() {

    const response =
        await fetch(
            "/api/leaderboard"
        );

    const data =
        await response.json();

    let html = "";

    data.forEach(
        function(user, index) {

            html +=
                '<div class="rank">' +
                '<span>#' +
                (index + 1) +
                ' ' +
                user.username +
                '</span>' +
                '<b>' +
                user.xp +
                ' XP</b>' +
                '</div>';

        }
    );

    document.getElementById(
        "leaderboard"
    ).innerHTML =
        html || "No users yet.";
}


   function update(data) {

    if (data.wallet !== undefined) {
        document.getElementById("wallet").value =
            data.wallet || "";
    }

    if (data.xp !== undefined) {
        document.getElementById("xp").innerText =
            data.xp;
    }

    if (data.streak !== undefined) {

        const streak = Number(data.streak);

        const claimed =
            Array.isArray(data.claimed_milestones)
                ? data.claimed_milestones.map(Number)
                : [];

        document.getElementById("streak").innerText =
            streak;

        const reward =
            document.getElementById("streakReward");

        const claimButton =
            document.getElementById("streakClaimButton");

        claimButton.style.display = "none";

        if (streak >= 3 && !claimed.includes(3)) {

            reward.innerText =
                "🔥 3-Day Flame — UNLOCKED";

            claimButton.style.display = "block";

        } else if (streak >= 7 && !claimed.includes(7)) {

            reward.innerText =
                "🏆 7-Day House — UNLOCKED";

            claimButton.style.display = "block";

        } else if (streak >= 30 && !claimed.includes(30)) {

            reward.innerText =
                "🌕 30-Day Moon — UNLOCKED";

            claimButton.style.display = "block";

        } else if (streak < 3) {

            const daysLeft = 3 - streak;

            reward.innerText =
                "🔥 Next: 3-Day Flame • " +
                daysLeft +
                (daysLeft === 1
                    ? " day left"
                    : " days left");

        } else if (streak < 7) {

            const daysLeft = 7 - streak;

            reward.innerText =
                "🏆 Next: 7-Day House • " +
                daysLeft +
                (daysLeft === 1
                    ? " day left"
                    : " days left");

        } else if (streak < 30) {

            const daysLeft = 30 - streak;

            reward.innerText =
                "🌕 Next: 30-Day Moon • " +
                daysLeft +
                (daysLeft === 1
                    ? " day left"
                    : " days left");

        } else {

            reward.innerText =
                "👑 All streak rewards claimed!";
        }
    }

    if (data.rank !== undefined) {
        document.getElementById("rank").innerText =
            data.rank;
    }
}


async function claimStreakReward() {

    currentUser();

    const streak = Number(
        document.getElementById("streak").innerText
    );

    const profileResponse = await fetch(
        "/api/user/" + encodeURIComponent(username)
    );

    const profileData = await profileResponse.json();

    const claimed = Array.isArray(profileData.claimed_milestones)
        ? profileData.claimed_milestones.map(Number)
        : [];

    let milestone = 0;

    if (streak >= 3 && !claimed.includes(3)) {
        milestone = 3;
    } else if (streak >= 7 && !claimed.includes(7)) {
        milestone = 7;
    } else if (streak >= 30 && !claimed.includes(30)) {
        milestone = 30;
    }

    if (!milestone) {
        show("🔒 No streak reward available yet.");
        return;
    }

    const response = await fetch(
        "/api/streak/claim",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                user: username,
                milestone: milestone
            })
        }
    );

    const data = await response.json();

    if (data.xp !== undefined) {
        update(data);
    }

    show(data.message);

    if (data.success) {
    await loadUser();
}


}


function show(text) {

    document.getElementById(
        "message"
    ).innerText =
        text;
}


loadUser();

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
    print("👑 BL3 HUB V5.3")
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
