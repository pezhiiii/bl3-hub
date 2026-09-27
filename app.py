from flask import Flask, jsonify, request, session
import sqlite3
import os
import secrets
import time
from datetime import datetime
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
<div class="badge">V5.2 • Verified Referrals</div>

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
        "📢 Share composer opened. XP verification comes next."
    );
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
        document.getElementById("wallet").value = data.wallet || "";
    }

    if (data.xp !== undefined) {

        document.getElementById(
            "xp"
        ).innerText =
            data.xp;
    }

    if (data.streak !== undefined) {

        document.getElementById(
            "streak"
        ).innerText =
            data.streak;
    }

    if (data.rank !== undefined) {

        document.getElementById(
            "rank"
        ).innerText =
            data.rank;
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
        "rank": rank
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

        conn.execute(
            """
            UPDATE users
            SET xp = xp + ?,
                streak = streak + 1
            WHERE username = ?
            """,
            (reward, username)
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
    print("👑 BL3 HUB V5.2")
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
