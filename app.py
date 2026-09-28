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
.hidden{display:none}.proof{padding:10px;border:1px solid var(--line);border-radius:14px;margin-top:8px}.footer{text-align:center;color:#656675;padding:55px 0 30px}
@media(max-width:820px){.grid{grid-template-columns:1fr}.hero{padding-top:45px}h1{letter-spacing:-3px}.nav .pill:nth-child(2){display:none}.shell{padding:14px}}
</style>
</head>
<body>
<div class="shell">
  <nav class="nav">
    <div class="brand">BL3<span>●</span></div>
    <div class="pill">THE HUMAN ALPHA NETWORK</div>
    <div class="pill" id="navAuth">WALLET OFFLINE</div>
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

  <div class="grid">
    <main>
      <div class="section-title"><div><div class="eyebrow">DISCOVER</div><h2>Live Arenas</h2></div><button class="btn tab" onclick="loadArenas()">↻ Refresh</button></div>
      <div id="arenas"><div class="card">Scanning the network…</div></div>
    </main>

    <aside>
      <div class="card">
        <div class="eyebrow">HUNTER ID</div>
        <h2 style="margin-top:8px">Your Passport</h2>
        <input id="username" value="demo_user" placeholder="BL3 username">
        <button class="btn" onclick="loadUser()">Load Profile</button>
        <div class="stats" style="margin-top:12px">
          <div class="stat"><div class="num" id="xp">0</div><div class="small">XP</div></div>
          <div class="stat"><div class="num" id="streak">0</div><div class="small">STREAK</div></div>
          <div class="stat"><div class="num" id="rank">-</div><div class="small">RANK</div></div>
          <div class="stat"><div class="num" id="wins">0</div><div class="small">WINS</div></div>
          <div class="stat"><div class="num" id="earned">0</div><div class="small">EARNED</div></div>
        </div>
        <div id="streakReward" class="meta" style="margin-top:12px">🔥 Next: 3-Day Flame</div>
        <button id="streakClaimButton" class="btn hot hidden" onclick="claimStreakReward()">🎁 Claim Streak Reward</button>
      </div>

      <div class="card" style="margin-top:16px">
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

  <div class="footer">BL3 // BUILD. MEME. REPEAT. // V6.1 WINNERS</div>
</div>
<div id="message" class="message hidden"></div>

<script>
let username="demo_user";
let messageTimer=null;
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
 }
 await loadLeaderboard(); await claimReferral(); await authStatus();
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
async function quest(name){currentUser();const d=await jsonFetch("/api/quest",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({user:username,quest:name})});if(d.xp!==undefined)update(d);show(d.message||"Quest finished");loadLeaderboard()}
function share(){window.open("https://warpcast.com/~/compose?text="+encodeURIComponent("BL3 — Hunt alpha. Prove it. 👑 https://bl3meme.com"),"_blank");show("Post your cast, paste its URL, then verify.")}
async function verifyShare(){currentUser();const cast_url=document.getElementById("castUrl").value.trim();const d=await jsonFetch("/api/share/verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({user:username,cast_url})});if(d.xp!==undefined)update(d);show(d.message||"Verification finished");if(d.success)loadLeaderboard()}
function invite(){const link=location.origin+"/?ref="+encodeURIComponent(currentUser());if(navigator.clipboard)navigator.clipboard.writeText(link);show("Invite link: "+link)}
async function claimReferral(){const p=new URLSearchParams(location.search),inviter=(p.get("ref")||"").trim(),invited=currentUser();if(!inviter)return;if(!invited||invited==="demo_user"){show("Referral detected. Enter your username.");return}if(inviter===invited){show("You cannot refer yourself.");return}const d=await jsonFetch("/api/referral",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({inviter,invited})});show(d.message||"Referral checked");if(d.success){history.replaceState({},"",location.pathname);loadLeaderboard()}}
async function connectWallet(){if(!window.ethereum){show("No browser wallet detected.");return}try{const a=await ethereum.request({method:"eth_requestAccounts"});if(!a.length)return;document.getElementById("wallet").value=a[0];show("Wallet connected. Now sign the message.")}catch(e){show("Wallet connection cancelled.")}}
async function signInWallet(){if(!window.ethereum){show("No browser wallet detected.");return}try{currentUser();if(username==="demo_user"){show("Enter your BL3 username first.");return}const a=await ethereum.request({method:"eth_requestAccounts"}),wallet=a[0];const n=await jsonFetch("/api/auth/nonce?wallet="+encodeURIComponent(wallet)+"&user="+encodeURIComponent(username));if(!n.success){show(n.message);return}const signature=await ethereum.request({method:"personal_sign",params:[n.message,wallet]});const d=await jsonFetch("/api/auth/verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({wallet,username,message:n.message,signature})});show(d.message||"Sign-in finished");if(d.success){document.getElementById("authStatus").innerText="Verified: "+wallet.slice(0,6)+"…"+wallet.slice(-4);document.getElementById("navAuth").innerText="WALLET VERIFIED";await loadUser()}}catch(e){show("Wallet sign-in cancelled or failed.")}}
async function authStatus(){const d=await jsonFetch("/api/auth/status");if(d.authenticated){document.getElementById("authStatus").innerText="Verified: "+d.wallet.slice(0,6)+"…"+d.wallet.slice(-4);document.getElementById("navAuth").innerText="WALLET VERIFIED"}}
async function loadLeaderboard(){const d=await jsonFetch("/api/leaderboard");let h="";(Array.isArray(d)?d:[]).slice(0,10).forEach((u,i)=>h+='<div class="leader"><span>#'+(i+1)+' '+escapeHtml(u.username)+'</span><b>'+u.xp+' XP</b></div>');document.getElementById("leaderboard").innerHTML=h||'<div class="meta">No hunters yet.</div>';document.getElementById("totalHunters").innerText=Array.isArray(d)?d.length:0}
async function claimStreakReward(){currentUser();const s=Number(document.getElementById("streak").innerText),p=await jsonFetch("/api/user/"+encodeURIComponent(username)),c=Array.isArray(p.claimed_milestones)?p.claimed_milestones.map(Number):[];let m=0;if(s>=3&&!c.includes(3))m=3;else if(s>=7&&!c.includes(7))m=7;else if(s>=30&&!c.includes(30))m=30;if(!m){show("No streak reward available yet.");return}const d=await jsonFetch("/api/streak/claim",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({user:username,milestone:m})});show(d.message||"Claim finished");if(d.success)await loadUser()}
function escapeHtml(v){return String(v??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]))}
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
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "✅ Payment marked as completed. Earnings are now counted in the winner profile."})


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
    wins = conn.execute(
        "SELECT COUNT(*) AS n FROM arenas WHERE winner_username = ?",
        (username,)
    ).fetchone()["n"]
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
    print("👑 BL3 ARENA V6.1 // WINNERS")
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
