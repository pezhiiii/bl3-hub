BL3 V2 GAME EDITION

What changed:
- New game-first homepage at /
- Old BL3 homepage preserved at /classic
- Playable Alpha Clash arena
- Hunter Creature identity
- HP, Attack, Power Strike, Repair
- XP, levels, coins, energy, wins/losses, streaks
- Daily Signal Chest
- Battle history
- Game leaderboard
- Uses the existing BL3 database path (BL3_DB_PATH), so Railway /data/bl3.db remains compatible

Deploy:
Replace the repo app.py with this app.py and let Railway redeploy.

Safety:
All existing BL3 routes remain in the file. V2 only replaces the public home view and adds /api/game/* routes.
