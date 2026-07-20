
<img width="1107" height="447" alt="image" src="https://github.com/user-attachments/assets/878b2312-27ae-4bf7-9244-186338f0c734" />

<img width="758" height="70" alt="image" src="https://github.com/user-attachments/assets/5034ac07-ff47-41c5-9511-3d82561e0ee3" />


## Challenge Description

> The goal is to learn which side is favored for each visible matchup, then size even-money bets well enough to grow the bankroll to the target.

The challenge exposes a TCP service server.py that simulates a modified baccarat game played between predefined AI agents. 
The connecting player does not control any cards — their only role is to bet on which side wins each round .
The session starts with 1000 and the goal is to reach a target bankroll of 100,000. Once the target is reached, the server returns the flag.


## The critical detail is in server.py's table_roster:

```python
TABLE_ROSTER = [
    ("omnicybr", "blackshard", 12),
    ("blackshard", "omnicybr", 12),
    ("northstar", "blackshard", 11),
    ...
]
```

Each table pairs a specific Player agent with a specific Banker agent, and the server announces both names before every single bet:

```
BankerAI :: OmniCybr
PlayerAI :: BlackShard
```

## Solution Script

```python
#!/usr/bin/env python3
import re
import pickle
from pwn import *
from game import load_player_agents, load_banker_agents, simulate_pairing

HOST = 'baccarat-6aa7281614db.inst.omnictf.com'
PORT = 1337
SIM_ROUNDS = 100000
KELLY_FRACTION = 1

def calculate_winrates():
    log.info("Simulating matchups (this step can take a while)...")
    players = {a.display_name: a for a in load_player_agents()}
    bankers = {a.display_name: a for a in load_banker_agents()}
    rates = {}
    for p_name, p_agent in players.items():
        for b_name, b_agent in bankers.items():
            stats = simulate_pairing(p_agent, b_agent, SIM_ROUNDS, "ctf_seed")
            rates[(p_name, b_name)] = stats.player_resolved_winrate
    with open("winrates.pkl", "wb") as f:
        pickle.dump(rates, f)
    log.success("Win rates saved to winrates.pkl")
    return rates

def load_winrates():
    try:
        with open("winrates.pkl", "rb") as f:
            return pickle.load(f)
    except FileNotFoundError:
        return calculate_winrates()

def solve():
    rates = load_winrates()
    log.info(f"Connecting to {HOST}:{PORT}...")
    r = remote(HOST, PORT, ssl=True)

    while True:
        try:
            data = r.recvuntil(b"Bet side [player/banker]:", timeout=30).decode()
        except EOFError:
            data = r.recvall().decode()
            print(data)
            break

        if "FLAG" in data or "Session result" in data:
            print(data)
            break

        player_ai = re.search(r"PlayerAI :: (\w+)", data).group(1)
        banker_ai = re.search(r"BankerAI :: (\w+)", data).group(1)
        bankroll = int(re.search(r"Bankroll :: (\d+)", data).group(1))

        p_win = rates[(player_ai, banker_ai)]
        if p_win > 0.5:
            side = "player"
            edge = p_win
        else:
            side = "banker"
            edge = 1.0 - p_win

        fraction = (2 * edge - 1) * KELLY_FRACTION
        bet = max(1, int(bankroll * fraction))

        log.info(f"[{player_ai} vs {banker_ai}] -> {side.upper()} "
                  f"({edge*100:.1f}%) | bet {bet}/{bankroll}")

        r.sendline(side.encode())
        prompt = r.recvline().decode()
        r.sendline(str(bet).encode())

    r.interactive()

if __name__ == "__main__":
    solve()
```
