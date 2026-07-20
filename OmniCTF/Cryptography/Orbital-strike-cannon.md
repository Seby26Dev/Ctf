<img width="1109" height="718" alt="image" src="https://github.com/user-attachments/assets/566dafe4-2a7e-4b94-bdbf-7c55370e8a8c" />

<img width="766" height="71" alt="image" src="https://github.com/user-attachments/assets/51ae7e3e-69e8-400c-90f4-8a1fbd9cc27c" />


 # What the server gives us

`server.py` spins up an instance (`cannon.py`) and sends us a public JSON blob containing:

- `alpha`, `beta` — two fixed 8-element vectors (octonions) for the whole session
- `outer_a` — a scalar
- `rng_beacons` — a list of values from an RNG explicitly flagged as "known-bad" in the `notes`
- `satellites` — 7 sets of "measurements" (5 real + 2 decoys), each with its own linear basis, bias, and coordinates
- `ciphertext` — the encrypted flag

The server then asks for a `firing_code` = `sha256(key + b"|fire").hexdigest()[:32]`, where `key` comes from a fully private `secret_material` that never appears in the JSON:

```python
secret_material = vec_to_bytes(moon0 + [x0, rng_u, rng_v])
key = hashlib.sha256(b"OSC-KEY|" + secret_material).digest()
```

So the goal is clear: **recover `moon0` (8 values), `x0`, and `rng_u`, `rng_v`** — none of which are sent directly.

## 2. Bug #1 —> the RNG is a linear LCG, so it breaks from 3 outputs

```python
class BrokenRNG:
    def __init__(self, u, v, state):
        ...
    def next(self):
        out = self.state
        self.state = (self.u * self.state + self.v) % P
        return out
```

This is a textbook [LCG](https://en.wikipedia.org/wiki/Linear_congruential_generator): `s_{i+1} = u*s_i + v (mod P)`. Since every output (`rng_beacons`) is public, we have three consecutive values `R0, R1, R2` satisfying:

```
R1 = u*R0 + v
R2 = u*R1 + v
```

Subtracting eliminates `v`:

```
R2 - R1 = u*(R1 - R0)  =>  u = (R2-R1) * inv(R1-R0) mod P
v = R1 - u*R0 mod P
```

With just **3 public numbers** we fully recover `u` and `v` — 2 of the 4 secrets we need, no linear-system solving required.

```python
R0, R1, R2 = rng_beacons[0], rng_beacons[1], rng_beacons[2]
inv_diff = pow((R1 - R0) % P, P - 2, P)
u = ((R2 - R1) * inv_diff) % P
v = (R1 - u * R0) % P
```

## 3. Bug #2 —> the "non-associativity" is just flavor text; the transition is affine

The title and comments make a big deal of octonion non-associativity as if it should scare us off. In practice it's irrelevant to the exploit — all that matters is that, at every step `i`, the state `(M_{i+1}, X_{i+1})` is obtained from `(M_i, X_i)` through a **known affine transform** (matrices built from `alpha`, `beta`, `outer_a`, and `rng_beacons`, all public):

```python
transition = mat_mul(mat_right(alpha), mat_left(r_oct))   # public 8x8 linear matrix
step[row][9] = beta[row]                                   # public affine offset
```

`build_state_expressions` composes these matrices step by step and produces, for every state `i`, a 10x10 matrix `states[i]` that expresses `[M_i, X_i, 1]` as an **affine function of `[M_0, X_0, 1]`** — the unknown vector we're after. In other words:

```
M_i = A_i · M_0 + b_i · X_0 + c_i     (A_i, b_i, c_i are all known/derivable)
X_i = ...
```

This turns the whole dynamical system (octonions, 10x10 matrices, LCG) into a **plain linear system with 9 unknowns**: the 8 components of `moon0` plus `x0`.

## 4. Bug #3 —> "real" satellites yield a consistent linear system, fakes don't

Each satellite produces 5 samples of 3 coordinates each:

```python
sample = [(mask * dot(row, fval) + bias[j]) % P for j, row in enumerate(basis_rows)]
```

where `fval = feature_value(moons, orbits, idx)` is exactly `[M_idx, X_idx, X_{idx+1}, X_{idx+2}]` — via step 3, an **affine** function of `(M_0, X_0)`. `mask` is `rng_beacons[idx+sid+4]`, so it's **public** (the RNG is fully known). `bias` and `basis_rows` are also public, straight from the JSON.

So every coordinate of every sample is a linear equation in the 9 unknowns `(M_0, X_0)`:

```
mask * (basis_row · [A_idx | b_idx | c_idx]) · [M0, X0, 1]^T  +  bias  =  observed_coord
```

With 5 samples × 3 coordinates we get **15 equations for 9 unknowns** — an overdetermined system. For the 5 **real** satellites, the equations are consistent (they were built from the true values). For the 2 **fake** satellites, the coordinates are pure noise (`rnd_vec`), so the solution found by Gaussian elimination fails the remaining equations — which is exactly the check `solve_linear_system` runs at the end:

```python
for i in range(n):
    if sum(M[i][j] * X[j] for j in range(m)) % P != Y[i]:
        return None   # fake satellite, discard the result
```

So the algorithm is simple: try each satellite, solve the system mod `P`, keep the first one that's consistent → that gives `M_0` (moon0) and `X_0` (x0).

## 5. Rebuilding the key and decrypting the flag

Once all 4 secret pieces are known (`moon0`, `x0`, `u`, `v` — standing in for `rng_u`, `rng_v`, since the LCG's initial internal state doesn't matter, only `u`/`v` are used in `secret_material`):

```python
secret_material = b"".join(x.to_bytes(16, "big") for x in (M0 + [X0, u, v]))
key = hashlib.sha256(b"OSC-KEY|" + secret_material).digest()
firing_code = hashlib.sha256(key + b"|fire").hexdigest()[:32]

flag_ct = bytes.fromhex(data["ciphertext"])
stream = hashlib.shake_256(key + b"|stream").digest(len(flag_ct))
flag = bytes(a ^ b for a, b in zip(flag_ct, stream)).decode()
```

`ciphertext` was just a XOR against a SHAKE-256 stream derived from the same key, so once the key is recovered the flag falls out locally — and separately, we send `firing_code` over the socket to also validate on the server side.

## 6. Exploit chain summary

1. Open a TLS connection to the server, read the public JSON + the "Submit firing code:" prompt.
2. From `rng_beacons[0..2]` → recover `u`, `v` (the LCG is linear, breaks algebraically).
3. From `alpha`, `beta`, `outer_a`, `rng_beacons` → build the affine state expressions for every step `i` in terms of `(M_0, X_0)` (composed 10x10 matrices).
4. For each satellite: build the linear system (15 equations, 9 unknowns) using the public `basis`, `bias`, `mask`; solve via Gaussian elimination mod `P`; check consistency.
5. First consistent satellite = real satellite → recover `M_0` (8 values) and `X_0`.
6. Rebuild `secret_material` → `key` → `firing_code`, decrypt `ciphertext` locally (SHAKE-256 XOR).
7. Send `firing_code` over the socket → server confirms and returns the flag.

**Crypto takeaway:** a system can look intimidating (octonions, non-associativity, 10×10 matrices, LCG) but if *every step is affine/linear with respect to a small set of publicly-derivable unknowns*, the whole thing collapses to standard linear algebra over a finite field — the same idea behind classic linear-cryptanalysis-style attacks.

## 7. Full exploit script

```python
#!/usr/bin/env python3
import socket
import ssl
import json
import hashlib

# --- Math helpers, extracted directly from cannon.py ---
P = (1 << 127) - 1

def add(a, b): return [(x + y) % P for x, y in zip(a, b)]
def sub(a, b): return [(x - y) % P for x, y in zip(a, b)]
def q_conj(a): return [a[0], (-a[1]) % P, (-a[2]) % P, (-a[3]) % P]

def q_mul(a, b):
    a0, a1, a2, a3 = a
    b0, b1, b2, b3 = b
    return [
        (a0 * b0 - a1 * b1 - a2 * b2 - a3 * b3) % P,
        (a0 * b1 + a1 * b0 + a2 * b3 - a3 * b2) % P,
        (a0 * b2 - a1 * b3 + a2 * b0 + a3 * b1) % P,
        (a0 * b3 + a1 * b2 - a2 * b1 + a3 * b0) % P,
    ]

def o_conj(x): return q_conj(x[:4]) + [(-v) % P for v in x[4:]]

def o_mul(x, y):
    a, b = x[:4], x[4:]
    c, d = y[:4], y[4:]
    left = sub(q_mul(a, c), q_mul(q_conj(d), b))
    right = add(q_mul(d, a), q_mul(b, q_conj(c)))
    return left + right

def basis(i):
    out = [0] * 8
    out[i] = 1
    return out

def mat_left(o): return transpose([o_mul(o, basis(i)) for i in range(8)])
def mat_right(o): return transpose([o_mul(basis(i), o) for i in range(8)])
def transpose(m): return [list(row) for row in zip(*m)]

def mat_mul(a, b):
    rows, inner, cols = len(a), len(b), len(b[0])
    return [
        [sum(a[i][k] * b[k][j] for k in range(inner)) % P for j in range(cols)]
        for i in range(rows)
    ]

def rng_octonion(r, i):
    a, b, c, d = r[i], r[i + 1], r[i + 2], r[i + 3]
    return [1, a, b, c, d, (a * b + c) % P, (b * c + d) % P, (a * d + b * c + 7) % P]

def build_state_expressions(alpha, beta, outer_a, rng_values):
    states = []
    cur = [[1 if i == j else 0 for j in range(10)] for i in range(10)]
    states.append(cur)

    for i in range(34 + 3):  # N_STATES + 3
        r_oct = rng_octonion(rng_values, i)
        transition = mat_mul(mat_right(alpha), mat_left(r_oct))

        step = [[0] * 10 for _ in range(10)]
        for row in range(8):
            for col in range(8):
                step[row][col] = transition[row][col]
            step[row][9] = beta[row]

        for col in range(8):
            step[8][col] = 1
        step[8][8] = outer_a
        step[8][9] = rng_values[i]
        step[9][9] = 1

        cur = mat_mul(step, cur)
        states.append(cur)
    return states

def feature_rows(states, i):
    rows = [states[i][j] for j in range(8)]
    rows.append(states[i][8])
    rows.append(states[i + 1][8])
    rows.append(states[i + 2][8])
    return rows

# --- Gaussian Elimination over F_P (Pure Python!) ---
def solve_linear_system(M, Y):
    n, m = len(M), len(M[0])
    A = [row[:] + [Y[i]] for i, row in enumerate(M)]

    # Forward elimination
    for col_idx in range(m):
        pivot = -1
        for i in range(col_idx, n):
            if A[i][col_idx] != 0:
                pivot = i
                break
        if pivot == -1: return None

        A[col_idx], A[pivot] = A[pivot], A[col_idx]
        inv = pow(A[col_idx][col_idx], P - 2, P)
        for j in range(col_idx, m + 1):
            A[col_idx][j] = (A[col_idx][j] * inv) % P

        for i in range(col_idx + 1, n):
            factor = A[i][col_idx]
            for j in range(col_idx, m + 1):
                A[i][j] = (A[i][j] - factor * A[col_idx][j]) % P

    # Back substitution
    X = [0] * m
    for i in range(m - 1, -1, -1):
        val = A[i][m]
        for j in range(i + 1, m):
            val = (val - A[i][j] * X[j]) % P
        X[i] = val % P

    # Verify consistency (this is what tells real satellites from fakes)
    for i in range(n):
        if sum(M[i][j] * X[j] for j in range(m)) % P != Y[i]:
            return None
    return X

# --- Main exploit ---
def exploit():
    host = "orbital-0a06a73c0edc.inst.omnictf.com"
    port = 1337

    print(f"[*] Connecting to {host}:{port} over SSL...")
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
    s.connect((host, port))

    # Wait for the JSON blob
    buf = b""
    while b"Submit firing code:" not in buf:
        buf += s.recv(4096)

    print("[+] Telemetry intercepted. Starting calculations...")
    json_str = buf.split(b"Telemetry follows. Survive the non-associative recoil.\n")[1].split(b"Submit firing code:")[0].strip()
    data = json.loads(json_str)

    rng_beacons = data["rng_beacons"]

    # 1. Recover u and v from the rng_beacons LCG
    R0, R1, R2 = rng_beacons[0], rng_beacons[1], rng_beacons[2]
    inv_diff = pow((R1 - R0) % P, P - 2, P)
    u = ((R2 - R1) * inv_diff) % P
    v = (R1 - u * R0) % P
    print(f"[*] RNG cracked -> u: {u}, v: {v}")

    # 2. Build the affine state expressions
    states = build_state_expressions(data["alpha"], data["beta"], data["outer_a"], rng_beacons)

    M0, X0 = None, None

    # 3. Iterate over satellites to find the real one and recover the secrets
    for sat in data["satellites"]:
        M_matrix = []
        Y_vec = []

        sid = int(sat["name"].split("-")[1])
        start, stop, step = sat["arange"]
        indices = [start + step * t for t in range(5)]

        for t, idx in enumerate(indices):
            mask = rng_beacons[idx + sid + 4]
            T = feature_rows(states, idx)
            M_eff = mat_mul(sat["basis"], T)

            for c in range(3):
                # 9 unknowns (8 for M0, 1 for X0)
                row = [(mask * M_eff[c][j]) % P for j in range(9)]
                # System constant
                y_val = (sat["coords"][t][c] - sat["bias"][c] - mask * M_eff[c][9]) % P
                M_matrix.append(row)
                Y_vec.append(y_val)

        # Solve the system
        X = solve_linear_system(M_matrix, Y_vec)
        if X is not None:
            print(f"[+] Found VALID satellite: {sat['name']}! Extracting state variables...")
            M0 = X[:8]
            X0 = X[8]
            break

    if M0 is None:
        print("[-] No valid satellite found.")
        return

    # 4. Rebuild the key and firing code
    secret_material = b"".join(x.to_bytes(16, "big") for x in (M0 + [X0, u, v]))
    key = hashlib.sha256(b"OSC-KEY|" + secret_material).digest()
    firing_code = hashlib.sha256(key + b"|fire").hexdigest()[:32]

    # Decrypt the flag locally for validation
    flag_ct = bytes.fromhex(data["ciphertext"])
    stream = hashlib.shake_256(key + b"|stream").digest(len(flag_ct))
    flag = bytes(a ^ b for a, b in zip(flag_ct, stream)).decode()

    print(f"[!] Generated Firing Code: {firing_code}")
    print(f"[!] Locally decrypted flag: {flag}")

    # 5. Send the payload to the server
    print("[*] Sending code to the orbital cannon...")
    s.sendall(firing_code.encode() + b"\n")

    response = s.recv(4096).decode()
    print("\n--- Server Response ---")
    print(response.strip())

if __name__ == "__main__":
    exploit()
```

