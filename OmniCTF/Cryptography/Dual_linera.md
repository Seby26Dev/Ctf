<img width="1115" height="483" alt="image" src="https://github.com/user-attachments/assets/ecbbde9a-a71d-4155-9ca1-f27e5c040bcf" />

<img width="765" height="67" alt="image" src="https://github.com/user-attachments/assets/e2cdccbf-acd9-41de-97e8-9ba80785e32a" />

## Challenge Description

We are given two files:

- `challenge.json` — the challenge instance (two primes `q1`, `q2`, 18 samples, and a ciphertext for the flag)
- `generate.sage` — the generator script that produced the instance

The generator implements a small linear scheme evaluated modulo **two different primes** at once:

```python
q1 = random_prime(2**180 - 1, lbound=2**179)   # ~180-bit prime
q2 = random_prime(2**181 - 1, lbound=2**180)   # ~181-bit prime

secret = ZZ.random_element(2**(SECRET_BITS-1), 2**SECRET_BITS)   # 96-bit secret

for _ in range(SAMPLE_COUNT):        # 18 samples
    a1 = ZZ.random_element(1, q1)
    a2 = ZZ.random_element(1, q2)
    e  = ZZ.random_element(0, 2**E_BITS)   # 176-bit "nonce"/error
    y1 = (a1 * secret + e) % q1
    y2 = (a2 * secret + e) % q2
```

Each sample publishes `(a1, a2, y1, y2)`. The 96-bit `secret` is then hashed with SHA-256 and used as a SHAKE-256-based stream key to XOR-encrypt the flag.

So the goal is simple: **recover `secret`** from the 18 published samples, then decrypt `flag_ciphertext`.

## The Vulnerability

At first glance this looks like two independent noisy linear equations (`y1` mod `q1`, `y2` mod `q2`), each hiding `secret` behind a fresh random error term `e`. If the two moduli and the two error terms were truly independent, this would basically be two separate, individually-secure Learning-With-Errors-like instances.

The bug is that **the same nonce `e` is reused for both equations in a sample**, just reduced modulo two *different* primes. Because `a1, secret, e` are all far smaller than `q1`, the reduction mod `q1` is really:

```
a1*secret + e = y1 + k1*q1      (exact integer equality, k1 ≥ 0 integer)
```

and analogously `y2` is already `< q2`, so mod `q2` we simply have:

```
a2*secret + e ≡ y2   (mod q2)
```

Now look at `y1 - y2` reduced **modulo `q2` only** (this is legal since `a1, y1 < q1 < q2`, so nothing there needs reducing mod `q2`):

```
y1 - y2 ≡ (a1 - a2)*secret - k1*q1   (mod q2)
```

The nonce `e` cancels out completely — it never appears in this relation. Multiplying by the modular inverse of `q1` mod `q2` isolates `secret`:

```
da = (a1 - a2) * q1⁻¹        (mod q2)
dy = (y1 - y2) * q1⁻¹        (mod q2)

dy ≡ da * secret - k1        (mod q2)
```

This is exactly a **Hidden Number Problem (HNP)** instance: for every sample `i` we get

```
dy_i - da_i * secret ≡ -k1_i   (mod q2)
```

where `secret` (96 bits) and every `k1_i` (also roughly 96 bits, since `k1 ≈ a1*secret / q1`) are the *unknowns*, all small compared to the ~181-bit modulus `q2`. With 18 such samples we have far more equations than unknowns-per-sample, which is the classic setup where an **LLL lattice reduction** recovers all the small unknowns, including `secret`, in polynomial time.

In short: reusing the nonce across two moduli connected by CRT-like arithmetic (`q1`, `q2` coprime) let us build a modulus-`q2`-only relation where the nonce disappears and the secret becomes recoverable via a standard HNP/lattice attack — hence the flag: *"CRT makes a tiny nonce ... without leaking it [directly, but leaking the secret instead]"*.

## Building the Lattice

We want short integer vectors `(secret, k1_1, ..., k1_n)` (all ~96 bits) satisfying

```
dy_i ≡ da_i * secret - k1_i   (mod q2)     for i = 1..n
```

This is set up as an `(n+2) x (n+2)` integer lattice:

```
Row 0        : [ 1, da_1, da_2, ..., da_n,      0 ]
Row i (1..n) : [ 0,  0, ..., q2, ..., 0,         0 ]   (q2 on the diagonal, position i)
Row n+1      : [ 0, dy_1, dy_2, ..., dy_n,       W ]
```

with `W = 2^96` used purely to scale/balance the constant column so LLL treats the "secret-recovery" coordinate with the right weight relative to the modular rows.

Taking an integer combination `secret * Row0 + Row(n+1)` produces the vector

```
(secret, secret*da_1 + dy_1, ..., secret*da_n + dy_n, W)
```

and since `secret*da_i + dy_i ≡ dy_i - da_i*(-secret) ...` reduces mod `q2` (using the `q2` rows to cancel multiples of `q2`) down to the small `k1_i` values, LLL finds a short vector of the form `(±secret, ±k1_1, ..., ±k1_n, ±W)` — the sign is fixed by checking which row has last coordinate `== W` vs `== -W`.

## Solve Script

```python
q1_inv = inverse_mod(q1, q2)

A, Y = [], []
for s in samples:
    da = (s['a1'] - s['a2']) % q2
    dy = (s['y1'] - s['y2']) % q2
    A.append((da * q1_inv) % q2)
    Y.append((dy * q1_inv) % q2)

M = Matrix(ZZ, n + 2, n + 2)
W = 2**96
M[0, 0] = 1
for i in range(n):
    M[0, i+1]   = A[i]
    M[i+1, i+1] = q2
    M[n+1, i+1] = Y[i]
M[n+1, n+1] = W

L = M.LLL()

for row in L:
    if abs(row[-1]) == W:
        secret = row[0] if row[-1] == -W else -row[0]
        break
```

Running this against the 18 published samples recovers:

```
secret = 67133769516566898715085291836
```

## Decrypting the Flag

The scheme derives the stream key as `SHA-256(str(secret))`, then XORs it (via SHAKE-256 expansion) against `flag_ciphertext`:

```python
key = hashlib.sha256(str(secret).encode()).digest()
flag = xor_stream(key, bytes.fromhex(flag_ciphertext))
```

This yields:

```
OmniCTF{crt_makes_a_tiny_nonce_without_leaking_it}
```
