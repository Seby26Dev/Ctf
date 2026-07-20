
<img width="1118" height="435" alt="image" src="https://github.com/user-attachments/assets/195fef7a-03fa-4fcb-8b5f-da92376b8d24" />


<img width="752" height="78" alt="image" src="https://github.com/user-attachments/assets/fe51e2fa-e24d-464a-b50e-3c30a6349bc7" />


## Challenge Overview

The system intercepts Alice's 24-byte public key and allows us to patch a single byte before it reaches Bob. The goal is to exploit this patch to force a cryptographic vulnerability and recover the encrypted flag

## Mathematical Collapse

Looking at the source code in `wrapper.py`, the vulnerability becomes clear in the `generate_public_key_near_multiple` function:

```python
target_value -= target_value % 65537
# ...
mask = secrets.choice((0x01, 0x02, 0x04, 0x08, 0x11, 0x55, 0x80))
original_bytes[byte_index] ^= mask
```
Summ
|--|
 Alice intentionally generates a large number that is a perfect multiple of 65537
|--|
 Before sending it, she XORs one random byte using a mask from a fixed list
|--|
As a result, the public key `A` actually sent over the wire is no longer divisible by 65537

We're allowed to patch a single byte. If we apply the same XOR mask Alice used, we restore the original public key —> forcing the new key A to be divisible by 65537 (`A ≡ 0 mod 65537`).

## Kill Chain

The attack has two phases:

#### Network Patch

We connect to the server, intercept the public key, and mathematically brute-force the corrupted byte by testing only the allowed masks, until the resulting number becomes a multiple of 65537. We send the offset and new value to the server and capture the remote ciphertext

#### Local Oracle Attack

Since the shared secret collapses to 0, we can use the local `.so` library as an oracle:
| Step | Description |
|------|--------------|
| 1 | Locally set the FLAG environment variable to a known string (e.g. "A" * 64`) |
| 2 | Run libcutecrypto.so with the patched public key |
| 3 | The library returns a local ciphertext: C_local = Keystream ⊕ Fake_Flag |
| 4 | Since we know the fake flag, we recover the keystream: Keystream = C_local ⊕ Fake_Flag |
| 5 | Decrypt the real flag: Real_Flag = C_remote ⊕ Keystream |


## Exploit

This script automates the entire process, from the SSL connection to the server through the local mathematical decryption of the flag.

```python
#!/usr/bin/env python3
import socket
import ssl
import re
import os

# Set the fake flag BEFORE importing anything from the C library wrapper
fake_flag_str = "A" * 64
os.environ["FLAG"] = fake_flag_str
os.environ["CUTESECURE_PRIVATE_B_HEX"] = "80" + "00"*14 + "11"

# Import functions from the local wrapper
from wrapper import send_mitm, init_system_output

def main():
    host = "whiskerfield-b43701b3163b.inst.omnictf.com"
    port = 1337

    # INTERCEPTION AND PATCH 
    print(f"[*] Connecting to {host}:{port} over SSL...")
    ctx = ssl.create_default_context()
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = ctx.wrap_socket(raw_socket, server_hostname=host)
    s.connect((host, port))

    buf = b""
    while b"tx> " not in buf:
        chunk = s.recv(4096)
        if not chunk: break
        buf += chunk

    # Extract the hexdump
    lines = buf.decode('utf-8', 'replace').split('\n')
    hex_data = "".join(line.split(":", 1)[1].replace(" ", "") for line in lines if re.match(r"^\s*[0-9a-fA-F]{4}:", line))

    original_a = bytes.fromhex(hex_data)
    print(f"[+] Intercepted public key: {original_a.hex()}")

    val = int.from_bytes(original_a, "big")
    patch = None
    allowed_masks = (0x01, 0x02, 0x04, 0x08, 0x11, 0x55, 0x80)

    # Search for the valid patch that restores divisibility by 65537
    for i in range(len(original_a)):
        for mask in allowed_masks:
            v = original_a[i] ^ mask
            shift = (len(original_a) - 1 - i) * 8
            new_val = val - (original_a[i] << shift) + (v << shift)

            if new_val % 65537 == 0:
                patch = f"{i:02x}:{v:02x}"
                patched_a = new_val.to_bytes(len(original_a), 'big')
                print(f"[!] Vulnerability triggered! Offset {hex(i)} -> Mask {hex(mask)} -> Value sent {hex(v)}")
                break
        if patch: break

    s.sendall(patch.encode('ascii') + b"\n")

    # Retrieve the encrypted payload from the server
    response = b""
    while True:
        chunk = s.recv(4096)
        if not chunk: break
        response += chunk

    remote_match = re.search(r"payload=([0-9a-f]+)", response.decode('utf-8', 'ignore'))
    remote_payload = bytes.fromhex(remote_match.group(1))
    print(f"[+] Server payload retrieved: {remote_payload.hex()[:32]}...")

    # LOCAL LIBRARY KEYSTREAM EXTRACTION
    print("[*] Running the C library locally to force the same keystream generation...")
    init_system_output()
    local_output = send_mitm(original_a, patched_a)

    local_match = re.search(r"payload=([0-9a-f]+)", local_output)
    local_payload = bytes.fromhex(local_match.group(1))

    # KPA DECRYPTION 
    # XOR the two payloads together to cancel out the keystream
    # (Real_Flag ^ Keystream) ^ (Fake_Flag ^ Keystream) = Real_Flag ^ Fake_Flag
    xor_result = bytes(r ^ l for r, l in zip(remote_payload, local_payload))

    # Skip the first 24 bytes (Bob's public key B) and XOR with 0x41 ("A")
    real_flag = bytes(x ^ 0x41 for x in xor_result[24:])

    print("\n DECRYPTED FLAG:")
    print(real_flag.decode('utf-8', 'ignore').strip('\x00'))

if __name__ == "__main__":
    main()
```
