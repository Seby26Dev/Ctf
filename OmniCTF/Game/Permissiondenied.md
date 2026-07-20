

<img width="1119" height="533" alt="image" src="https://github.com/user-attachments/assets/8bb3f79a-1ad7-4678-9d8d-c2b784ce9600" />

<img width="768" height="65" alt="image" src="https://github.com/user-attachments/assets/74618334-a695-4dd1-82a8-7a58ff92cb02" />


Upon joining the server, I tried basic commands to enumerate available plugins and permissions

/help returned nothing useful, but /plugins revealed two plugins installed:

    GroupManager (a permissions management plugin)
    CTFHandler (a custom CTF plugin that registers /flag)

Running /flag returned:

```
Unknown command.
```

This meant the /flag command existed but was hidden behind a permission. I needed to find a way to escalate privileges

Using tab completion, I found two GroupManager commands available to my default user:

    /manglist — lists available groups
    /manglistp <group> — lists permissions for a group

Running /manglistp Admin revealed:

```
The group 'Admin' has the following permissions:
-essentials.*
customdemotion.demote
flaghandler.flag
```

Further tab completion revealed a /demote command from a customdemotion plugin. Running /demote showed:

```
Usage: /demote <rank>
Available ranks:
0 -> Prisoner
1 -> Restricted
2 -> Limited
3 -> Default (current rank)
4 -> Builder
5 -> Helper
6 -> Moderator
7 -> Admin
You cannot demote yourself above your current rank.
```

Running:

```
/demote -1
```

Bypassed the rank restriction entirely and glitched the plugin granting me a higher rank than intended. After a few iterations, my rank escalated all the way to Admin (7).

Once I had the Admin rank , I simply ran:

```
/flag
```


