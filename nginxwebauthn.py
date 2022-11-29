#!/usr/bin/env python3
import random
import socketserver
import http.server
import http.cookies
import json
import base64
import sys
import os
import time
import glob
import configparser
from urllib.parse import parse_qs
from random import randint

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.header import Header

from fido2.client import ClientData
from fido2.server import U2FFido2Server, RelyingParty
from fido2.ctap2 import AttestationObject, AttestedCredentialData, AuthenticatorData
from fido2 import cbor

CONFIG_FILE = "/etc/nginxwebauthn.conf"

if os.path.exists(CONFIG_FILE):
  config = configparser.ConfigParser()
  config.read(CONFIG_FILE)
  if "Global" in config.sections():
    if "allowpreregistration" in dict(config['Global'].items()).keys():
      ALLOW_PREREGISTRATION = config['Global']['allowpreregistration'].lower() in ['true', '1', 't', 'y', 'yes']
    else:
      ALLOW_PREREGISTRATION = False
    if ("fromemail" in dict(config['Global'].items()).keys()) and ("adminemail" in dict(config['Global'].items()).keys()): 
      ALLOW_EMAIL = True
      FROM_EMAIL = config['Global']['fromemail']
      ADMIN_EMAIL = config['Global']['adminemail']
    else:
      ALLOW_EMAIL = False

TOKEN_LIFETIME = 60 * 60 * 24
PORT = 8000
HTTP_PREFIX = "/nginx_fido_auth"
CREDENTIALS_DIR = "/opt/nginxwebauthn/credentials"
REGISTRATION_DIR = "/opt/nginxwebauthn/registrations"
HEADERS_DIR = "/opt/nginxwebauthn/headers"
LASTCHALLENGE = "/tmp/.lastchallenge"

FORM = f"""
<head>
  <meta http-equiv="Content-Type" content="text/html;charset=UTF-8">
  <link rel="stylesheet" href="style.css">
</head>
<body>
<script>

window.addEventListener('load', function(){{
  const queryString = window.location.search;
  const urlParams = new URLSearchParams(queryString);

  urlParams.forEach(function(value, key) {{
    switch (key.toLowerCase()) {{
      case 'externalid':
        document.getElementById('externalId').value = value 
        break;
      case 'username':
        document.getElementById('username').value = value
        break;
      case 'tokenname':
        document.getElementById('tokenName').value = value
        break;
      case 'name':
        document.getElementById('name').value = value
        break;
      case 'phone':
        document.getElementById('phone').value = value
        break;
      case 'email':
        document.getElementById('email').value = value
        break;
      case 'hiddenelements':
        let elements = JSON.parse(value)
        elements.forEach(function(elementId){{
          document.getElementById(elementId).style.display = "none"
        }})
        break;
      default:
        console.log(`unsupported attribute: ${{key}}`);
    }}
  }});
  if (urlParams.get('externalId') != undefined) {{
    window.externalId.value = urlParams.get('externalId')
  }}
}})

function atobarray(sBase64) {{
    var sBinaryString = atob(sBase64), aBinaryView = new Uint8Array(sBinaryString.length);
    Array.prototype.forEach.call(aBinaryView, function (el, idx, arr) {{ arr[idx] = sBinaryString.charCodeAt(idx); }});
    return aBinaryView;
}}

function barraytoa(arrayBuffer) {{
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
}}

async function configure() {{
    try {{
        let data = await fetch('%s/get_challenge_for_new_key', {{ method: 'POST' }});
        let json = await data.json()
        json.publicKey.challenge = atobarray(json.publicKey.challenge)
        json.publicKey.user.id = atobarray(json.publicKey.user.id)
        let cred = await navigator.credentials.create(json)
        if ({str(ALLOW_PREREGISTRATION).lower()}) {{
          window.host.value = window.location.host
          window.clientData.value = barraytoa(cred.response.clientDataJSON)
          window.attestationObject.value = barraytoa(cred.response.attestationObject)
          window.command.style.display = "none"
          window.preregistration.style.display = "block"
        }} else {{
          window.command.innerHTML = 'On your server, to save this key please run:<br /><pre>sudo nginxwebauthn.py save-client ' + window.location.host + ' ' + barraytoa(cred.response.clientDataJSON) + ' ' + barraytoa(cred.response.attestationObject) + ' credential_name</pre>'
        }}
    }} catch (e) {{
        console.log(e)
    }}
}}

(async function init() {{
    let data = await fetch('%s', {{ method: 'POST' }});
    let json = await data.json()
    if (json.publicKey !== undefined) {{
        json.publicKey.challenge = atobarray(json.publicKey.challenge)
        json.publicKey.allowCredentials.forEach(function(cred){{cred.id = atobarray(cred.id)}})
        json.publicKey.rpId = json.publicKey.rpId.split(":")[0]
        let result = await navigator.credentials.get(json)
        await fetch('%s/complete_challenge_for_existing_key', {{ method: 'POST', body: JSON.stringify({{
          id: barraytoa(result.rawId),
          authenticatorData: barraytoa(result.response.authenticatorData),
          clientDataJSON: barraytoa(result.response.clientDataJSON),
          signature: barraytoa(result.response.signature)
        }}), headers:{{ 'Content-Type': 'application/json' }}}})

        // Find the new URL to redirect to.
        let path = '/'
        path += window.location.pathname.slice('%s/'.length)
        path += window.location.search
        if (window.location.hash) {{
           path += '#' + window.location.hash
        }}
        window.location.href = path
    }}
    if (json.error == 'not_configured') {{
        configure();
    }}
}})()
</script>
<div id="command"></div>
<div id="preregistration" style="display: none" class="login-page">
  <div class="form">
    <form action="{HTTP_PREFIX}/preregistration" method="post">
      <input type="text" id="username" name="username" required placeholder="Username *">
      <input type="text" id="tokenName" name="tokenName" required placeholder="Token name *">
      <input type="text" id="name" name="name" placeholder="Name">
      <input type="tel" id="phone" name="phone" placeholder="Phone">
      <input type="email" id="email" name="email" placeholder="Email">

      <input type="hidden" name="externalId" id="externalId" value="">
      <input type="hidden" name="host" id="host">
      <input type="hidden" name="clientData" id="clientData">
      <input type="hidden" name="attestationObject" id="attestationObject">

      <input type="submit" value="Submit">
    </form>
  </div>
</div>
</body>
"""

CSS_CONTENTS = """
.login-page {
  width: 360px;
  padding: 8% 0 0;
  margin: auto;
}
.form {
  position: relative;
  z-index: 1;
  background: #FFFFFF;
  max-width: 360px;
  margin: 0 auto 100px;
  padding: 45px;
  text-align: center;
  box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24);
}
.form input {
  outline: 0;
  background: #f2f2f2;
  width: 100%;
  border: 0;
  margin: 0 0 15px;
  padding: 15px;
  box-sizing: border-box;
  font-size: 14px;
}
.form input[type=submit] {
  text-transform: uppercase;
  outline: 0;
  background: #4CAF50;
  width: 100%;
  border: 0;
  padding: 15px;
  color: #FFFFFF;
  font-size: 14px;
  -webkit-transition: all 0.3 ease;
  transition: all 0.3 ease;
  cursor: pointer;
}
body {
  background: #76b852; /* fallback for old browsers */
  background: -webkit-linear-gradient(right, #76b852, #8DC26F);
  background: -moz-linear-gradient(right, #76b852, #8DC26F);
  background: -o-linear-gradient(right, #76b852, #8DC26F);
  background: linear-gradient(to left, #76b852, #8DC26F);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

.success {
  color: green;
  font-size: x-large;
}

.error {
  color: red;
  font-size: x-large;
}
"""

class TokenManager(object):
    """Who needs a database when you can just store everything in memory?"""

    def __init__(self):
        self.tokens = {}
        self.headers = {}
        self.random = random.SystemRandom()

    def generate(self):
        t = '%064x' % self.random.getrandbits(8*32)
        self.tokens[t] = time.time()
        return t

    def set_header(self, t, header):
        self.headers[t] = header
    
    def get_header(self, t):
        try:
            return self.headers.get(t, 0)
        except Exception:
            return False

    def is_valid(self, t):
        try:
            return time.time() - self.tokens.get(t, 0) < TOKEN_LIFETIME
        except Exception:
            return False

    def invalidate(self, t):
        if t in self.tokens:
            del self.tokens[t]

#TODO remove elements from challenge managers after some time
LOGIN_CHALLENGE_MANAGER = {}
REGISTRATION_CHALLENGE_MANAGER = {}
CHALLENGE = {}
TOKEN_MANAGER = TokenManager()
HEADER_MANAGER = {}

def send_registration_mail_to_admin(username, token_name, name, phone, email, external_id, file_name):
  if not ALLOW_EMAIL:
    return

  smtp = smtplib.SMTP()
  smtp.connect('localhost')

  msgRoot = MIMEMultipart("alternative")
  msgRoot['Subject'] = Header("New nginxwebauthn registration", "utf-8")
  msgRoot['From'] = FROM_EMAIL
  msgRoot['To'] = ADMIN_EMAIL
  message = f"""
Username: {username}
Token name: {token_name}
Name: {name}
Phone: {phone}
Email: {email}
External ID: {external_id}

To confirm the registration run this command on your server
sudo mv {REGISTRATION_DIR}/{file_name} {CREDENTIALS_DIR}/{file_name}
"""
  text = MIMEText(message, "plain", "utf-8")
  msgRoot.attach(text)
  smtp.sendmail(FROM_EMAIL, ADMIN_EMAIL, msgRoot.as_string())

class AuthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == HTTP_PREFIX + '/style.css':
          self.send_response(200)
          self.send_header('Content-type', 'text/css')
          self.end_headers()
          self.wfile.write(bytes(CSS_CONTENTS, 'UTF-8'))
          return
        if self.path == HTTP_PREFIX + '/check':
            cookie = http.cookies.SimpleCookie(self.headers.get('Cookie'))
            if 'token' in cookie and TOKEN_MANAGER.is_valid(cookie['token'].value):
                self.send_response(200)
                header = TOKEN_MANAGER.get_header(cookie['token'].value)
                if header != 0:
                    self.send_header(header[0], header[1])
                self.end_headers()
                return

            self.send_response(401)
            self.end_headers()
            return

        if self.path.startswith(HTTP_PREFIX + '/login'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(bytes((FORM % (HTTP_PREFIX, HTTP_PREFIX + "/get_challenge_for_existing_key", HTTP_PREFIX, HTTP_PREFIX + '/login')), 'UTF-8'))
            return

        if self.path.startswith(HTTP_PREFIX + "/register"):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(bytes((FORM % (HTTP_PREFIX, HTTP_PREFIX + "/register", HTTP_PREFIX, HTTP_PREFIX + '/login')), 'UTF-8'))
            return

        if self.path == HTTP_PREFIX + '/logout':
            cookie = http.cookies.SimpleCookie(self.headers.get('Cookie'))
            if 'token' in cookie:
                TOKEN_MANAGER.invalidate(cookie['token'].value)

            # This just replaces the token with garbage
            self.send_response(302)
            cookie = http.cookies.SimpleCookie()
            cookie["token"] = '***'
            cookie["token"]["path"] = '/'
            cookie["token"]["secure"] = True
            self.send_header('Set-Cookie', cookie.output(header=''))
            self.send_header('Location', '/')
            self.end_headers()

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        origin = self.headers.get('Origin')
        host = origin[len('https://'):]

        rp = RelyingParty(host, 'NGINX Auth Server')
        server = U2FFido2Server(origin, rp)

        if self.path == HTTP_PREFIX + "/get_challenge_for_new_key":
            registration_data, state = server.register_begin({ 'id': b'default', 'name': "Default user", 'displayName': "Default user" })
            registration_data["publicKey"]["challenge"] = str(base64.b64encode(registration_data["publicKey"]["challenge"]), 'utf-8')
            registration_data["publicKey"]["user"]["id"] = str(base64.b64encode(registration_data["publicKey"]["user"]["id"]), 'utf-8')

            self.send_response(200)
            self.send_header('Content-type', 'application/json')

            if ALLOW_PREREGISTRATION:
              cookie = http.cookies.SimpleCookie()
              challenge_id = "".join(str(randint(1,9)) for _ in range(100))
              cookie["challenge_id"] = challenge_id
              REGISTRATION_CHALLENGE_MANAGER[challenge_id] = state
              self.send_header('Set-Cookie', cookie.output(header=''))
            else:
              # Save this challenge to a file so you can kill the host to add the client via CLI
              with open(LASTCHALLENGE, 'w') as f:
                f.write(json.dumps(state))

            self.end_headers()
            self.wfile.write(bytes(json.dumps(registration_data), 'UTF-8'))
            return

        if self.path == HTTP_PREFIX + "/preregistration":
          if ALLOW_PREREGISTRATION:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            post_data = parse_qs(post_data.decode('utf-8'))
            if not "externalId" in post_data.keys():
              post_data["externalId"] = ['']
            host = post_data['host'][0]

            client_data = ClientData(base64.b64decode(post_data['clientData'][0]))
            attestation_object = AttestationObject(base64.b64decode(post_data['attestationObject'][0]))

            rp = RelyingParty(host, 'NGINX Auth Server')
            server = U2FFido2Server('https://' + host, rp)

            cookie = http.cookies.SimpleCookie(self.headers.get('Cookie'))
            if 'challenge_id' in cookie and cookie['challenge_id'].value in REGISTRATION_CHALLENGE_MANAGER:
              challenge = REGISTRATION_CHALLENGE_MANAGER.pop(cookie['challenge_id'].value)
              auth_data = server.register_complete(challenge, client_data, attestation_object)
              external_id = post_data["externalId"][0]
              file_name = post_data['username'][0] + "_" + post_data['tokenName'][0]
              if external_id != '':
                file_name = external_id + '.' + file_name
              with open(REGISTRATION_DIR + "/" + file_name, 'wb') as f:
                f.write(auth_data.credential_data)
              send_registration_mail_to_admin(post_data['username'][0], post_data['tokenName'][0], post_data['name'][0], post_data['phone'][0], post_data['email'][0], post_data['externalId'][0], file_name)
              self.send_response(200)
              self.send_header('Content-type', 'text/html')
              self.end_headers()
              self.wfile.write(bytes(f"<head><link rel='stylesheet' href='style.css'></head><body><div class='form'><div class='success'>Success</div><div style='padding-top: 1em'><a href='{HTTP_PREFIX + '/login'}'>Login</div></div></body>", 'UTF-8'))
              return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes("<head><link rel='stylesheet' href='style.css'></head></body><div class='form'><div class='error'>Error</div></div></body>", 'UTF-8'))
            return

        if self.path == HTTP_PREFIX + "/register":
          self.send_response(401)
          self.send_header('Content-type', 'application/json')
          self.end_headers()
          self.wfile.write(bytes(json.dumps({'error': 'not_configured'}), 'UTF-8'))
          return

        creds = []
        files=glob.glob(CREDENTIALS_DIR + "/*")
        for file in files:
            public_key = ""
            with open(file, 'rb') as f:
                cred, _ = AttestedCredentialData.unpack_from(f.read())
                # TODO add more public-keys which must be stored in AttestedCredentialData
                creds.append(cred)
                auth_data, state =server.authenticate_begin([cred])
                public_key = str(base64.b64encode(auth_data["publicKey"]["allowCredentials"][0]["id"]))[2:-1]
            header_file = HEADERS_DIR + "/" + file.split("/")[-1]
            if os.path.exists(header_file):
                with open(header_file, 'r') as f:
                    HEADER_MANAGER[public_key] = ["Fido-User", "\t".join(f.read().splitlines())]


        if self.path == HTTP_PREFIX + "/get_challenge_for_existing_key":
            auth_data, state = server.authenticate_begin(creds)
            auth_data["publicKey"]["challenge"] = str(base64.b64encode(auth_data["publicKey"]["challenge"]), 'utf-8')
            for el in auth_data["publicKey"]["allowCredentials"]:
                el["id"] = str(base64.b64encode(el["id"]), 'utf-8')
            #auth_data["publicKey"]["allowCredentials"][0]["id"] = str(base64.b64encode(auth_data["publicKey"]["allowCredentials"][0]["id"]), 'utf-8')

            self.send_response(200)

            if ALLOW_PREREGISTRATION:
              cookie = http.cookies.SimpleCookie()
              challenge_id = "".join(str(randint(1,9)) for _ in range(100))
              cookie["challenge_id"] = challenge_id
              LOGIN_CHALLENGE_MANAGER[challenge_id] = state
              self.send_header('Set-Cookie', cookie.output(header=''))
            else:
              CHALLENGE.update(state)

            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(json.dumps(auth_data), 'UTF-8'))

        if self.path == HTTP_PREFIX + "/complete_challenge_for_existing_key":
            data = json.loads(self.rfile.read(int(self.headers.get('Content-Length'))))

            credential_id = base64.b64decode(data['id'])
            client_data = ClientData(base64.b64decode(data['clientDataJSON']))
            auth_data = AuthenticatorData(base64.b64decode(data['authenticatorData']))
            signature = base64.b64decode(data['signature'])

            if ALLOW_PREREGISTRATION:
              cookie = http.cookies.SimpleCookie(self.headers.get('Cookie'))
              if 'challenge_id' in cookie and cookie['challenge_id'].value in LOGIN_CHALLENGE_MANAGER:
                challenge = LOGIN_CHALLENGE_MANAGER.pop(cookie['challenge_id'].value)
              else:
                self.send_response(401)
                self.end_headers()
                return
            else:
              challenge = CHALLENGE

            server.authenticate_complete(
              challenge,
              creds,
              credential_id,
              client_data,
              auth_data,
              signature
            )

            cookie = http.cookies.SimpleCookie()
            header = HEADER_MANAGER.get(data['id'], ["", ""])
            token = TOKEN_MANAGER.generate()
            cookie["token"] = token
            TOKEN_MANAGER.set_header(token, header)
            cookie["token"]["path"] = "/"
            cookie["token"]["secure"] = True

            self.send_response(200)
            self.send_header('Set-Cookie', cookie.output(header=''))
            if header != 0:
                self.send_header(header[0], header[1])
            self.end_headers()
            self.wfile.write(bytes(json.dumps({'status': 'ok'}), 'UTF-8'))

if len(sys.argv) > 1 and sys.argv[1] == "save-client":
    host = sys.argv[2]
    client_data = ClientData(base64.b64decode(sys.argv[3]))
    attestation_object = AttestationObject(base64.b64decode(sys.argv[4]))

    rp = RelyingParty(host, 'NGINX Auth Server')
    server = U2FFido2Server('https://' + host, rp)

    with open(LASTCHALLENGE) as f:
        auth_data = server.register_complete(json.loads(f.read()), client_data, attestation_object)
        with open(CREDENTIALS_DIR + "/" + sys.argv[5], 'wb') as f:
            f.write(auth_data.credential_data)

    print("Credentials saved successfully")

else:
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("", PORT), AuthHandler)
    try:
        print("serving at port", PORT)
        httpd.serve_forever()
    finally:
        httpd.server_close()
