#!/usr/bin/env python3

import os
import sys
import shutil
from pathlib import Path

user = sys.argv[1]
group = sys.argv[2]

print("creating directroy structure")
Path("/opt/nginxwebauthn/credentials").mkdir(parents=True, exist_ok=True)
Path("/opt/nginxwebauthn/registrations").mkdir(parents=True, exist_ok=True)
Path("/opt/nginxwebauthn/headers").mkdir(parents=True, exist_ok=True)

shutil.chown("/opt/nginxwebauthn/registrations", user=user, group=group)

config_contents = """
[Global]
# after succesful token registration a form is displayed where user can fill in the token name and their personal information
# the token is then stored in /opt/nginxwebauthn/registrations
AllowPreregistration = false

# if FromEmail and AdminEmail are configured the user personal information is sent to the AdminEmail requires running SMTP server (like postfix) on localhost:25
#FromEmail = root@localhost
#AdminEmail = root@localhost
"""

if not os.path.exists("/etc/nginxwebauthn.conf"):
  with open("/etc/nginxwebauthn.conf", 'w') as f:
    f.write(config_contents)

script_path = os.path.realpath(__file__).replace("/nginxwebauthn-ubuntu-install.py", "/nginxwebauthn.py")

systemd_contents = """
[Unit]
Description=Python NGINX Webauthn

[Service]
Type=simple
User=%s
Group=%s
ExecStart="%s"
StandardOutput=/var/log/nginxwebauthn.log
StandardError=/var/log/nginxwebauthn.err.log
Restart=always

[Install]
WantedBy=multi-user.target
"""

print("creating systemd service file")
with open('/lib/systemd/system/nginxwebauthn.service', 'w') as f:
    f.write(systemd_contents % (user, group, script_path))

print("running systemctl commands")
os.system("systemctl daemon-reload")
os.system("systemctl enable nginxwebauthn.service")
os.system("systemctl start nginxwebauthn.service")

