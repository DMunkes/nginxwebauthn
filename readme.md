# NGINX + WebAuthn for your small scale web applications

## What is this for?

If you run some small services on a public-facing server that you would like to protect (i.e. Jupyter of VS code-server) and have a Yubikey or similar, you can use this repository to add secure, public-key authentication to them **without modifying the original service itself**.

## How to set up?

Run `nginx -V` and check it is compiled with `auth_request_module` otherwise recompile it with `--with-http_auth_request_module` configuration parameter. Then set up NGINX to proxy your service, note that you will also need SSL because WebAuthn only works over HTTPS.

```
server {
    server_name myserver.bennewhouse.com; # managed by Certbot

    # Redirect everything that begins with /auth to the authorization server
    location /nginx_fido_auth {
        proxy_pass http://127.0.0.1:8000;
    }

    # If the authorization server returns 401 Unauthorized, redirect to /atuh/login
    error_page 401 = @error401;
    location @error401 {
        return 302 /nginx_fido_auth/login$request_uri;
    }

    root /var/www/html;
    index index.html;
    location / {
        auth_request /nginx_fido_auth/check; # Ping /auth/check for every request, and if it returns 200 OK grant access
        # The next two lines are ptional config for authentication header needed by your application.
        # Replace X-SSL-CERT with any header your application expects to carry the user ID.
        auth_request_set $fido $upstream_http_fido_user;
        passenger_set_header 'X-SSL-CERT' $fido;

        # Here is where you would put other proxy_pass info to forward to Jupyter, etc. In this example I'm just serving raw HTML
    }

    # Override the application logout url with the fido auth logout url. Replace /users/logout with url where your application logout button points to.
    location /users/logout {
        return 302 /nginx_fido_auth/logout
    }

    listen [::]:443 ssl ; # managed by Certbot
    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/myserver.bennewhouse.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/myserver.bennewhouse.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
}
```

Reload NGINX with the aforementioned configuration. Next install the nginxwebauthn Python package as root -- dependencies needs to be installed globally to be able to add user credentials later. Other option is to change privileges to `/opt/nginxwebauthn` to be able to write there by regular user which may be a security flaw. Install script takes two arguments -- user and group for the script to be started as.  

```
sudo su
pip3 install nginxwebauthn-jv
nginxwebauthn-ubuntu-install.py user group
```

If `nginxwebauthn-ubuntu-install.py` fails for any reason you can try to replicate steps in ``cat `which nginxwebauthn-install.py` ``. Basically it creates a directory structure in `/opt/nginxwebauthn` and configures systemd service to run the `nginxwebauthn.py` script as a daemon.

## How to use?

Browse to your site with appended `/nginx_fido_auth/register` in a browser that supports WebAuthn. Insert your security key when requested, and the page will tell you to run a command that looks like:

```
sudo python3 nginx-webauthn.py save-client myserver.bennewhouse.com *big long base64 string* *big long base64 string* auth_name
```

Replace `auth_name` with something unique that will help you identify the credential and run that on the server. You only need to do this once per key. The credentials are stored in `/opt/nginxwebauthn/credentials/auth_name`. If you set up your NGINX to expect the HTTP header to distinguish the authenticated user put the header contents to `/opt/nginxwebauthn/headers/auth_name`. The header file is paired with credential file by file name. `\n` characters in headers are replaced with `\t` and sent back to the NGINX server.

That's it! Navigating back to your website will now authenticate you using the key you just saved.

## How to build pip package

```
sudo python3 -m pip install --upgrade pip setuptools wheel
sudo -H pip3 install keyring
git clone https://github.com/jan-vitek/nginxwebauthn
cd nginxwebauthn
python3 setup.py bdist_wheel
```

Then you can distribute the `.whl` file from `dist` to your server and install it with `pip3 install nginxwebauthn_jv-*.whl`. Or if you are registered to PyPI.org you can upload the package this way:
```
cat << EOF > ~/.pypirc
[distutils] 
index-servers=pypi
[pypi] 
repository = https://upload.pypi.org/legacy/ 
username = your_pypi_username
EOF

python -m twine upload dist/*
```

## Limitations

- This uses the built-in python3 server, which isn't designed for high-volume. You'd want to port this to a uwsgi setup if you wanted to productionize it.

## FAQ

*Why do I need to run the `save-client` command?*

This seemed easier than setting up a potentially insecure password so that you could authorize your key. Instead it asserts that you have shell access by requiring that you run a command.
