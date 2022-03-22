import setuptools
with open("readme.md", "r") as fh:
    long_description = fh.read()
setuptools.setup(
     name='nginxwebauthn-jv',  
     version='0.1.4',
     scripts=['nginxwebauthn.py', 'nginxwebauthn-ubuntu-install.py'] ,
     author="Jan Vitek",
     author_email="mail@janvitek.com",
     description="WebAuthn auth proxy for NGINX. Fork of github.com/newhouseb/nginxwebauthn with multi user capabilities and HTTP header user identification.",
     long_description=long_description,
     long_description_content_type="text/markdown",
     url="https://github.com/jan-vite/nginxwebauthn",
     packages=setuptools.find_packages(),
     install_requires=['fido2==0.6.0'],
     classifiers=[
         "Programming Language :: Python :: 3",
         "Operating System :: OS Independent",
     ],
 )
