Open net scans
===========

Goals
------------

* Get a list of all registered domains
* Check for https
    * Use the cert to learn about subdomains
* Use OSINT tools to learn as much as we can about all the domains we find

Important Information
------------

Some registries allow users to download zone data directly from CZDAP, and others provide FTP credentials that you can use to login to their servers. These tools allow you to programmatically perform these two tasks:

* Download zone data directly using the CZDAP API.
* Decrypt FTP credentials downloaded from ICANN's CZDAP application.

Installation
------------

This script requires Python 2.x

`pip install -r requirements.txt` for the extension libraries.

Downloading zone data from CZDAP
---------------------

1. Visit CZDAP and copy your token. You can find it on your user profile page.

2. Make a copy of the `config.sample.yaml` file and name it `config.yaml`.

3. Edit config.yaml and overwrite the "token" parameter with the your unique token.

4. Run `python download.py`

Decrypting FTP credentials
----------------------

To decrypt your own FTP credentials:

1. Visit CZDAP and copy your token. You can find it on your user profile page, under the tab "API".

2. Make a copy of the `config.sample.yaml` file and name it `config.yaml`.

3. Edit config.yaml and overwrite the "token" parameter with the your unique token.

2. Copy your private key into this directory and make sure it's named `czdap.private.key`.

4. Run `python decrypt.py`.
