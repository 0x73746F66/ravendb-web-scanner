Open net scans
===========

Goals
------------

* Get a list of all registered domains using zonefiles
* Check for https
    * Use the cert to learn about subdomains
* Use OSINT tools to learn as much as we can about all the domains we find

Important Information
------------

Some registries allow users to download zone data directly from CZDAP, and others provide FTP credentials that you can use to login to their servers. 

Before using this repo you need to acquire credentials for:

* zonefile data using the CZDAP API
* FTP credentials for unsupported CZDAP domains (com, name)

Installation
------------

This script requires Python 3.7

`pip install -r requirements.txt` for the extension libraries.

First steps
---------------------

1. Acquire credentials

2. Make a copy of the `config.sample.yaml` file and name it `config.yaml`.

3. Edit config.yaml and overwrite the _sample_ parameters with the your unique token.

4. Acquire a license for ravendb and run ravendb, a sample `ravendb-docker.sh` is there for convenience

Running
---------------------

In the src folder you will find `process_*.py` and `gather_*.py` files that are run simply using the python interpreter and reads inputs from your config.yaml