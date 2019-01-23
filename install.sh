#!/usr/bin/env bash
apt-get download python-dnspython
dpkg -x python-dnspython_1.15.0-1_all.deb ./dnspython
mv dnspython/usr/lib/python2.7/dist-packages/dns venv/lib/python2.7/site-packages/
mv dnspython/usr/lib/python2.7/dist-packages/dnspython-1.15.0.egg-info venv/lib/python2.7/site-packages/