#!/usr/bin/env python
# -*- coding:utf-8

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from yaml import load
from os import path, getcwd
import requests
import json
import base64
import sys

# Create a session
s = requests.Session()

# Load the config file and validate.
try:
  config_file = path.join(path.realpath(getcwd()), 'config.yaml')
  with open(config_file, 'r') as f:
    config = load(f.read())

except:
  sys.stderr.write("Error loading config.json file.\n")
  exit(1)
if 'token' not in config['czdap']:
  sys.stderr.write("'token' parameter not found in the config.json file\n")
  exit(1)
if 'base_url' not in config['czdap']:
  sys.stderr.write("'base_url' parameter not found in the config.json file\n")
  exit(1)

# Load the private key.
try:
  privateKeyFile = open("czdap.private.key", "r")
  key = RSA.importKey(privateKeyFile.read())
  cipher = PKCS1_v1_5.new(key)
  privateKeyFile.close()
except:
  sys.stderr.write("Error loading private key from file 'czdap.private.key'. Please copy your key into this directory.\n")
  exit(1)

# Get the credentials JSON from CZDAP API.
r = s.get(config['czdap']['base_url'] + '/user-credentials.json?token=' + config['czdap']['token'])
if r.status_code != 200:
  sys.stderr.write("Unexpected response from CZDAP. Are you sure your token and base_url are correct in config.json?\n")
  exit(1)
try:
  credsData = json.loads(r.text)
  with open('credentials.json', 'w') as f:
    f.write(r.text)
except:
  sys.stderr.write("Unable to parse JSON returned from CZDAP.\n")
  exit(1)

# Decrypt and output.
print('server,username,password')
for creds in credsData:
  piecesJSON = cipher.decrypt(base64.b64decode(creds['credentials']), 0)
  if not piecesJSON:
    sys.stderr.write("Error: Decryption failed, do you have the correct keyfile?\n")
    exit(1)
  pieces = json.loads(piecesJSON)
  username = unicode(base64.b64decode(pieces[0]), "utf-8")
  password = unicode(base64.b64decode(pieces[1]), "utf-8")
  print(",".join([creds['host'],username,password]))
