#!/usr/bin/env python
import logging, gzip, shutil, re, json, colorlog
from os import path, getcwd, isatty
from glob import glob


log = logging.getLogger()
format_str = '%(asctime)s - %(levelname)-8s - %(message)s'
date_format = '%Y-%m-%d %H:%M:%S'
if isatty(2):
  cformat = '%(log_color)s' + format_str
  colors = {'DEBUG': 'reset',
            'INFO': 'bold_blue',
            'WARNING': 'bold_yellow',
            'ERROR': 'bold_red',
            'CRITICAL': 'bold_red'}
  formatter = colorlog.ColoredFormatter(cformat, date_format, log_colors=colors)
else:
  formatter = logging.Formatter(format_str, date_format)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
log.addHandler(stream_handler)
log.setLevel(logging.DEBUG)

regex = r"^([a-zA-Z0-9-]+)[.]{1}([a-zA-Z0-9-]+)[.]{1}\s(\d{0,32})\sin\sns\s([a-zA-Z0-9-\.]+).$"

fq_path = path.join(path.realpath(getcwd()), 'zonefiles')

for filepath in glob('%s/*.txt' % fq_path):
  filename = ''.join(filepath.split('/')[-1:])
  log.info('filename %s' % filename)
  for line in open(filepath,'r').readlines():
    o = {}
    log.debug(line)
    matches = re.finditer(regex, line, re.MULTILINE)
    fqdn = None
    for match in matches:
      domain = match.group(1)
      tld = match.group(2)
      if not fqdn:
        fqdn = '.'.join([domain, tld])

      o['domain'] = domain
      o['tld'] = tld
      o['ns'] = []
      o['ns'].append({
        'ttl': match.group(3),
        'ns': match.group(4)
      })
    if fqdn:
      log.info(fqdn)
      for ns in o['ns']:
        log.info('NS {ns} ttl {ttl}'.format(**ns))
