import logging, gzip, shutil, re, json
from os import path, getcwd
from glob import glob


log = logging.getLogger()

regex = r"^([a-zA-Z0-9-]+)[.]{1}([a-zA-Z0-9-]+)[.]{1}\s(\d{0,32})\sin\sns\s([a-zA-Z0-9-\.]+).$"

fq_path = path.join(path.realpath(getcwd()), 'zonefiles')

for filepath in glob('%s/*.txt' % fq_path):
  filename = ''.join(filepath.split('/')[-1:])
  print ('filename %s' % filename)
  o = {}
  for line in open(filepath,'r').readlines():
    matches = re.finditer(regex, line, re.MULTILINE)
    for match in matches:
      domain = match.group(1)
      tld = match.group(2)
      fqdn = '.'.join([domain, tld])
      if fqdn not in o:
        o[fqdn] = {
          'domain': domain,
          'tld': tld,
          'ns': []
        }
      if 'ns' not in o[fqdn]:
        o[fqdn]['ns'] = []
      o[fqdn]['ns'].append({
        'ttl': match.group(3),
        'ns': match.group(4)
      })

  for n, d in o.items():
    print (n)
    for ns in d['ns']:
      print ('NS {ns} ttl {ttl}'.format(**ns))
