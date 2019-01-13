#!/usr/bin/env python
# -*- coding:utf-8
import re, logging, gzip, shutil, requests, sys, json, colorlog, argparse, mysql.connector
from os import path, getcwd, makedirs, isatty
from glob import glob
from urlparse import urlparse
from mysql.connector import errorcode
from yaml import load, dump
from datetime import datetime


config = None

def sanitize(filter):
  return filter


def get_from_model(table_name, key, default=None):
  model_file = path.join(path.realpath(getcwd()), 'model', '%s.yaml' % table_name)
  with open(model_file, 'r') as f:
    schema = load(f.read())

  return schema.get(key, default)


def sql(query):
  log = logging.getLogger()
  c = get_config()
  rows = None
  cnx = None
  try:
    cnx = mysql.connector.connect(
      user=c['mysql'].get('user'),
      password=c['mysql'].get('passwd', ''),
      host=c['mysql'].get('host', 'localhost'),
      port=c['mysql'].get('port', 3306),
      database=c['mysql'].get('db')
    )
    cursor = cnx.cursor()
    cursor.execute(query)
    if query.startswith('SELECT'):
      rows = cursor.fetchall()
    else:
      cnx.commit()
      rows = cursor.lastrowid
    cursor.close()
  except mysql.connector.Error as err:
    if cnx:
      cnx.rollback()
    if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
      log.critical("Something is wrong with your user name or password")
      exit(1)
    elif err.errno == errorcode.ER_BAD_DB_ERROR:
      log.critical("Database does not exist")
      exit(1)
    else:
      log.critical(err)
      log.info(query)
      exit(1)

  if cnx:
    cnx.close()

  return rows


def upsert_into(table, inserts):
  model = get_from_model(table, 'field')
  params = []
  cols = []
  updates = []
  values = []
  if type(inserts) == dict:
    old = inserts
    inserts = [old]
  for i_values in inserts:
    i_params = {}
    val_list = []

    for field, schema in model.items():
      if field in [i for i in i_values]:
        if schema['type'] == 'datetime':
          i_params[field] = datetime.strptime(i_values[field], '%Y-%m-%d %H:%M:%S')
        elif isinstance(i_values[field], eval(schema['type'])):
          i_params[field] = i_values[field]
        else:
          i_params[field] = eval(schema['type'] + "('" + str(i_values[field]) + "')")
        continue

      elif 'default' in schema:
        i_params[field] = schema['default']
        continue

      elif 'nullable' in schema and not schema['nullable']:
        raise ValueError('%s not of type %s, no default, and not nullable' % (
          field, schema['type']
        ))

    for k,v in i_params.items():
      if model[k]['type'] == 'str':
        val_list.append("'"+v+"'")
      elif not v:
        val_list.append('NULL')
      else:
        val_list.append(str(v))
    params.append(i_params)
    values.append(','.join(val_list))

  if params:
    for i,key in enumerate(params[0]):
      cols.append('`{}`'.format(key))
    for i,key in enumerate(i_values):
      updates.append('`{col}`=VALUES(`{col}`)'.format(col=key))

  query = """
    INSERT INTO {table} ({fields}) VALUES {values}
    ON DUPLICATE KEY UPDATE {updates}
  """.format(
    table=get_from_model(table, 'table', table),
    fields=','.join(cols),
    updates=','.join(updates),
    values='('+'),('.join(values)+')'
  )
  return sql(query)

def select_from(table, filter=None):
  f = get_from_model(table, 'field')
  field_names = '`'+'`,`'.join([i for i in f])+'`'
  query = ("SELECT {fields} FROM {table} {where}".format(
    fields=field_names,
    table=get_from_model(table, 'table', table),
    where='' if not filter else 'WHERE %s' % sanitize(filter)
  ))

  return sql(query)


def get_config(config_file=None):
  global config

  if not config:
    if not config_file:
      config_file = path.join(path.realpath(getcwd()), 'config.yaml')
    with open(config_file, 'r') as f:
      config = load(f.read())

  return config


session = requests.Session()


def main(config_file):
  global session
  c = get_config()
  regex = r"^([a-zA-Z0-9-]+)[.]{1}([a-zA-Z0-9-]+)[.]{1}\s+(\d+)\s+in\s+ns\s+([a-zA-Z0-9-\.]+).$"
  log = logging.getLogger()
  base_dir = 'zonefiles'
  if not path.exists(base_dir):
    makedirs(base_dir)

  if 'czdap' not in c or not c['czdap'].get('token'):
    log.critical("'token' parameter not found in the %s file" % config_file)
    exit(1)
  if 'czdap' not in c or not c['czdap'].get('base_url'):
    log.critical("'base_url' parameter not found in the %s file" % config_file)
    exit(1)

  # Get all the files that need to be downloaded using CZDAP API.
  r = session.get(c['czdap']['base_url'] + '/en/user-zone-data-urls.json?token=' + c['czdap']['token'])
  if r.status_code != 200:
    log.critical("Unexpected response from CZDAP. Are you sure your token and base_url are correct in %s?" % config_file)
    exit(1)
  try:
    urls = json.loads(r.text)
  except:
    log.critical("Unable to parse JSON returned from CZDAP.")
    exit(1)

  proj_root = path.realpath(getcwd())
  fq_path = path.join(proj_root, base_dir)
  files = []

  for filepath in glob('%s/*.txt.gz' % fq_path):
    filename = ''.join(filepath.split('/')[-1:])
    files.append(filename)

  # unique list
  urls = list(set(urls))
  for uri in urls:
    log_inserts = []
    url = c['czdap']['base_url'] + uri
    czdap_id = int(''.join(''.join(uri.split('?')[:-1]).split('/')[-1:]))
    dest_file, file_size = get_remote_stat(url)
   
    if not dest_file:
      log.warning('Skipping %s' % uri)
      continue

    if dest_file in files:
      local_file_path = path.join(fq_path, dest_file)
      local_size = path.getsize(local_file_path)
      if local_size == file_size:
        log.info("Local file exists: %s" % dest_file)
        continue
      else:
        log.info("Refreshing file: %s" % dest_file)
    
    dest_path = path.join(fq_path, dest_file)
    download(url, dest_path)
    decompress(dest_path)
    log.info("Done %s" % dest_file)
    plaintext_file = dest_path.replace('.gz', '', 1)
    for line in open(plaintext_file, 'r').readlines():
      o = {}
      log.debug(line)
      matches = re.finditer(regex, line, re.MULTILINE)
      # num = sum(1 for _ in re.finditer(regex, line, re.MULTILINE))
      # if num == 0:
      #   print('%s' % line)
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
        for ns in o['ns']:
          log_inserts.append({
            'domain': domain,
            'tld': tld,
            'fqdn': fqdn,
            'local_file': dest_file,
            'czdap_id': czdap_id,
            'nameserver': ns['ns'],
            'ttl': ns['ttl']
          })
    # commit per file
    if log_inserts:
      log.info('%d array items' % len(log_inserts))
      n = 1000
      final = [log_inserts[i * n:(i + 1) * n] for i in range((len(log_inserts) + n - 1) // n )]  
      for upserts in final:
        upsert_into('scan_log', upserts)
    # upsert_into('scan_log', log_inserts)
  exit(0)


def get_remote_stat(url):
  global session
  log = logging.getLogger()

  r = session.head(url)
  if r.status_code != 200:
    log.error("Unexpected HTTP response code %d for URL %s" % (r.status_code, url))
    return None, None
  dest_file = r.headers['Content-disposition'].replace('attachment; filename=', '').replace('"', '', 2)
  file_size = int(r.headers['Content-Length'])

  return dest_file, file_size


def download(url, dest_path):
  global session
  log = logging.getLogger()
  r = session.get(url)
  if r.status_code != 200:
    log.error("Unexpected HTTP response code %d for URL %s" % (r.status_code, url))
    return

  log.debug("saving as %s" % dest_path)
  with open(dest_path, 'wb') as f:
    for chunk in r.iter_content(1024):
      f.write(chunk)


def decompress(file_path):
  log = logging.getLogger()
  with gzip.open(file_path, 'rb') as f_in:
    new_dest = file_path.replace('.gz', '', 1)
    log.debug("decompressing to %s" % new_dest)
    with open(new_dest, 'wb') as f_out:
      shutil.copyfileobj(f_in, f_out)


def setup_logging(log_level):
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

  if log_level > 0:
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    log.addHandler(stream_handler)
  if log_level == 1:
    log.setLevel(logging.CRITICAL)
  if log_level == 2:
    log.setLevel(logging.ERROR)
  if log_level == 3:
    log.setLevel(logging.WARN)
  if log_level == 4:
    log.setLevel(logging.INFO)
  if log_level >= 5:
    log.setLevel(logging.DEBUG)

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='open net scans')
  parser.add_argument('-c', '--config_file', default='config.yaml', help='absolute path to config file')
  parser.add_argument('-v', action='store_true')
  parser.add_argument('-vv', action='store_true')
  parser.add_argument('-vvv', action='store_true')
  parser.add_argument('-vvvv', action='store_true')
  parser.add_argument('-vvvvv', action='store_true')
  args = parser.parse_args()
  log_level = 4
  if args.v:
    log_level = 1
  elif args.vv:
    log_level = 2
  elif args.vvv:
    log_level = 3
  elif args.vvvv:
    log_level = 4
  elif args.vvvvv:
    log_level = 5

  setup_logging(log_level)
  main(config_file=args.config_file)
