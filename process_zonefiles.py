#!/usr/bin/env python
# -*- coding:utf-8
import re, logging, gzip, shutil, requests, sys, json, colorlog, argparse, mysql.connector, shelve
import OpenSSL, ssl, socket
from os import path, getcwd, makedirs, isatty
from glob import glob
from urlparse import urljoin, urlparse
from mysql.connector import errorcode
from yaml import load
from datetime import datetime
from bitmath import Byte


config = None
session = None

def sanitize(filter):
  """ TODO
  SQLi protection
  """
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
    log.debug('Creating database connection')
    cnx = mysql.connector.connect(
      user=c['mysql'].get('user'),
      password=c['mysql'].get('passwd', ''),
      host=c['mysql'].get('host', 'localhost'),
      port=c['mysql'].get('port', 3306),
      database=c['mysql'].get('db')
    )
    cursor = cnx.cursor()
    log.debug('Executing query\n%s' % query)
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
      log.warning('Closing database connection after exception')
      cnx.close()
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
    log.debug('Closing database connection')
    cnx.close()

  return rows

def upsert_into(table, inserts):
  log = logging.getLogger()
  model = get_from_model(table, 'field')
  params = []
  cols = []
  updates = []
  values = []
  if type(inserts) == dict:
    old = inserts
    inserts = [old]
  log.debug('building upsert sql for %d records' % len(inserts))
  for i_values in inserts:
    i_params = {}
    val_list = []

    for field, schema in model.items():
      if field in [i for i in i_values]:
        if schema['type'] == 'datetime':
          if isinstance(i_values[field], str):
            i_params[field] = i_values[field]
          else:
            i_params[field] = i_values[field].strftime('%Y-%m-%d %H:%M:%S')
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
      if model[k]['type'] in ['str', 'datetime']:
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

def get_session():
  global session

  if not session:
    session = requests.Session()

  return session

def get_remote_stat(url):
  session = get_session()
  log = logging.getLogger()

  r = session.head(url)
  if r.status_code != 200:
    log.error("Unexpected HTTP response code %d for URL %s" % (r.status_code, url))
    return None, None
  dest_file = r.headers['Content-disposition'].replace('attachment; filename=', '').replace('"', '', 2)
  file_size = int(r.headers['Content-Length'])

  return dest_file, file_size

def download(url, dest_path):
  session = get_session()
  log = logging.getLogger()
  r = session.get(url, stream=True)
  r.raw.decode_content = True
  if r.status_code != 200:
    log.error("Unexpected HTTP response code %d for URL %s" % (r.status_code, url))
    return

  with open(dest_path, 'wb') as f:
    shutil.copyfileobj(r.raw, f)

  return dest_path

def decompress(file_path):
  new_dest = file_path.replace('.gz', '', 1)
  with gzip.open(file_path, 'rb') as f_in:
    with open(new_dest, 'wb') as f_out:
      shutil.copyfileobj(f_in, f_out)
  return new_dest

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

def download_zonefile_list(base_url, token):
  session = get_session()
  log = logging.getLogger()
  # Get all the files that need to be downloaded using CZDAP API.
  r = session.get(base_url + '/en/user-zone-data-urls.json?token=' + token)
  if r.status_code != 200:
    log.critical("Unexpected response from CZDAP. Are you sure your token and base_url are correct in your config_file?")
    exit(1)
  try:
    urls = json.loads(r.text)
  except:
    log.critical("Unable to parse JSON returned from CZDAP.")
    exit(1)

  return list(set(urls))

def get_local_files(dest_dir):
  files = []
  for filepath in glob('%s/*.txt.gz' % dest_dir):
    filename = ''.join(filepath.split('/')[-1:])
    files.append(filename)

  return files

def absolute_path(path_in):
  path_out = path_in
  proj_root = path.realpath(getcwd())
  if path_in.startswith('./'):
    path_out = path.join(proj_root, path_in.replace('./', ''))
  elif not path_in.startswith('/'):
    path_out = path.join(proj_root, path_in)

  return path_out

def collect_remote_files():
  c = get_config()
  log = logging.getLogger()
  files = set()

  zonefile_dir = absolute_path(c.get('zonefile_dir'))
  if not path.exists(zonefile_dir):
    makedirs(zonefile_dir)

  if 'czdap' not in c or not c['czdap'].get('token'):
    log.critical("'token' parameter not found in the config file")
    exit(1)
  if 'czdap' not in c or not c['czdap'].get('base_url'):
    log.critical("'base_url' parameter not found in the config file")
    exit(1)

  urls = download_zonefile_list(base_url=c['czdap']['base_url'], token=c['czdap']['token'])
  log.info("caching remote zonefiles")

  cache_path = c['records'].get('cache_path')
  if not cache_path:
    log.critical('cache_path was missing from the config')
    exit(1)
  cache = shelve.open(cache_path)
  try:
    for full_uri in urls:
      now = datetime.utcnow().replace(microsecond=0)
      uri = urljoin(full_uri, urlparse(full_uri).path)
      key = str(uri.replace('/', ''))
      if cache.has_key(key):
        obj = json.loads(cache[key])
        last_cached = datetime.strptime(obj['cached'], '%Y-%m-%dT%H:%M:%S')
        delta = now - last_cached
        if delta.days == 0:
          log.info("%s is already in cache for today" % uri)
          files.add(path.join(zonefile_dir, obj['file']))
          continue
      obj = cache_remote(uri)
      if obj:
        czdap_id = int(''.join(uri.split('/')[-1:]))
        pieces = obj['file'].split('-')[1:]
        pieces.insert(0, str(czdap_id))
        dest_file = '-'.join(pieces)
        cache[key] = json.dumps({
          'cached': now.isoformat(),
          'file': dest_file
        })
        files.add(path.join(zonefile_dir, dest_file))

  finally:
    cache.close()

  return list(files)

def cache_remote(uri):
  c = get_config()
  log = logging.getLogger()
  url = c['czdap']['base_url'] + uri + '?token=' + c['czdap'].get('token')
  czdap_id = int(''.join(uri.split('/')[-1:]))
  remote_file, file_size = get_remote_stat(url)
  if not remote_file:
    log.warning('Cannot cache %s' % uri)
    return

  pieces = remote_file.split('-')[1:]
  pieces.insert(0, str(czdap_id))
  key = '-'.join(pieces)
  obj = {
    'id': czdap_id,
    'size': file_size,
    'file': remote_file,
    'uri': uri
  }
  cache_path = c['records'].get('cache_path')
  if not cache_path:
    log.critical('cache_path was missing from the config')
    exit(1)
  cache = shelve.open(cache_path)
  try:
    cache[key] = json.dumps(obj)
  finally:
    cache.close()
  return obj

def extract_new_domains(zonefile_path):
  c = get_config()
  log = logging.getLogger()

  if not path.isfile(zonefile_path):
    log.error('missing zonefile %s' % zonefile_path)
    return

  mysql_data = []
  zonefile = ''.join(zonefile_path.split('/')[-1:])
  default_regex = r"^([a-zA-Z0-9-]+)[.]{1}([a-zA-Z0-9-]+)[.]{1}\s+(\d+)\s+in\s+ns\s+([a-zA-Z0-9-\.]+).$"
  regex = c['records'].get('regex')
  if not regex:
    regex = default_regex

  force_persist = c.get('force_persist', False)
  stale_days = int(c['records'].get('stale_days', 0))
  cache_path = c['records'].get('cache_path')
  if not cache_path:
    log.critical('cache_path was missing from the config')
    exit(1)

  num_lines = 0
  num_matches = 0
  cache = shelve.open(cache_path)
  cache_key = str(zonefile + '.gz')
  try:
    if not cache.has_key(cache_key):
      czdap_id = ''.join(zonefile_path.split('/')[-1:]).split('-')[0]
      uri = path.join(c['czdap'].get('zone_file_uri'), czdap_id)
      cached = cache_remote(uri)
      if not cached:
        return

    remote = json.loads(cache[cache_key])
    czdap_id = int(remote['id'])
    scanned_time = datetime.utcnow().replace(microsecond=0)
    for line in open(zonefile_path, 'r').readlines():
      log.debug(line)
      num_lines += 1
      num = sum(1 for _ in re.finditer(regex, line, re.MULTILINE))
      if num == 0:
        log.debug('No match found for line\n%s' % line)
        continue

      num_matches += 1
      domain, tld, ttl, ns = re.search(regex, line).groups()
      fqdn = str('.'.join([domain, tld]))
      last_scanned = False
      
      if force_persist:
        log.debug('Forced queue for persistance %s' % fqdn)
        mysql_data.append({
          'domain': domain,
          'tld': tld,
          'fqdn': fqdn,
          'local_file': zonefile,
          'remote_file': remote['uri'],
          'czdap_id': czdap_id,
          'nameserver': ns,
          'ttl': ttl,
          'scanned': scanned_time.strftime('%Y-%m-%d %H:%M:%S')
        })
        continue

      if cache.has_key(fqdn):
        log.debug('cache hit')
        last_scanned = datetime.strptime(cache[fqdn], '%Y-%m-%dT%H:%M:%S')
        delta = scanned_time - last_scanned
      else:
        log.debug('cache miss')
        cache[fqdn] = scanned_time.isoformat()
        
      if not last_scanned or delta.days >= stale_days:
        log.debug('%s queue for persistance' % fqdn)
        mysql_data.append({
          'domain': domain,
          'tld': tld,
          'fqdn': fqdn,
          'local_file': zonefile,
          'remote_file': remote['uri'],
          'czdap_id': czdap_id,
          'nameserver': ns,
          'ttl': ttl,
          'scanned': scanned_time.strftime('%Y-%m-%d %H:%M:%S')
        })
      else:
        log.debug('Skipping %s persistance' % fqdn)
  finally:
    cache.close()

  log.info('Matched %d of %d domains' % (num_matches, num_lines))

  return mysql_data

def check_files():
  c = get_config()
  log = logging.getLogger()

  force_download = c.get('force_download', False)
  zonefile_dir = absolute_path(c.get('zonefile_dir'))
  to_download = collect_remote_files()

  if not to_download:
    log.info('nothing to download')
    return

  local_files = get_local_files(zonefile_dir)
  log.info('processing new downloads')
  cache_path = c['records'].get('cache_path')
  if not cache_path:
    log.critical('cache_path was missing from the config')
    exit(1)
  cache = shelve.open(cache_path)

  try:
    for dest_path in to_download:
      dest_file = str(''.join(dest_path.split('/')[-1:]))
      zonefile = dest_path.replace('.gz', '', 1)
      if not cache.has_key(dest_file):
        log.warning('cache error %s for %s' % (dest_file, zonefile))
        continue

      remote = json.loads(cache[dest_file])
      url = c['czdap']['base_url'] + remote['uri'] + '?token=' + c['czdap'].get('token')
      human_size = Byte(remote['size']).best_prefix()

      if force_download:
        log.info("Force download [{size}] {uri} > {file}".format(
          size=human_size,
          uri=remote['uri'],
          file=dest_path
        ))
        if download(url, dest_path):
          decompress(dest_path)
          log.info("Decompressed as %s" % zonefile)

      elif dest_file in local_files:
        local_size = path.getsize(dest_path)
        if local_size == remote['size']:
          log.info("Matched local file [%s] skipping download.." % dest_file)
      else:
        log.info("Downloading [{size}] {uri} > {file}".format(
          size=human_size,
          uri=remote['uri'],
          file=dest_path
        ))
        if download(url, dest_path):
          decompress(dest_path)
          log.info("Decompressed as %s" % zonefile)

      parse_file(zonefile)

  finally:
    cache.close()

def parse_file(zonefile):
  log = logging.getLogger()
  new_data = extract_new_domains(zonefile)
  if not new_data:
    log.info('Found no new items for %s' % zonefile)
    return
  if new_data:
    n = 1000
    num_records = len(new_data)
    log.info('Found new %d items' % num_records)
    if num_records == 0:
      return
    if num_records <= n:
      upsert_into('scan_log', new_data)
      log.info('Database persistance success')
      return

    log.info('Splitting into %d chunks' % n)
    final = [new_data[i * n:(i + 1) * n] for i in range((num_records + n - 1) // n )]  
    for upserts in final:
      upsert_into('scan_log', upserts)

def main(reprocess_local_file=None):
  log = logging.getLogger()
  c = get_config()
  zonefile_dir = absolute_path(c.get('zonefile_dir'))
  if reprocess_local_file:
    force_download = c.get('force_download', False)
    zonefile_path = absolute_path(reprocess_local_file)
    if force_download:
      czdap_id = ''.join(zonefile_path.split('/')[-1:]).split('-')[0]
      uri = path.join(c['czdap'].get('zone_file_uri'), czdap_id)
      if not cache_remote(uri):
        return
      compressed_zonefile_path = zonefile_path + '.gz'
      parse_file(compressed_zonefile_path)
    else:
      if not path.isfile(zonefile_path):
        zonefile_path = path.join(zonefile_dir, args.reprocess_local_file)
      if not path.isfile(zonefile_path):
        log.error('file not found: %s' % args.reprocess_local_file)
        return
      parse_file(zonefile_path)
      return

  if not check_files():
    log.warning('It appears there is no work to do')


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='open net scans')
  parser.add_argument('-c', '--config_file', default='config.yaml', help='absolute path to config file')
  parser.add_argument('-l', '--reprocess_local_file', help='local zone file to reprocess')
  parser.add_argument('--verbose', '-v', action='count', default=0)
  args = parser.parse_args()

  log_level = args.verbose if args.verbose else 3
  setup_logging(log_level)
  get_config(config_file=args.config_file)

  main(reprocess_local_file=args.reprocess_local_file)
