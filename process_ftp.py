#!/usr/bin/env python
import hashlib, argparse, logging, colorlog, re, shutil, gzip, mysql.connector, shelve, json
from os import path, isatty, getcwd, makedirs
from yaml import load
from ftplib import FTP
from bitmath import Byte
from mysql.connector import errorcode
from datetime import datetime


config = None

def get_config(config_file=None):
  global config

  if not config:
    if not config_file:
      config_file = path.join(path.realpath(getcwd()), 'config.yaml')
    with open(config_file, 'r') as f:
      config = load(f.read())

  return config

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

def ftp_download(ftp, remote_source, local_filename):
  log = logging.getLogger()
  log.info('downloading to %s' % local_filename)
  with open(local_filename, 'wb') as f:
    ftp.retrbinary('RETR %s' % remote_source, lambda data: f.write(data))
  return local_filename

def ftp_filesize(ftp, filename):
  global stat
  def put_stat(s):
    global stat
    stat = s
  size = 0
  log = logging.getLogger()
  log.info('checking file sze for %s' % filename)
  regex = r"^[-rwx]{10}\s+\d+\s+\w+\s+\w+\s+(\d+)\s+(.+)\s.+$"
  ftp.dir(filename, lambda data: put_stat(data))
  match = re.search(regex, stat)
  if match:
    size, last_mod_date = match.groups()
  try:
    ftp.sendcmd("TYPE i") # Switch to Binary mode
    ftp.size(filename, lambda data: put_stat(data))
    size = stat
    ftp.sendcmd("TYPE A") # Switch to ASCII mode
  except:
    pass

  return int(size)

def validateIntegrity(orighash, destfilepath):
  log = logging.getLogger()
  desthash = None
  with open(destfilepath, "rb") as f:
    desthash = hashlib.md5(f.read()).hexdigest()
  log.info('md5checksum %s == %s' % (orighash, desthash))
  return orighash==desthash

def md5_checksum(md5_file, target):
  md5hash = None
  with open(md5_file, 'r') as f:
    md5hash = ''.join(re.findall(r"([a-fA-F\d]{32})", f.read()) or [])
  return validateIntegrity(md5hash.strip(), target)

def decompress(file_path, new_dest):
  with gzip.open(file_path, 'rb') as f_in:
    with open(new_dest, 'wb') as f_out:
      shutil.copyfileobj(f_in, f_out)
  return new_dest

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

  if not cols or not values:
    return

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

def parse_file(zonefile_path, regex, tld, remote_file):
  c = get_config()
  log = logging.getLogger()
  cache_path = c['records'].get('cache_path')

  if not cache_path:
    log.critical('cache_path was missing from the config')
    exit(1)

  if not path.isfile(zonefile_path):
    log.error('missing zonefile %s' % zonefile_path)
    return

  stale_days = int(c['records'].get('stale_days', 0))
  cache = shelve.open(cache_path)
  try:
    zonefile = ''.join(zonefile_path.split('/')[-1:])

    n = 1000
    num_lines = 0
    num_matches = 0
    scanned_time = datetime.utcnow().replace(microsecond=0)
    with open(zonefile_path, 'r') as f:
      mysql_data = []
      for line in f:
        # log.debug(line)
        num_lines += 1
        num = sum(1 for _ in re.finditer(regex, line))
        if num == 0:
          log.debug('No match found for line\n%s' % line)
          continue

        num_matches += 1
        domain, ttl, ns = re.search(regex, line).groups()
        ns = ns.lower()
        domain = domain.lower()
        fqdn = str('.'.join([domain, tld]))
        if ttl:
          ttl = ttl.strip()
        if not ttl.strip():
          ttl = 86500

        should_process = False
        cache_key = str(fqdn)
        if not cache.has_key(cache_key):
          log.debug('cache miss')
          should_process = True
          last_scanned = scanned_time
        else:
          last_scanned = datetime.strptime(cache[cache_key], '%Y-%m-%dT%H:%M:%S')

        delta = scanned_time - last_scanned
        if delta.days >= stale_days:
          log.debug('%s queue for persistance' % fqdn)
          should_process = True

        if should_process:
          cache[cache_key] = scanned_time.isoformat()
          mysql_data.append({
            'domain': domain,
            'tld': tld,
            'fqdn': fqdn,
            'local_file': zonefile,
            'remote_file': remote_file,
            'nameserver': ns,
            'ttl': ttl,
            'scanned': scanned_time.strftime('%Y-%m-%d %H:%M:%S')
          })
        num_records = len(mysql_data)
        if num_records >= n:
          log.info('Found new %d items' % num_records)
          upsert_into('scan_log', mysql_data)
          log.info('Database persistance success')
          mysql_data = []

      upsert_into('scan_log', mysql_data)
    log.info('Matched %d of %d domains' % (num_matches, num_lines))

  finally:
    cache.close()

def main():
  log = logging.getLogger()
  conf = get_config()
  tmp_dir = conf.get('tmp_dir')
  if not path.isdir(tmp_dir):
    makedirs(tmp_dir)
  zonefile_dir = conf.get('zonefile_dir')
  if not path.isdir(zonefile_dir):
    makedirs(zonefile_dir)

  for c in conf.get('ftp'):
    server = c.get('server')
    user = c.get('user')
    passwd = c.get('passwd')
    regex = c.get('regex')
    ftp = FTP(server)
    try:
      ftp.set_pasv(True)
      ftp.login(user, passwd)
      if not c.get('files'):
        log.critical('files array needed in ftp conf')
        exit(1)
      for z in c.get('files'):
        md5hash_file = z.get('md5checksum')
        md5_file_path = path.join(tmp_dir, md5hash_file)
        ftp_download(ftp, md5hash_file, md5_file_path)
        target_file = z.get('file_path')
        target_file_path = path.join(zonefile_dir, target_file)
        zonefile_path = path.join(zonefile_dir, target_file.replace('.gz', '.txt', 1))
        download_zonefile = True
        if path.isfile(target_file_path):
          target_size = ftp_filesize(ftp, target_file)
          human_size = Byte(target_size).best_prefix()
          log.info('%s is %s' % (target_file, human_size))
          if md5_checksum(md5_file_path, target_file_path):
            log.info('file %s matches checksum. skipping' % target_file)
            download_zonefile = False

        if download_zonefile and ftp_download(ftp, target_file, target_file_path):
          log.info('Decompressing %s' % target_file)
          decompress(target_file_path, zonefile_path)
          log.info('Parsing %s' % zonefile_path)
        remote = 'ftp://' + user + '@' + path.join(server, target_file)
        parse_file(zonefile_path, regex, z.get('tld'), remote)

    finally:
      ftp.quit()


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='open net scans')
  parser.add_argument('-c', '--config_file', default='config.yaml', help='absolute path to config file')
  parser.add_argument('-l', '--reprocess_local_file', help='local zone file to reprocess')
  parser.add_argument('--verbose', '-v', action='count', default=0)
  args = parser.parse_args()

  log_level = args.verbose if args.verbose else 3
  setup_logging(log_level)
  get_config(config_file=args.config_file)

  main()
