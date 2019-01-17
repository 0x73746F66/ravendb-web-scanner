#!/usr/bin/env python
# -*- coding:utf-8
import logging, colorlog, argparse, mysql.connector, shelve
from os import path, getcwd, isatty
from urlparse import urljoin, urlparse
from mysql.connector import errorcode
from yaml import load
from datetime import datetime


config = None
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
  parser.add_argument('--verbose', '-v', action='count', default=0)
  args = parser.parse_args()

  log_level = args.verbose if args.verbose else 3
  setup_logging(log_level)
  c = get_config(config_file=args.config_file)

  log = logging.getLogger()
  query = "SELECT CONCAT(d.name, '.', t.name) as fqdn, updated FROM scans.domain d LEFT JOIN scans.tld t ON d.tld_id = t.id"
  cache_path = c['records'].get('cache_path', 'pyshelf.db')
  cache = shelve.open(cache_path, writeback=True)
  try:
    for fqdn, updated in sql(query):
      key = str(fqdn)
      if cache.has_key(key):
        log.info('%s cache hit' % key)
      else:
        log.info('%s cache miss' % key)
        last_scanned = datetime.strptime(str(updated), '%Y-%m-%d %H:%M:%S')
        cache[key] = last_scanned.isoformat()
  finally:
    cache.close()
