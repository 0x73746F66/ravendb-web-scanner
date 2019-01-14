#!/usr/bin/env python
# -*- coding:utf-8
import logging, sys, colorlog, argparse, mysql.connector
from os import path, getcwd, isatty
from mysql.connector import errorcode
from yaml import load, dump


config = None


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


def get_config(config_file=None):
  global config

  if not config:
    if not config_file:
      config_file = path.join(path.realpath(getcwd()), 'config.yaml')
    with open(config_file, 'r') as f:
      config = load(f.read())

  return config


def main(config_file):
  get_config(config_file=config_file)
  log = logging.getLogger()

  query = None
  query_file = path.join(path.realpath(getcwd()), 'sql', 'drop_schema.sql')
  with open(query_file, 'r') as f:
    query = load(f.read())
  if query:
    sql(query)

  exit(0)


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
