#!/usr/bin/env python
# -*- coding:utf-8

import logging, gzip, shutil, requests, sys, json, colorlog, argparse
from os import path, getcwd, makedirs, isatty
from glob import glob
from urlparse import urlparse

session = requests.Session()


def main(config_file):
  global session
  log = logging.getLogger()
  base_dir = 'zonefiles'
  if not path.exists(base_dir):
    makedirs(base_dir)

  try:
    configFile = open(config_file, "r")
    config = json.load(configFile)
    configFile.close()
  except:
    log.critical("Error loading %s file." % config_file)
    exit(1)
  if not config.has_key('token'):
    log.critical("'token' parameter not found in the %s file" % config_file)
    exit(1)
  if not config.has_key('base_url'):
    log.critical("'base_url' parameter not found in the %s file" % config_file)
    exit(1)

  # Get all the files that need to be downloaded using CZDAP API.
  r = session.get(config['base_url'] + '/user-zone-data-urls.json?token=' + config['token'])
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
    url = config['base_url'] + uri
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
  parser.add_argument('-c', '--config_file', default='config.json', help='absolute path to config file')
  parser.add_argument('-v', action='store_true')
  parser.add_argument('-vv', action='store_true')
  parser.add_argument('-vvv', action='store_true')
  parser.add_argument('-vvvv', action='store_true')
  parser.add_argument('-vvvvv', action='store_true')
  args = parser.parse_args()
  log_level = 0
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