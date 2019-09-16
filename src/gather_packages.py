#!/usr/bin/env python
# -*- coding:utf-8
import requests, logging, colorlog, argparse, retry
import scandir, json, time, re, multiprocessing
from functools import wraps
from os import path, getcwd, isatty, makedirs
from yaml import load
from datetime import datetime
from socket import error as SocketError

from models import *
from helpers import *


@retry(SocketError, tries=20, delay=1, backoff=0.5, logger=logging.getLogger(__file__))  # 1.8 hrs
def process(fqdn):
    c = get_config()
    log = logging.getLogger(__file__)

    base_dir = c['osint'].get('base_dir').format(home=path.expanduser('~'))

    now = datetime.utcnow().replace(microsecond=0)
    updated_date = now.strftime('%Y-%m-%d')
    package_files = [
        'requirements.txt',
        'setup.py',
        'package.json',
        'package-lock.json',
        'yarn.json',
        'yarn.lock',
        'npm-package.json',
        'npm-package-lock.json',
        'Gemfile', 
        'Gemfile.lock',
        'composer.json',
        'build.gradle',
        'manifest.json',
        'bower.json',
        'pubspec.yaml',
        'MANIFEST.in',
    ]
    common_dirs = [
        'src',
        'dist', 
        'public', 
        'html',
        'vendor',
        'build',
        'prd',
        'prod',
        'production',
        'test',
        'dev',
        'development',
        'npe',
        'stg',
        'stage',
        'staging',
    ]
    for p in package_files:
        # test root
        r = get_file(fqdn, uri=p)
        if r:
            log.info('{}\ncontent: {}'.format(p, r.text))
            exit(0)

        for d in common_dirs:
            r = get_file(fqdn, uri=path.join(d, p))
            if r:
                log.info('{}/{}\ncontent: {}'.format(d, p, r.text))
                exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='open net scans')
    parser.add_argument('-c', '--config-file', default='config.yaml', help='absolute path to config file')
    parser.add_argument('--verbose', '-v', action='count', default=0)
    args = parser.parse_args()

    log_level = args.verbose if args.verbose else 3
    setup_logging(log_level)
    log = logging.getLogger(__file__)
    c = get_config(config_file=args.config_file)
    base_dir = c['osint'].get('base_dir').format(home=path.expanduser('~'))

    pool = multiprocessing.Pool(c.get('multiprocessing_pools', 1))
    try:
        for _, domains, other_files in scandir.walk(base_dir):
            for domain in domains:
                # log.info('Queue %s to process' % domain)
                pool.apply_async(process, args=(domain, ))
            break
    finally:
        pool.close()
    pool.join()
