#!/usr/bin/env python
# -*- coding:utf-8
import requests, logging, colorlog, argparse
import scandir, json, time, re, multiprocessing
from functools import wraps
from os import path, getcwd, isatty, makedirs
from urlparse import urljoin, urlparse
from yaml import load
from datetime import datetime
from socket import error as SocketError

config = None
session = None


def retry(ExceptionToCheck, tries=4, delay=3, backoff=2, logger=None):
    """
    :param ExceptionToCheck: the exception to check. may be a tuple of exceptions to check
    :type ExceptionToCheck: Exception or tuple
    :param tries: number of times to try (not retry) before giving up
    :type tries: int
    :param delay: initial delay between retries in seconds
    :type delay: int
    :param backoff: backoff multiplier e.g. value of 2 will double the delay each retry
    :type backoff: int
    :param logger: logger to use. If None, print
    :type logger: logging.Logger instance
    """

    def deco_retry(f):
        @wraps(f)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 1:
                try:
                    return f(*args, **kwargs)
                except ExceptionToCheck, e:
                    msg = "%s, Retrying in %d seconds..." % (str(e), mdelay)
                    if logger:
                        logger.warning(msg)
                    else:
                        print msg
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
                except Exception as e:
                    logger.critical(e)
                    break
            return f(*args, **kwargs)

        return f_retry  # true decorator

    return deco_retry

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


def setup_logging(log_level):
    log = logging.getLogger()
    format_str = '%(asctime)s - %(process)d - %(levelname)-8s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    if isatty(2):
        cformat = '%(log_color)s' + format_str
        colors = {
            'DEBUG': 'reset',
            'INFO': 'bold_blue',
            'WARNING': 'bold_yellow',
            'ERROR': 'bold_red',
            'CRITICAL': 'bold_red'
        }
        formatter = colorlog.ColoredFormatter( cformat, date_format, log_colors=colors)
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

    logging.getLogger("urllib3").setLevel(logging.CRITICAL)

def get_file(host, use_https=True):
    session = get_session()
    log = logging.getLogger(__file__)
    if use_https:
        url = 'https://' + host
    else:
        url = 'http://' + host

    try:
        r = session.head(url)
    except:
        if use_https:
            return get_file(host, use_https=False)
        return None
    if r.status_code != 200:
        # if str(r.status_code).startswith('3'):
        #     log.warning("Ignoring %d redirect for URL %s" % (r.status_code, url))
        # elif r.status_code == 403:
        #     log.warning("Ignoring Forbidden %s" % url)
        # elif r.status_code == 404:
        #     log.warning("Ignoring Not Found %s" % url)
        # else:
        #     log.error("Unexpected HTTP response code %d for URL %s" % (r.status_code, url))
        return None

    return session.get(host)

# @retry(SocketError, tries=20, delay=1, backoff=0.5, logger=logging.getLogger(__file__))  # 1.8 hrs
def process(fqdn):
    c = get_config()
    log = logging.getLogger(__file__)

    base_dir = c['osint'].get('base_dir').format(home=path.expanduser('~'))

    now = datetime.utcnow().replace(microsecond=0)
    updated_date = now.strftime('%Y-%m-%d')
    package_files = ['requirements.txt', 'setup.py', 'package.json', 'package-lock.json', 'yarn.json', 'yarn.lock', 'npm-package.json', 'npm-package-lock.json'
                    'Gemfile', 'Gemfile.lock', 'composer.json']
    common_dirs = ['src', 'dist', 'public', 'html', 'vendor', 'prd', 'prod', 'production', 'test', 'dev', 'development', 'stg', 'stage', 'staging']
    for p in package_files:
        # test root
        r = get_file(path.join(fqdn, p))
        if r:
            log.info('{}\ncontent: {}'.format(p, r.text))
            exit(0)

        for d in common_dirs:
            r = get_file(path.join(fqdn, d, p))
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
