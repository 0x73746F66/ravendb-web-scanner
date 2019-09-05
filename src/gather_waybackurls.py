#!/usr/bin/env python
# -*- coding:utf-8
import os, argparse, logging, shodan, urllib3, multiprocessing
from datetime import datetime, date, timedelta
from pyravendb.custom_exceptions.exceptions import *
from random import randint

from helpers import *
from models import *
from czdap import *
from osint import *

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, urllib3.exceptions.ConnectionError, RetryCatcher), tries=5, delay=1.5, backoff=3, logger=logging.getLogger())
def process_deps(domain: Domain):
    log = logging.getLogger()
    # osint_db = get_db("osint")
    now = datetime.utcnow().replace(microsecond=0)
    # scanned_at = now.isoformat()
    log.info(f'Checking Deps for {domain.fqdn}')
    try:
        r = waybackurls(domain.fqdn)
        if not r:
            log.warn(f'no waybackurls results for {domain.fqdn}')
        url_list = file_list_filter(
            r, ['text/css', 'text/css; charset=utf-8', 'text/plain', 'text/plain; charset=utf-8', 'application/javascript', 'application/javascript; charset=utf-8', 'application/json; charset=utf-8', 'text/json', 'application/manifest+json'], ['.css', '.txt', 'js', 'json'])
        if url_list:
            log.info('{}\n{}'.format(domain.fqdn, url_list))
            exit(0)
        log.warn(f'match no interesting waybackurls for {domain.fqdn}')

    except TimeoutError as e:
        time.sleep(randint(15, 60))
        raise RetryCatcher(e)

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def get_domain_by_domainqueue(domain_queue):
    store = get_db('zonefiles')
    with store.open_session() as session:
        return session.load(f'Domain/{domain_queue.name}')

def main():
    c = get_config()
    n_cpus = int(c['multiprocessing_processes'].get('depscan', 1))
    for domains_queued in get_next_from_queue(object_type=DepScanQueue, take=n_cpus):
        domains = []
        for domain_queue in domains_queued:
            if not isinstance(domain_queue, DepScanQueue):
                break
            domain = get_domain_by_domainqueue(domain_queue)
            if not isinstance(domain, Domain):
                log.error(f'{domain_queue.name} missing Domain. Skipping..')
                continue
            domains.append(domain)

        if n_cpus == 1:
            for domain in domains:
                process_deps(domain)
        else:
            gc.collect()
            p = multiprocessing.Pool(processes=n_cpus)
            p.map(process_deps, domains)
            p.close()
            p.join()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='open net scans')
    parser.add_argument('-c', '--config-file', default='config.yaml', help='absolute path to config file')
    parser.add_argument('-l', '--log-file', default=None, help='absolute path to config file')
    parser.add_argument('--cron', default=False, type=bool, help='absolute path to config file')
    parser.add_argument('--verbose', '-v', action='count', default=0)
    args = parser.parse_args()

    log_level = args.verbose if args.verbose else 3
    setup_logging(log_level, file_path=args.log_file)
    log = logging.getLogger()
    c = get_config(config_file=args.config_file)
    if args.cron:
        filename = os.path.basename(__file__)
        if not c['cron_enable'].get(filename):
            log.warn(f'Configured to terminate {filename}')
            exit(0)

    ravendb_conn = '{}://{}:{}'.format(
        c['ravendb'].get('proto'),
        c['ravendb'].get('host'),
        c['ravendb'].get('port'),
    )
    get_db('osint', ravendb_conn)
    get_db('zonefiles', ravendb_conn)
    get_db('queue', ravendb_conn)
    main()
