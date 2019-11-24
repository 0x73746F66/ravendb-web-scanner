#!/usr/bin/env python
# -*- coding:utf-8
import os, argparse, logging, shodan, urllib3, multiprocessing
from datetime import datetime, date, timedelta
from pyravendb.custom_exceptions.exceptions import *
from random import randint
from retry import retry

from helpers import *
from models import *
from czdap import *
from osint import *

@retry((WhoisException, AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, urllib3.exceptions.ConnectionError), tries=5, delay=1.5, backoff=3, logger=logging.getLogger())
def process_whois(domain: Domain):
    domain_name = domain.fqdn
    log = logging.getLogger()
    osint_db = get_db("osint")
    now = datetime.utcnow().replace(microsecond=0)
    scanned_at = now.isoformat()
    log.info(f'Checking Whois for {domain_name}')
    try:
        r = get_whois(domain_name, normalized=True)
        if r:
            whois_options = {
                'domain': domain_name,
                'scanned_at': scanned_at
            }
            has_data = False
            if 'id' in r:
                has_data = True
                if type(r['id']) == list:
                    whois_options['whois_id'] = ','.join(sorted(r['id']))
                else:
                    whois_options['whois_id'] = str(r['id'])
            for key in ['status', 'registrar', 'emails', 'whois_server']:
                if key in r:
                    has_data = True
                    if type(r[key]) == list:
                        whois_options[key] = ','.join(sorted(r[key]))
                    else:
                        whois_options[key] = str(r[key])
            for contact in ['billing', 'admin', 'tech', 'registrant']:
                if 'contacts' in r and contact in r['contacts'] and r['contacts'][contact]:
                    has_data = True
                    whois_options['contact_%s'%contact] = r['contacts'][contact]
            for key in ['updated_date', 'creation_date', 'expiration_date']:
                if key in r:
                    has_data = True
                    if isinstance(r[key], datetime):
                        whois_options[key] = r[key].isoformat()
                    elif type(r[key]) == list and isinstance(r[key][0], datetime):
                        whois_options[key] = r[key][0].isoformat()
                    else:
                        whois_options[key] = str(r[key])
            if not has_data:
                return
            if type(r['raw']) == list:
                whois_options['raw'] = str(r['raw'][0])
            else:
                whois_options['raw'] = str(r['raw'])
            whois = Whois(**whois_options)
            ravendb_key = f'Whois/{whois.domain}'
            with osint_db.open_session() as session:
                stored = session.load(ravendb_key)
                if not stored:
                    log.info(f'Saving new whois for {domain_name}')
                else:
                    log.info(f'Replacing whois for {domain_name}')
                    session.delete(ravendb_key)
                    session.save_changes()
            with osint_db.open_session() as session:
                session.store(whois, ravendb_key)
                session.save_changes()
    except WhoisException as e:
        log.error(e)
        if 'No root WHOIS server found' not in str(e):
            raise Exception(e)
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
    n_cpus = int(c['multiprocessing_processes'].get('whois', 1))
    for domains_queued in get_next_from_queue(object_type=WhoisQueue, take=n_cpus):
        domains = []
        for domain_queue in domains_queued:
            if not isinstance(domain_queue, WhoisQueue):
                break
            domain = get_domain_by_domainqueue(domain_queue)
            if not isinstance(domain, Domain):
                log.error(f'{domain_queue.name} missing Domain. Skipping..')
                continue
            domains.append(domain)

        if n_cpus == 1:
            for domain in domains:
                process_whois(domain)
        else:
            gc.collect()
            p = multiprocessing.Pool(processes=n_cpus)
            p.map(process_whois, domains)
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
