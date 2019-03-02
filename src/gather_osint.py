#!/usr/bin/env python
# -*- coding:utf-8
import argparse, logging
from datetime import datetime

from helpers import *
from models import *
from czdap import *
from osint import *

def process_dns(domain):
    log = logging.getLogger()
    dns_db = get_db("dns")
    now = datetime.utcnow().replace(microsecond=0)
    scanned_at = now.isoformat()

    host_ip = get_a(domain)
    cname = get_cnames(domain),
    mx = get_mx(domain),
    soa = get_soa(domain),
    txt = get_txt(domain)

    dns = DNS(domain, host_ip, cname, mx, soa, txt, scanned_at)
    print(dns)
    exit(0)
    return dns

def process_whois(domain):
    log = logging.getLogger()
    whois_db = get_db("whois")
    now = datetime.utcnow().replace(microsecond=0)
    scanned_at = now.isoformat()
    try:
        r = get_whois(domain.fqdn, normalized=True)
        print(r['emails'])
        print(type(r['emails']))
        exit(0)
        whois = Whois(
            r['id'],
            domain.fqdn,
            r['status'],
            r['registrar'],
            ','.join(r['emails'].sort()),
            r['whois_server'],
            r['contacts']['billing'],
            r['contacts']['admin'],
            r['contacts']['tech'],
            r['contacts']['registrant'],
            r['creation_date'][0].isoformat(),
            r['expiration_date'][0].isoformat(),
            r['updated_date'][0].isoformat(),
            scanned_at
        )
        with whois_db.open_session() as session:
            query_result = list(session.query(object_type=Whois).where(domain=domain.fqdn).order_by_descending('scanned_at_unix'))
            if not query_result or is_whois_updated(whois, query_result[0]):
                session.store(whois)
                session.save_changes()
                return whois
    except WhoisException as e:
        log.error(e)
        if r:
            print(r)



#     if host_ip and save_shodan(host_ip, shodan_dir=path.join(base_dir, c['osint'].get('shodan_dir').format(domain=fqdn))):
#         log.info('saved shodan for %s' % fqdn)

#     if save_spider(fqdn, spider_dir=path.join(base_dir, c['osint'].get('spider_dir').format(domain=fqdn))):
#         log.info('saved spider for %s' % fqdn)

#     https_dir = path.join(base_dir, c['osint'].get('https_dir').format(domain=fqdn))
#     cert = save_https(fqdn, host_ip, https_dir=https_dir)
#     if not cert:
#         return
#     log.info('saved https cert detail for %s' % fqdn)
#     # pylint: disable=no-member
#     if not cert.has_key('subjectAltName'):
#         return
#     # pylint: enable=no-member
#     log.debug('found subjectAltName %s' % cert['subjectAltName'])
#     domains = set()
#     for d in cert['subjectAltName'].split(','):
#         domain = ''.join(d.split('DNS:')).strip()
#         if not d.startswith('*'):
#             domains.add(domain)
#     for domain in domains:
#         sub_domain = fqdn, domain.replace(fqdn, '').rstrip('.')
#         sub_domain_path = path.join(fqdn, sub_domain)
#         sub_host_ip = get_a(domain)
#         if save_spider(domain, spider_dir=path.join(base_dir, c['osint'].get('spider_dir').format(domain=sub_domain_path))):
#             log.info('saved spider for %s' % domain)
        
#         if save_shodan(sub_host_ip, shodan_dir=path.join(base_dir, c['osint'].get('shodan_dir').format(domain=sub_domain_path))):
#             log.info('saved shodan for %s' % domain)
#         https_subdir = path.join(base_dir, c['osint'].get('https_dir').format(domain=sub_domain_path))
#         if save_https(domain, sub_host_ip, https_dir=https_subdir):
#             log.info('saved https cert detail for %s' % domain)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='open net scans')
    parser.add_argument('-c', '--config-file', default='config.yaml', help='absolute path to config file')
    parser.add_argument('--verbose', '-v', action='count', default=0)
    args = parser.parse_args()

    log_level = args.verbose if args.verbose else 3
    setup_logging(log_level)
    log = logging.getLogger()
    c = get_config(config_file=args.config_file)
    ravendb_conn = '{}://{}:{}'.format(
        c['ravendb'].get('proto'),
        c['ravendb'].get('host'),
        c['ravendb'].get('port'),
    )
    scans_db = get_db("scans", ravendb_conn)
    get_db("whois", ravendb_conn)
    get_db("dns", ravendb_conn)

    with scans_db.open_session() as session:
        query_result = list(session.query(object_type=Domain).order_by_descending('started_at_unix'))
    if not query_result:
        log.info('Nothing to do')
        exit(0)
    for domain in query_result:
        process_whois(domain)
        process_dns(domain)
