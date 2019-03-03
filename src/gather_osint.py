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
    osint_db = get_db("osint")
    now = datetime.utcnow().replace(microsecond=0)
    scanned_at = now.isoformat()

    host_ip = get_a(domain.fqdn)
    cname = get_cnames(domain.fqdn)
    mx = get_mx(domain.fqdn)
    soa = []
    for s in get_soa(domain.fqdn):
        soa.append(SOA(**s))
    txt = get_txt(domain.fqdn)

    dns = DnsQuery(
        domain=domain.fqdn,
        A=host_ip or None,
        CNAME=None if not cname else '|'.join(sorted(cname)),
        MX=None if not mx else '|'.join(sorted(mx)),
        SOA=soa or None,
        TXT=None if not txt else '|'.join(sorted(txt)),
        scanned_at=scanned_at
    )
    with osint_db.open_session() as session:
        query_result = list(session.query(object_type=DnsQuery).where(domain=domain.fqdn).order_by_descending('scanned_at_unix'))
        if not query_result or is_dns_updated(dns, query_result[0]):
            log.info('Saving dns query for %s' % domain.fqdn)
            session.store(dns)
            session.save_changes()
            return dns

@retry((WhoisException), tries=5, delay=1, backoff=3, logger=logging.getLogger())
def process_whois(domain):
    log = logging.getLogger()
    osint_db = get_db("osint")
    now = datetime.utcnow().replace(microsecond=0)
    scanned_at = now.isoformat()
    try:
        r = get_whois(domain.fqdn, normalized=True)
        whois = Whois(
            id=','.join(sorted(r['id'])),
            domain=domain.fqdn,
            status=','.join(sorted(r['status'])),
            registrar=','.join(sorted(r['registrar'])),
            emails=None if not 'emails' in r else ','.join(sorted(r['emails'])),
            whois_server=None if not 'whois_server' in r else ','.join(sorted(r['whois_server'])),
            contact_billing=r['contacts']['billing'],
            contact_admin=r['contacts']['admin'],
            contact_tech=r['contacts']['tech'],
            contact_registrant=r['contacts']['registrant'],
            creation_date=None if not 'creation_date' in r else r['creation_date'][0].isoformat(),
            expiration_date=None if not 'expiration_date' in r else r['expiration_date'][0].isoformat(),
            updated_date=None if not 'updated_date' in r else r['updated_date'][0].isoformat(),
            scanned_at=scanned_at
        )
        with osint_db.open_session() as session:
            query_result = list(session.query(object_type=Whois).where(domain=domain.fqdn).order_by_descending('scanned_at_unix'))
            if not query_result or is_whois_updated(whois, query_result[0]):
                log.info('Saving whois %s' % domain.fqdn)
                session.store(whois)
                session.save_changes()
                return whois
    except WhoisException as e:
        log.error(e)
        if 'No root WHOIS server found' not in str(e):
            raise Exception(e)

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
    zonefiles_db = get_db("zonefiles", ravendb_conn)
    get_db("osint", ravendb_conn)
    zonefiles = []
    with zonefiles_db.open_session() as session:
        zonefiles = list(session.query(object_type=Zonefile).order_by('started_at_unix'))
    for zonefile in zonefiles:
        log.info('Gathering [.%s] domains' % zonefile.tld)
        with zonefiles_db.open_session() as session:
            query_result = list(session.query(object_type=Domain).where(tld=zonefile.tld).order_by('saved_at_unix'))
            if not query_result:
                log.info('Nothing to do')
                continue
            for domain in query_result:
                process_whois(domain)
                process_dns(domain)
