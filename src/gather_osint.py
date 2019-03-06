#!/usr/bin/env python
# -*- coding:utf-8
import argparse, logging
from datetime import datetime, date, timedelta
from pyravendb.custom_exceptions.exceptions import AllTopologyNodesDownException

from helpers import *
from models import *
from czdap import *
from osint import *

@retry((AllTopologyNodesDownException), tries=5, delay=1.5, backoff=3, logger=logging.getLogger())
def process_dns(domain):
    log = logging.getLogger()
    osint_db = get_db("osint")
    now = datetime.utcnow().replace(microsecond=0)
    scanned_at = now.isoformat()
    try:
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
            query_result = list(session.query(object_type=DnsQuery).where(domain=dns.domain).order_by_descending('scanned_at_unix'))
            if not query_result:
                log.info('Saving new dns query for %s' % dns.domain)
            elif is_dns_updated(dns, query_result[0]):
                log.info('Saving updated dns query for %s' % dns.domain)
            else:
                return dns
            session.store(dns, 'DnsQuery/%s' % dns.domain)
            session.save_changes()
            return dns
    except Exception as e:
        log.exception(e)
    return None

@retry((WhoisException, AllTopologyNodesDownException), tries=5, delay=1, backoff=3, logger=logging.getLogger())
def process_whois(domain):
    log = logging.getLogger()
    osint_db = get_db("osint")
    now = datetime.utcnow().replace(microsecond=0)
    scanned_at = now.isoformat()
    try:
        r = get_whois(domain.fqdn, normalized=True)
        if r:
            whois_options = {
                'domain': domain.fqdn,
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
            with osint_db.open_session() as session:
                query_result = list(session.query(object_type=Whois).where(domain=whois.domain).order_by_descending('scanned_at_unix'))
                if not query_result:
                    log.info('Saving new whois for %s' % whois.domain)
                elif is_whois_updated(whois, query_result[0]):
                    log.info('Saving update whois for %s' % whois.domain)
                else:
                    return whois
                session.store(whois, 'Whois/%s' % whois.domain)
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
# for domain in domains:
#     sub_domain = fqdn, domain.replace(fqdn, '').rstrip('.')
#     sub_domain_path = path.join(domain_name, sub_domain)
#     sub_host_ip = get_a(domain)
#     if save_spider(domain, spider_dir=path.join(base_dir, c['osint'].get('spider_dir').format(domain=sub_domain_path))):
#         log.info('saved spider for %s' % domain)
    
#     if save_shodan(sub_host_ip, shodan_dir=path.join(base_dir, c['osint'].get('shodan_dir').format(domain=sub_domain_path))):
#         log.info('saved shodan for %s' % domain)

def process_shodan(domain_name, host_ip):
    log = logging.getLogger()

@retry((AllTopologyNodesDownException), tries=5, delay=1.5, backoff=3, logger=logging.getLogger())
def process_tls(domain_name, host_ip):
    log = logging.getLogger()
    osint_db = get_db("osint")

    PEM, headers = get_certificate(domain_name)
    if headers:
        scanned_at = datetime.utcnow().replace(microsecond=0)
        headers['Host'] = domain_name
        headers['scanned_at'] = scanned_at.isoformat()
        headers['scanned_at_unix'] = time.mktime(scanned_at.timetuple())
        headers = HttpHeader(**decode_bytes(headers))
        ravendb_key = 'HttpHeader/%s' % domain_name
        with osint_db.open_session() as session:
            stored = session.load(ravendb_key)
            if not stored:
                log.info('Saving new HttpHeader for %s' % domain_name)
            else:
                log.info('Replacing HttpHeader for %s' % domain_name)
                session.delete(ravendb_key)
                session.save_changes()
        with osint_db.open_session() as session:
            session.store(headers, ravendb_key)
            session.save_changes()

    if not PEM:
        return
    cert = get_certificate_detail(cert=PEM)
    if not cert:
        log.warn('problem extracting certificate for %s' % domain_name)
        return
    scanned_at = datetime.utcnow().replace(microsecond=0)
    cert['domain'] = domain_name
    cert['scanned_at'] = scanned_at.isoformat()
    cert['scanned_at_unix'] = time.mktime(scanned_at.timetuple())
    certificate = Certificate(**decode_bytes(cert))
    ravendb_key = 'Certificate/%s' % domain_name
    with osint_db.open_session() as session:
        stored_certificate = session.load(ravendb_key)
        if not stored_certificate:
            log.info('Saving new certificate for %s' % domain_name)
        else:
            log.info('Replacing certificate for %s' % domain_name)
            session.delete(ravendb_key)
            session.save_changes()
    with osint_db.open_session() as session:
        session.store(certificate, ravendb_key)
        session.save_changes()

    with osint_db.open_session() as session:
        stored_certificate = session.load(ravendb_key)
        log.info('Attaching certificate for %s' % domain_name)
        session.advanced.attachment.store(stored_certificate, '%s.pem' % domain_name, PEM, content_type="text/plain")
        session.save_changes()

@retry((AllTopologyNodesDownException), tries=5, delay=1.5, backoff=3, logger=logging.getLogger())
def gather_osint(zonefile):
    log = logging.getLogger()
    osint_db = get_db("osint")
    zonefiles_db = get_db("zonefiles")
    log.info('Gathering recently scanned [.%s] domains to skip' % zonefile.tld)
    scanned_recently = set()
    recent_dt = date.today() - timedelta(days=3)
    with osint_db.open_session() as session:
        r1 = list(session.query(object_type=Whois).where_greater_than_or_equal('scanned_at_unix', int(recent_dt.strftime("%s"))))
        r2 = list(session.query(object_type=DnsQuery).where_greater_than_or_equal('scanned_at_unix', int(recent_dt.strftime("%s"))))
        if r1:
            for whois in r1:
                scanned_recently.add(whois.domain)
        if r2:
            for dns in r2:
                scanned_recently.add(dns.domain)

    log.info('Gathering [.%s] domains' % zonefile.tld)
    with zonefiles_db.open_session() as session:
        query_result = list(session.query(object_type=Domain).where(tld=zonefile.tld).order_by('saved_at_unix'))
        if not query_result:
            log.warn('Nothing to do')
            return
        for domain in query_result:
            if domain.fqdn not in scanned_recently:
                scanned_recently.add(domain.fqdn)
                dns = process_dns(domain)
                if not dns or not dns.A:
                    continue
                process_tls(domain.fqdn, dns.A)
                whois = process_whois(domain) # must be last, retry is buggy





                # # pylint: disable=no-member
                # if not cert.has_key('subjectAltName'):
                #     return
                # # pylint: enable=no-member
                # json_doc = json.dumps(cert, default=lambda o: o.isoformat() if isinstance(o, (datetime)) else str(o) )
                # print(json_doc)
                # exit(0)
                # log.debug('found subjectAltName %s' % cert['subjectAltName'])
                # domains = set()
                # for d in cert['subjectAltName'].split(','):
                #     domain = ''.join(d.split('DNS:')).strip()
                #     if not d.startswith('*'):
                #         domains.add(domain)

                #     https_subdir = path.join(base_dir, c['osint'].get('https_dir').format(domain=sub_domain_path))
                #     if save_https(domain, sub_host_ip, https_dir=https_subdir):
                #         log.info('saved https cert detail for %s' % domain)

@retry((AllTopologyNodesDownException), tries=5, delay=1.5, backoff=3, logger=logging.getLogger())
def main():
    zonefiles_db = get_db("zonefiles")
    zonefiles = []
    with zonefiles_db.open_session() as session:
        zonefiles = list(session.query(object_type=Zonefile).order_by('started_at_unix'))

    gc.collect()
    p = multiprocessing.Pool()
    n_cpus = 6
    p.map(gather_osint, zonefiles, n_cpus)
    p.close()
    p.join()

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
    get_db("osint", ravendb_conn)
    get_db("zonefiles", ravendb_conn)
    main()