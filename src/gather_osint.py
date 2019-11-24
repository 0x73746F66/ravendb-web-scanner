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

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, urllib3.exceptions.ConnectionError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def process_dns(domain_name):
    log = logging.getLogger()
    osint_db = get_db("osint")
    now = datetime.utcnow().replace(microsecond=0)
    scanned_at = now.isoformat()
    log.info(f'Checking DNS for {domain_name}')
    try:
        host_ip = get_a(domain_name)
        cname = get_cnames(domain_name)
        mx = get_mx(domain_name)
        soa = []
        for s in get_soa(domain_name):
            soa.append(SOA(**s))
        txt = get_txt(domain_name)

        dns = DnsQuery(
            domain=domain_name,
            A=host_ip or None,
            CNAME=None if not cname else '|'.join(sorted(cname)),
            MX=None if not mx else '|'.join(sorted(mx)),
            SOA=soa or None,
            TXT=None if not txt else '|'.join(sorted(txt)),
            scanned_at=scanned_at
        )
        ravendb_key = f'DnsQuery/{dns.domain}'
        with osint_db.open_session() as session:
            stored = session.load(ravendb_key)
            if not stored:
                log.info(f'Saving new dns query for {domain_name}')
            else:
                log.info(f'Replacing dns query for {domain_name}')
                session.delete(ravendb_key)
                session.save_changes()
        with osint_db.open_session() as session:
            session.store(dns, ravendb_key)
            session.save_changes()
            return dns
    except NonUniqueObjectException as e:
        log.exception(e) #TODO handle this better
    except Exception as e:
        log.exception(e)
    return None

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, urllib3.exceptions.ConnectionError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def process_shodan(domain_name, ip_str):
    log = logging.getLogger()
    c = get_config()
    api = shodan.Shodan(c.get('shodan_api_key'))
    log.info(f'Checking Shodan for {domain_name}')
    try:
        r = api.host(ip_str)
    except (shodan.exception.APIError):
        return
    if r:
        osint_db = get_db("osint")
        shodan_obj = {
            'domain': domain_name,
            'ip_str': ip_str
        }
        for field in ['last_update', 'country_code', 'country_name', 'latitude', 'longitude']:
            if field in r:
                if isinstance(r[field], datetime):
                    shodan_obj[field] = r[field].isoformat()
                else:
                    shodan_obj[field] = r[field]
        if 'ports' in r and 'data' in r and len(r['ports']) > 0:
            shodan_obj['scans'] = []
            for data in r['data']:
                module = data['_shodan']['module']
                raw = None
                if module in data:
                    raw = data[module]
                shodan_obj['scans'].append(PortScan(
                            crawler='shodan',
                            crawler_id=data['_shodan']['id'],
                            port=int(data['port']),
                            module=module,
                            transport=data['transport'],
                            raw=raw,
                            response=data['data'],
                            ptr=None if not 'ptr' in data['_shodan'] else data['_shodan']['ptr'],
                            isp=None if not 'isp' in data else data['isp'],
                            asn=None if not 'asn' in data else data['asn']
                        ))
        shodan_scan = Shodan(**shodan_obj)
        ravendb_key = f'Shodan/{domain_name}'
        with osint_db.open_session() as session:
            stored = session.load(ravendb_key)
            if not stored:
                log.info(f'Saving new Shodan for {domain_name}')
            else:
                log.info(f'Replacing Shodan for {domain_name}')
                session.delete(ravendb_key)
                session.save_changes()
        with osint_db.open_session() as session:
            session.store(shodan_scan, ravendb_key)
            session.save_changes()

        return shodan_scan

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, urllib3.exceptions.ConnectionError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def process_tls(domain_name):
    log = logging.getLogger()
    osint_db = get_db("osint")
    log.info(f'Checking TLS for {domain_name}')
    PEM, headers = get_certificate(domain_name)
    if headers:
        scanned_at = datetime.utcnow().replace(microsecond=0)
        headers['Host'] = domain_name
        headers['scanned_at'] = scanned_at.isoformat()
        headers['scanned_at_unix'] = time.mktime(scanned_at.timetuple())
        headers = HttpHeader(**decode_bytes(headers))
        ravendb_key = f'HttpHeader/{domain_name}'
        with osint_db.open_session() as session:
            stored = session.load(ravendb_key)
            if not stored:
                log.info(f'Saving new HttpHeader for {domain_name}')
            else:
                log.info(f'Replacing HttpHeader for {domain_name}')
                session.delete(ravendb_key)
                session.save_changes()
        with osint_db.open_session() as session:
            session.store(headers, ravendb_key)
            session.save_changes()

    if not PEM:
        return
    cert = get_certificate_detail(cert=PEM)
    if not cert:
        log.warn(f'problem extracting certificate for {domain_name}')
        return
    scanned_at = datetime.utcnow().replace(microsecond=0)
    cert['domain'] = domain_name
    cert['scanned_at'] = scanned_at.isoformat()
    cert['scanned_at_unix'] = time.mktime(scanned_at.timetuple())
    certificate = Certificate(**decode_bytes(cert))
    ravendb_key = f'Certificate/{domain_name}'
    with osint_db.open_session() as session:
        stored_certificate = session.load(ravendb_key)
        if not stored_certificate:
            log.info(f'Saving new certificate for {domain_name}')
        else:
            log.info(f'Replacing certificate for {domain_name}')
            session.delete(ravendb_key)
            session.save_changes()
    with osint_db.open_session() as session:
        session.store(certificate, ravendb_key)
        session.save_changes()

    with osint_db.open_session() as session:
        stored_certificate = session.load(ravendb_key)
        log.info(f'Attaching certificate for {domain_name}')
        session.advanced.attachment.store(stored_certificate, f'{domain_name}.pem', PEM, content_type="text/plain")
        session.save_changes()

    return certificate

def gather_osint(d):
    log = logging.getLogger()
    domain_name = d.fqdn

    try:
        certificate = process_tls(domain_name)
        domains = set()
        domains.add(domain_name)
        if certificate and hasattr(certificate, 'subjectAltName'):
            for d in certificate.subjectAltName.split(','): # pylint: disable=no-member
                subdomain = ''.join(d.split('DNS:')).strip()
                if not subdomain.startswith('*'):
                    domains.add(subdomain)
                    process_tls(subdomain)
                    save_to_queue('DepScan/%s' % subdomain, DepScanQueue(
                        name=subdomain,
                        added=datetime.utcnow().replace(microsecond=0).isoformat()
                    ))
        for domain in domains:
            dns = process_dns(domain)
            if not dns or not dns.A:
                continue
            process_shodan(domain, dns.A)

    except Exception as e:
        log.exception(e)
        pass

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def get_domain_by_domainqueue(domain_queue):
    store = get_db('zonefiles')
    with store.open_session() as session:
        return session.load(f'Domain/{domain_queue.name}')

def main():
    c = get_config()
    n_cpus = int(c['multiprocessing_processes'].get('osint', 1))
    for domains_queued in get_next_from_queue(object_type=DomainQueue, take=n_cpus):
        domains = []
        for domain_queue in domains_queued:
            if not isinstance(domain_queue, DomainQueue):
                break
            domain = get_domain_by_domainqueue(domain_queue)
            if not isinstance(domain, Domain):
                log.error(f'{domain_queue.name} missing Domain. Skipping..')
                continue
            domains.append(domain)

        if n_cpus == 1:
            for domain in domains:
                gather_osint(domain)
        else:
            gc.collect()
            p = multiprocessing.Pool(processes=n_cpus)
            p.map(gather_osint, domains)
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
