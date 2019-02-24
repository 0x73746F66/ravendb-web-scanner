#!/usr/bin/env python
# -*- coding:utf-8
import logging, OpenSSL, socket, ssl
import scandir, dns, dns.resolver, json, shodan, time, urllib2

from os import path, getcwd, isatty, makedirs
from urlparse import urljoin, urlparse
from datetime import datetime
from pythonwhois import get_whois
from pythonwhois.shared import WhoisException
from socket import error as SocketError

from helpers import *
from models import *
from czdap import *

def get_certificate_detail(cert):
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    result = {
        'subject': dict(x509.get_subject().get_components()),
        'issuer': dict(x509.get_issuer().get_components()),
        'serialNumber': x509.get_serial_number(),
        'version': x509.get_version(),
        'notBefore': datetime.strptime(x509.get_notBefore(), '%Y%m%d%H%M%SZ'),
        'notAfter': datetime.strptime(x509.get_notAfter(), '%Y%m%d%H%M%SZ'),
    }
    extensions = (x509.get_extension(i)
                  for i in range(x509.get_extension_count()))
    extension_data = {e.get_short_name(): str(e) for e in extensions}
    result.update(extension_data)
    return result

def get_certificate(host, port=443, timeout=10):
    session = get_session()
    log = logging.getLogger()
    url = 'https://' + host
    try:
        r = session.head(url)
    except:
        return None, None
    if r.status_code != 200:
        if str(r.status_code).startswith('3'):
            log.warning("Ignoring %d redirect for URL %s" % (r.status_code, url))
        elif r.status_code == 403:
            log.warning("Ignoring Forbidden %s" % url)
        elif r.status_code == 404:
            log.warning("Ignoring Not Found %s" % url)
        else:
            log.error("Unexpected HTTP response code %d for URL %s" % (r.status_code, url))
        return None, None

    context = ssl.create_default_context()
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)
    DER = None
    try:
        DER = sock.getpeercert(True)
    except:
        return None, None
    finally:
        sock.close()

    PEM = ssl.DER_cert_to_PEM_cert(DER)
    return PEM, r.headers


@retry((dns.resolver.NoNameservers, dns.exception.Timeout), tries=20, delay=1, backoff=0.5, logger=logging.getLogger())  # 1.8 hrs
def get_dns_record(domain, record, nameservers=None):
    resolver = dns.resolver.get_default_resolver()
    ns_a = resolver.nameservers
    default_nameservers = [
        '9.9.9.9', '1.1.1.1', '208.67.222.222', '8.8.8.8', '64.6.64.6',
        '84.200.69.80', '216.146.35.35', '198.41.0.4', '192.58.128.30',
        '199.7.83.42', '199.9.14.201', '192.5.5.241'
    ]
    for n in nameservers + default_nameservers:
        ns_a.append(str(n))
    resolver.nameservers = ns_a
    try:
        return resolver.query(domain, record)
    except (dns.resolver.NoAnswer, dns.exception.SyntaxError, dns.resolver.NXDOMAIN):
        return


def get_cnames(domain, nameservers=None):
    results = set()
    result = get_dns_record(domain, 'CNAME', nameservers=nameservers)
    if result:
        for data in result:
            results.add(data.target)
    return list(results)


def get_a(domain, nameservers=None):
    result = get_dns_record(domain, 'A', nameservers=nameservers)
    if result:
        for data in result:
            return data.address
    return


def get_soa(domain, nameservers=None):
    results = []
    result = get_dns_record(domain, 'SOA', nameservers=nameservers)
    if result:
        for rdata in result:
            results.append({
                'serial': rdata.serial,
                'tech': rdata.rname,
                'refresh': rdata.refresh,
                'retry': rdata.retry,
                'expire': rdata.expire,
                'minimum': rdata.minimum,
                'mname': rdata.mname
            })
    return results


def get_mx(domain, nameservers=None):
    results = set()
    result = get_dns_record(domain, 'MX', nameservers=nameservers)
    if result:
        for data in result:
            results.add(data.exchange)
    return list(results)


def get_txt(domain, nameservers=None):
    results = set()
    result = get_dns_record(domain, 'TXT', nameservers=nameservers)
    if result:
        for data in result:
            results.add(data)
    return list(results)


@retry(SocketError, tries=20, delay=1, backoff=0.5, logger=logging.getLogger())  # 1.8 hrs
def save_whois(host, whois_dir):
    if not path.exists(whois_dir):
        makedirs(whois_dir)
    try:
        r = get_whois(host)
    except (WhoisException):
        return
    updated_date = datetime.utcnow().strftime('%Y-%m-%d')
    file_name = path.join(whois_dir, updated_date + '.json')
    with open(file_name, 'w+') as f:
        f.write(
            json.dumps(r, default=lambda o: o.isoformat() if isinstance(o, (datetime)) else str(o) ))
    return True


def save_shodan(host, shodan_dir):
    c = get_config()
    api = shodan.Shodan(c.get('shodan_api_key'))
    if not path.exists(shodan_dir):
        makedirs(shodan_dir)
    try:
        r = api.host(host)
    except (shodan.exception.APIError):
        return
    last_update = datetime.strptime(
        r.get('last_update'), '%Y-%m-%dT%H:%M:%S.%f')
    updated_date = last_update.strftime('%Y-%m-%d')
    file_name = path.join(shodan_dir, updated_date + '.json')
    with open(file_name, 'w+') as f:
        f.write(
            json.dumps(r, default=lambda o: o.isoformat() if isinstance(o, (datetime)) else str(o) ))
    return True


def save_spider(host, spider_dir):
    log = logging.getLogger()
    if not path.exists(spider_dir):
        makedirs(spider_dir)

    html = None
    url = 'https://' + host
    log.info('Trying %s' % url)
    try:
        website = urllib2.urlopen(url)
        html = website.read()
    except:
        url = 'http://' + host
        log.warn('Trying %s' % url)
        try:
            website = urllib2.urlopen(url)
            html = website.read()
        except Exception as e:
            log.error('Unable to crawl %s\t%s' % (host, e))
    if html:
        links_tuple = re.findall(r"\"(((http|ftp)s?:)?/{1,2}.*?)\"", html)
        links = set()
        for g1, g2, g3 in links_tuple:
            links.add(g1)
        links = '\n'.join(list(links))

        updated_date = datetime.utcnow().replace(
            microsecond=0).strftime('%Y-%m-%d')
        file_name = path.join(spider_dir, updated_date + '_links.txt')
        with open(file_name, 'w+') as f:
            f.write(links)
            return True


def save_https(fqdn, host_ip, https_dir):
    log = logging.getLogger()
    now = datetime.utcnow().replace(microsecond=0)
    updated_date = now.strftime('%Y-%m-%d')
    if not path.exists(https_dir):
        makedirs(https_dir)
    PEM, headers = get_certificate(fqdn)
    if headers:
        file_name = path.join(https_dir, updated_date + '_headers.json')
        with open(file_name, 'w+') as f:
            log.info('saved https headers for %s' % fqdn)
            f.write(json.dumps(headers, default=lambda o: o.isoformat() if isinstance(o, (datetime)) else str(o)))
    file_name = path.join(https_dir, updated_date + '_key.pem')
    with open(file_name, 'w+') as f:
        log.info('saved key.pem for %s' % fqdn)
        f.write(PEM)

    cert = get_certificate_detail(cert=PEM)
    if not cert:
        return False
    file_name = path.join(https_dir, updated_date + '_key_detail.json')
    with open(file_name, 'w+') as f:
        f.write(json.dumps(cert, default=lambda o: o.isoformat() if isinstance(o, (datetime)) else str(o) ))
        return cert
