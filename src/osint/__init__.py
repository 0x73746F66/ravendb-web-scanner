#!/usr/bin/env python
# -*- coding:utf-8
import logging, OpenSSL, socket, ssl
import scandir, dns, dns.resolver, json, shodan, time

from os import path, getcwd, isatty, makedirs
from urllib.request import urlopen
from urllib.parse import urljoin, urlparse
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
        'notBefore': datetime.strptime(x509.get_notBefore().decode(), '%Y%m%d%H%M%SZ'),
        'notAfter': datetime.strptime(x509.get_notAfter().decode(), '%Y%m%d%H%M%SZ'),
    }
    extensions = (x509.get_extension(i)
                for i in range(x509.get_extension_count()))
    extension_data = {e.get_short_name(): str(e) for e in extensions}
    result.update(extension_data)
    return result

def get_certificate(host, port=443, timeout=10, referer=None):
    session = get_session()
    log = logging.getLogger()
    headers = {
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9',
        'Pragma': 'no-cache',
    }
    if referer:
        headers['referer'] = referer
    if host.startswith('https'):
        url = host
    else:
        url = 'https://' + host
    try:
        r = session.get(url,headers=headers)
    except:
        return None, None
    if r.status_code != 200:
        if str(r.status_code).startswith('3'):
            return get_certificate(r.headers['Location'], referer=host)
        elif r.status_code == 403:
            log.warning("Ignoring Forbidden %s" % url)
        elif r.status_code == 404:
            log.warning("Ignoring Not Found %s" % url)
        else:
            log.error("Unexpected HTTP response code %d for URL %s" % (r.status_code, url))
        return None, None

    try:
        context = ssl.create_default_context()
        conn = socket.create_connection((host, port))
        sock = context.wrap_socket(conn, server_hostname=host)
        sock.settimeout(timeout)
        DER = sock.getpeercert(True)
        PEM = ssl.DER_cert_to_PEM_cert(DER)
    except Exception as e:
        print(e)
        return None, None
    finally:
        sock.close()

    return PEM, r.headers

@retry((dns.resolver.NoNameservers, dns.exception.Timeout), tries=20, delay=1, backoff=0.5, logger=logging.getLogger())  # 1.8 hrs
def get_dns_record(domain, record, nameservers=[]):
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

def get_cnames(domain, nameservers=[]):
    results = set()
    result = get_dns_record(domain, 'CNAME', nameservers=nameservers)
    if result:
        for data in result:
            results.add(str(data.target))
    return list(results)


def get_a(domain, nameservers=[]):
    result = get_dns_record(domain, 'A', nameservers=nameservers)
    if result:
        for data in result:
            return data.address
    return

def get_soa(domain, nameservers=[]):
    results = []
    result = get_dns_record(domain, 'SOA', nameservers=nameservers)
    if result:
        for rdata in result:
            results.append({
                'serial': int(rdata.serial),
                'tech': str(rdata.rname),
                'refresh': int(rdata.refresh),
                'retry': int(rdata.retry),
                'expire': int(rdata.expire),
                'minimum': int(rdata.minimum),
                'mname': str(rdata.mname)
            })
    return results

def get_mx(domain, nameservers=[]):
    results = set()
    result = get_dns_record(domain, 'MX', nameservers=nameservers)
    if result:
        for data in result:
            results.add(str(data.exchange))
    return list(results)

def get_txt(domain, nameservers=[]):
    results = set()
    result = get_dns_record(domain, 'TXT', nameservers=nameservers)
    if result:
        for data in result:
            results.add(str(data))
    return list(results)

@retry(SocketError, tries=20, delay=1, backoff=0.5, logger=logging.getLogger())  # 1.8 hrs
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
        website = urlopen(url)
        html = website.read()
    except:
        url = 'http://' + host
        log.warn('Trying %s' % url)
        try:
            website = urlopen(url)
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
