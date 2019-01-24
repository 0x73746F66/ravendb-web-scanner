#!/usr/bin/env python
# -*- coding:utf-8
import requests, logging, colorlog, argparse, mysql.connector, shelve, OpenSSL, ssl, socket
import dns, dns.resolver, json, shodan, time, urllib2, re, multiprocessing
from functools import wraps
from os import path, getcwd, isatty, makedirs
from urlparse import urljoin, urlparse
from mysql.connector import errorcode
from yaml import load
from datetime import datetime
from pythonwhois import get_whois
from pythonwhois.shared import WhoisException
from socket import error as SocketError

config = None
session = None


def sanitize(filter):
    """ TODO
    SQLi protection
    """
    return filter


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


def get_from_model(table_name, key, default=None):
    model_file = path.join(
        path.realpath(getcwd()), 'model', '%s.yaml' % table_name)
    with open(model_file, 'r') as f:
        schema = load(f.read())

    return schema.get(key, default)


def sql(query):
    log = logging.getLogger()
    c = get_config()
    rows = None
    cnx = None
    try:
        log.debug('Creating database connection')
        cnx = mysql.connector.connect(
            user=c['mysql'].get('user'),
            password=c['mysql'].get('passwd', ''),
            host=c['mysql'].get('host', 'localhost'),
            port=c['mysql'].get('port', 3306),
            database=c['mysql'].get('db'))
        cursor = cnx.cursor()
        log.debug('Executing query\n%s' % query)
        cursor.execute(query)
        if query.startswith('SELECT'):
            rows = cursor.fetchall()
        else:
            cnx.commit()
            rows = cursor.lastrowid
        cursor.close()
    except mysql.connector.Error as err:
        if cnx:
            cnx.rollback()
            log.warning('Closing database connection after exception')
            cnx.close()
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            log.critical("Something is wrong with your user name or password")
            exit(1)
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            log.critical("Database does not exist")
            exit(1)
        else:
            log.critical(err)
            log.info(query)
            exit(1)

    if cnx:
        log.debug('Closing database connection')
        cnx.close()

    return rows


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
    finally:
        sock.close()
    PEM = ssl.DER_cert_to_PEM_cert(DER)
    return PEM, r.headers


@retry((dns.resolver.NoNameservers, dns.exception.Timeout),
       tries=20,
       delay=1,
       backoff=0.5,
       logger=logging.getLogger())  # 1.8 hrs
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


@retry((SocketError), tries=20, delay=1, backoff=0.5, logger=logging.getLogger())  # 1.8 hrs
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
    c = get_config(config_file=args.config_file)
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
    if not path.exists(spider_dir):
        makedirs(spider_dir)

    html = None
    url = 'https://' + host
    try:
        website = urllib2.urlopen(url)
        html = website.read()
    except:
        url = 'http://' + host
        try:
            website = urllib2.urlopen(url)
            html = website.read()
        except:
            pass
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


@retry((Exception), tries=20, delay=1, backoff=0.5, logger=logging.getLogger())  # 1.8 hrs
def process(domain_a):
    c = get_config(config_file=args.config_file)
    log = logging.getLogger()

    base_dir = c['osint'].get('base_dir').format(home=path.expanduser('~'))
    stale_days = c['records'].get('stale_days', 0)

    if not NO_CACHE:
        cache_path = c['records'].get('cache_path', 'pyshelf.db')
        cache = shelve.open(cache_path, writeback=True)
    try:
        for fqdn, ns_a in domain_a.items():
            now = datetime.utcnow().replace(microsecond=0)
            should_process = True if NO_CACHE else False
            key = 'osint_' + str(fqdn)

            if not NO_CACHE:
                last_scanned = now
                if cache.has_key(key):
                    log.info('%s cache hit' % fqdn)
                    last_scanned = datetime.strptime(
                        str(cache[key]), '%Y-%m-%dT%H:%M:%S')
                else:
                    log.info('%s cache miss' % fqdn)
                    should_process = True

                delta = now - last_scanned
                if delta.days > stale_days:
                    should_process = True
                    log.info('%s is stale, processing' % fqdn)
                    continue

            if not should_process:
                continue

            if not NO_CACHE:
                cache[key] = now.isoformat()
            updated_date = now.strftime('%Y-%m-%d')
            if save_whois(fqdn, whois_dir=path.join(base_dir, c['osint'].get('whois_dir').format(domain=fqdn))):
                log.info('saved whois for %s' % fqdn)

            host = get_a(fqdn, nameservers=list(ns_a))
            if host and save_shodan(host, shodan_dir=path.join(base_dir, c['osint'].get('shodan_dir').format(domain=fqdn))):
                log.info('saved shodan for %s' % fqdn)

            dns_dir = path.join(base_dir, c['osint'].get('dns_dir').format(domain=fqdn))
            if not path.exists(dns_dir):
                makedirs(dns_dir)

            dns_data = {
                'updated_date': updated_date,
                'a': host,
                'cname': get_cnames(fqdn, nameservers=list(ns_a)),
                'mx': get_mx(fqdn, nameservers=list(ns_a)),
                'soa': get_soa(fqdn, nameservers=list(ns_a)),
                'txt': get_txt(fqdn, nameservers=list(ns_a))
            }
            file_name = path.join(dns_dir, updated_date + '.json')
            with open(file_name, 'w+') as f:
                log.info('saved dns data for %s' % fqdn)
                f.write(json.dumps(dns_data, default=lambda o: o.isoformat() if isinstance(o, (datetime)) else str(o) ))

            https_dir = path.join(base_dir, c['osint'].get('https_dir').format(domain=fqdn))
            if not path.exists(https_dir):
                makedirs(https_dir)
            PEM, headers = get_certificate(fqdn)
            if headers:
                file_name = path.join(https_dir, updated_date + '_headers.json')
                with open(file_name, 'w+') as f:
                    log.info('saved https headers for %s' % fqdn)
                    f.write(json.dumps(headers, default=lambda o: o.isoformat() if isinstance(o, (datetime)) else str(o)))
            if not PEM:
                continue
            file_name = path.join(https_dir, updated_date + '_key.pem')
            with open(file_name, 'w+') as f:
                log.info('saved key.pem for %s' % fqdn)
                f.write(PEM)
            cert = get_certificate_detail(cert=PEM)
            if not cert:
                continue
            file_name = path.join(https_dir, updated_date + '_key_detail.json')
            with open(file_name, 'w+') as f:
                log.info('saved https cert detail for %s' % fqdn)
                f.write(json.dumps(cert, default=lambda o: o.isoformat() if isinstance(o, (datetime)) else str(o) ))
            if not cert.has_key('subjectAltName'):
                continue
            log.info('found subjectAltName %s' % cert['subjectAltName'])
            hosts = set(fqdn)
            for domain in cert['subjectAltName'].split(','):
                hosts.add(''.join(domain.split('DNS:')).strip())
            for host in hosts:
                if save_spider(host, spider_dir=path.join(base_dir, c['osint'].get('spider_dir').format(domain=fqdn))):
                    log.info('saved spider for %s' % host)

    finally:
        if not NO_CACHE:
            cache.close()


if __name__ == '__main__':
    global NO_CACHE
    parser = argparse.ArgumentParser(description='open net scans')
    parser.add_argument('-c', '--config-file', default='config.yaml', help='absolute path to config file')
    parser.add_argument('-L', '--limit', type=int, default=5000)
    parser.add_argument('-n', '--no-cache', default=False, action='store_true')
    parser.add_argument('--verbose', '-v', action='count', default=0)
    args = parser.parse_args()

    NO_CACHE = args.no_cache

    log_level = args.verbose if args.verbose else 3
    setup_logging(log_level)

    num_records = int(sql('SELECT COUNT(*) FROM domain')[0][0])
    offset = 0
    loop = 0
    loops = 1 + (num_records / args.limit)

    processes = []
    while loops != 0:
        loop += 1
        query = "SELECT CONCAT(d.name, '.', t.name) as fqdn, n.nameserver FROM scans.domain d INNER JOIN scans.tld t ON d.tld_id = t.id LEFT JOIN scans.link_domain_ns l ON d.id = l.domain_id LEFT JOIN scans.nameservers n ON n.id = l.ns_id ORDER BY d.updated DESC"
        q_limit = ' LIMIT %d, %d' % (offset, args.limit)
        query += q_limit

        domain_a = {}
        for d, ns in sql(query):
            if not d in domain_a:
                domain_a[d] = set()
            domain_a[d].add(ns)

        t = multiprocessing.Process(target=process, args=(domain_a, ))
        processes.append(t)
        t.start()
        offset = args.limit * loop
        loops -= 1

    for one_process in processes:
        one_process.join()