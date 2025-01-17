import hashlib, time, requests, logging, colorlog, gzip, shutil, re, mmap, multiprocessing, gc, urllib3
from os import path, getcwd, isatty
from functools import wraps
from yaml import load
from ftplib import FTP, all_errors
from bitmath import Byte
from progressbar import ProgressBar
from datetime import datetime
from pyravendb.custom_exceptions.exceptions import AllTopologyNodesDownException
from socket import error as SocketError
from retry import retry

from models import *

config = None
session = None

class RetryCatcher(Exception):
    def __init__(self, message):
        super().__init__(message)

def get_session():
  global session

  if not session:
    session = requests.Session()

  return session

def get_config(config_file=None):
    global config

    if not config:
        if not config_file:
            config_file = path.join(path.realpath(getcwd()), 'config.yaml')
        with open(config_file, 'r') as f:
            config = load(f.read())

    return config

def setup_logging(log_level, file_path=None):
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
        formatter = colorlog.ColoredFormatter(
            cformat, date_format, log_colors=colors)
    else:
        formatter = logging.Formatter(format_str, date_format)

    if log_level > 0:
        if file_path:
            file_handler = logging.StreamHandler(open(file_path, 'a+'))
            file_handler.setFormatter(formatter)
            log.addHandler(file_handler)
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

def decompress(file_path, new_dest):
    with gzip.open(file_path, 'rb') as f_in:
        with open(new_dest, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    return new_dest

def make_split_filename(filepath, numeric):
    path_part, filename = path.split(filepath)
    name, ext = path.splitext(filename)
    return path.join(path_part, '{}_{}{}'.format(name, numeric, ext))

def split_file(filepath, lines_per_file=100000):
    path_part, filename = path.split(filepath)
    files = []
    with open(filepath, 'r') as r:
        name, ext = path.splitext(filename)
        try:
            w = open(path.join(path_part, '{}_{}{}'.format(name, 0, ext)), 'w')
            for i, line in enumerate(r):
                if not i % lines_per_file:
                    w.close()
                    filename = make_split_filename(filepath, i)
                    w = open(filename, 'w')
                    files.append(filename)
                w.write(line)
        finally:
            w.close()
    return files

def splitfile_rounding(split_lines, line_count):
    if line_count < split_lines:
        return 0
    if line_count == split_lines:
        return split_lines
    return int(line_count / split_lines) * split_lines

def file_line_count(filename, pattern=None):
    lines = 0
    f = open(filename, "r+")
    try:
        if not pattern:
            buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            while buf.readline():
                lines += 1
        else:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                for _ in pattern.findall(m):
                    lines += 1
    finally:
        f.close()
    return lines

def split_zonefile(zonefile, split_lines=100000):
    log = logging.getLogger()
    if not path.isfile(zonefile.local_file):
        return None

    if zonefile.line_count == zonefile.previous_line_count:
        return []
    log.info('Splitting %s' % zonefile.local_file)
    split_files = split_file(zonefile.local_file, lines_per_file=split_lines)
    process_files = []
    last_file_processed = make_split_filename(zonefile.local_file, splitfile_rounding(split_lines, zonefile.previous_line_count))
    for f in reversed(split_files):
        process_files.append(f)
        if f == last_file_processed:
            break
    else:
        process_files = reversed(split_files)
    return process_files

def parse_zonefile(zonefile, file_path, regex, document={}, n_cpus=2):
    log = logging.getLogger()
    pattern = re.compile(bytes(regex.encode('utf8')), re.DOTALL | re.IGNORECASE | re.MULTILINE)
    log.info('Reading lines of %s' % file_path)
    if not n_cpus or n_cpus <= 1:
        for doc in _parse(file_path, zonefile, pattern, document):
            _save(doc)
    else:
        gc.collect()
        p = multiprocessing.Pool(processes=n_cpus)
        p.map(_save, _parse(file_path, zonefile, pattern, document))
        p.close()
        p.join()

def _parse(file_part_path, zonefile, pattern, document={}):
    log = logging.getLogger()
    with open(file_part_path, 'r') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            log.debug('extracting domains using regex')
            for domain, ttl, ns in pattern.findall(m):
                log.debug('found %s' % '%s.%s' % (domain.decode('utf-8'), document['tld']))
                d = {
                    'fqdn': '%s.%s' % (domain.decode('utf-8'), document['tld']),
                    'domain': domain.decode('utf-8'),
                    'local_file': zonefile.local_file,
                    'nameserver': ns.decode('utf-8').lower(),
                    'ttl': 86400 if not ttl.decode('utf-8').strip() else int(ttl)
                }
                yield {**document, **d}
        log.debug('finished extraction')

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, urllib3.exceptions.ConnectionError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def _save(document):
    log = logging.getLogger()
    store = get_db('zonefiles')
    ravendb_key = 'Domain/%s' % document['fqdn']
    nameservers = set()
    nameservers.add(document['nameserver'])
    with store.open_session() as session:
        stored_zonefile = session.load(ravendb_key)
        if stored_zonefile:
            log.info('Replacing domain for %s' % document['fqdn'])
            for ns in stored_zonefile.nameserver.split(','):
                nameservers.add(ns)
        else:
            log.info('Saving new domain for %s' % document['fqdn'])

        document['nameserver'] = ','.join(sorted(nameservers))
        document['saved_at'] = datetime.utcnow().replace(microsecond=0).isoformat()
        domain = Domain(**document)
        session.delete(ravendb_key)
        session.save_changes()
    with store.open_session() as session:
        session.store(domain, ravendb_key)
        session.save_changes()

    save_to_queue(ravendb_key, DomainQueue(
        name = domain.fqdn,
        added = domain.saved_at
    ))
    save_to_queue('Whois/%s' % domain.fqdn, WhoisQueue(
        name=domain.fqdn,
        added=domain.saved_at
    ))
    save_to_queue('DepScan/%s' % domain.fqdn, DepScanQueue(
        name=domain.fqdn,
        added=domain.saved_at
    ))

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, urllib3.exceptions.ConnectionError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def get_next_from_queue(object_type, take=1):
    log = logging.getLogger()
    store = get_db('queue')
    generate = True
    while generate:
        with store.open_session() as session:
            queue = list(session.query(object_type=object_type).order_by_descending('added_unix').take(take))
            if not queue:
                generate = False
            for item in queue:
                log.debug('item %s' % item)
                if isinstance(item, ZonefilePartQueue):
                    ravendb_key = 'ZonefilePart/%s' % path.splitext(path.split(item.file_path)[1])[0]
                    log.debug('deleteing %s' % ravendb_key)
                    delete_queue_item(ravendb_key)
                if isinstance(item, DomainQueue):
                    ravendb_key = 'Domain/%s' % item.name
                    log.debug('deleteing %s' % ravendb_key)
                    delete_queue_item(ravendb_key)
                if isinstance(item, WhoisQueue):
                    ravendb_key = 'Whois/%s' % item.name
                    log.debug('deleteing %s' % ravendb_key)
                    delete_queue_item(ravendb_key)
                if isinstance(item, DepScanQueue):
                    ravendb_key = 'DepScan/%s' % item.name
                    log.debug('deleteing %s' % ravendb_key)
                    delete_queue_item(ravendb_key)
            yield queue

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, urllib3.exceptions.ConnectionError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def delete_queue_item(ravendb_key):
    # log = logging.getLogger()
    with get_db('queue').open_session() as session:
        # log.debug('loading entity for %s' % ravendb_key)
        # entity = session.load(ravendb_key)
        # log.debug('deleting entity %s' % entity)
        # session.delete(entity)
        session.delete(ravendb_key)
        session.save_changes()

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, urllib3.exceptions.ConnectionError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def save_to_queue(ravendb_key, item):
    log = logging.getLogger()
    q_db = get_db("queue")
    with q_db.open_session() as session:
        if session.load(ravendb_key):
            return
    log.info('Saving to queue: %s' % ravendb_key)
    with q_db.open_session() as session:
        session.store(item, ravendb_key)
        session.save_changes()

@retry(all_errors, tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def ftp_session(server, user, passwd, use_pasv=True):
    ftp = FTP(server)
    if use_pasv:
        ftp.set_pasv(True)
    ftp.login(user, passwd)
    return ftp

def ftp_download(ftp, remote_source, local_filename):
    log = logging.getLogger()
    filesize = ftp_filesize(ftp, remote_source)
    human_size = Byte(filesize).best_prefix()
    log.info('downloading %s to %s' % (human_size, local_filename))
    progress = ProgressBar(maxval=filesize)
    with open(local_filename, 'wb') as f:
        def download_file(chunk):
            f.write(chunk)
            progress.update(len(chunk))
        progress.start()
        ftp.retrbinary('RETR %s' % remote_source, download_file)
    progress.finish()
    return local_filename

def ftp_filesize(ftp, filename):
    global stat

    def put_stat(s):
        global stat
        stat = s

    size = 0
    log = logging.getLogger()
    log.info('checking file size for %s' % filename)
    regex = r"^[-rwx]{10}\s+\d+\s+\w+\s+\w+\s+(\d+)\s+(.+)\s.+$"
    ftp.dir(filename, lambda data: put_stat(data))
    match = re.search(regex, stat)
    if match:
        size, last_mod_date = match.groups()
    try:
        ftp.sendcmd("TYPE i")  # Switch to Binary mode
        ftp.size(filename, lambda data: put_stat(data))
        size = stat
        ftp.sendcmd("TYPE A")  # Switch to ASCII mode
    except:
        pass

    return int(size)

def validateIntegrity(orighash, destfilepath):
    log = logging.getLogger()
    desthash = None
    with open(destfilepath, "rb") as f:
        desthash = hashlib.md5(f.read()).hexdigest()
    log.debug('md5checksum %s == %s' % (orighash, desthash))
    return orighash == desthash

def md5_checksum(md5_file, target):
    md5hash = None
    with open(md5_file, 'r') as f:
        md5hash = ''.join(re.findall(r"([a-fA-F\d]{32})", f.read()) or [])
    return validateIntegrity(md5hash.strip(), target)

def decode_bytes(d):
    ret = {}
    for key, value in d.items():
        if type(value) == bytes:
            val = value.decode()
        elif isinstance(value, datetime):
            val = value
        elif type(value) == dict:
            val = decode_bytes(value)
        elif type(value) == str:
            val = value
        else:
            val = str(value)
        if type(key) == bytes:
            ret[key.decode()] = val
        else:
            ret[key] = val
    return ret

@retry(SocketError, tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def get_file(host, uri='', use_https=True):
    session = get_session()
    log = logging.getLogger()
    if use_https:
        url = 'https://' + path.join(host, uri)
    else:
        url = 'http://' + path.join(host, uri)

    url = url.replace(":80/", "/").replace(":443/", "/")

    try:
        r = session.head(url, verify=False, timeout=1)
    except:
        if use_https:
            return get_file(host, uri, use_https=False)
        return None
    if not str(r.status_code).startswith('2'):
        if str(r.status_code).startswith('3'):
            log.warning("Ignoring %d redirect for URL %s" % (r.status_code, url))
        elif r.status_code == 403:
            log.warning("Forbidden %s" % url)
        elif r.status_code == 404:
            log.warning("Not Found %s" % url)
        else:
            log.error("Unexpected HTTP response code %d for URL %s" % (r.status_code, url))
        return None

    return session.get(host)

@retry(SocketError, tries=5, delay=1.5, backoff=3, logger=logging.getLogger())
def file_list_filter(file_list: list, content_type: list = [], file_ext: list = []) -> set:
    return_list = set()
    session = get_session()
    log = logging.getLogger()
    for url in file_list:
        if file_ext:
            for ext in file_ext:
                if ext in url:
                    return_list.add(url)
                    log.info(f'added {url}')
                    continue

        if file_ext and not content_type:
            log.info(f'skipping {url}, no ext match')
            continue

        r = session.head(url.replace(":80/", "/").replace(":443/", "/"), verify=False, timeout=3)
        cType = None
        if "Content-Type" in r.headers.keys():
            cType = r.headers["Content-Type"]

        if not cType or cType not in content_type:
            log.info(f'skipping {url}, no content_type match')
            continue

        if not str(r.status_code).startswith('2'):
            if str(r.status_code).startswith('3'):
                log.warning("Ignoring %d redirect for URL %s" % (r.status_code, url))
            elif r.status_code == 403:
                log.warning("Forbidden %s" % url)
            elif r.status_code == 404:
                log.warning("Not Found %s" % url)
            else:
                log.error("Unexpected HTTP response code %d for URL %s" % (r.status_code, url))
            continue
        log.info(f'added {url} based on content_type')
        return_list.add(url)

    return return_list
