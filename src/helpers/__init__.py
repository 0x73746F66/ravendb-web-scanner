import os, hashlib, time, requests, logging, colorlog, gzip, shutil, re, mmap, multiprocessing, gc
from os import path, getcwd, isatty
from functools import wraps
from yaml import load
from ftplib import FTP
from bitmath import Byte
from progressbar import ProgressBar
from datetime import datetime

from models import get_db, Domain, is_domain_updated

config = None
session = None

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
                except ExceptionToCheck as e:
                    msg = "%s, Retrying in %d seconds..." % (str(e), mdelay)
                    if logger:
                        logger.warning(msg)
                    else:
                        print(msg)
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
                except Exception as e:
                    logger.exception(e)
                    break
            return f(*args, **kwargs)

        return f_retry  # true decorator

    return deco_retry

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
        formatter = colorlog.ColoredFormatter(
            cformat, date_format, log_colors=colors)
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
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)

def decompress(file_path, new_dest):
    with gzip.open(file_path, 'rb') as f_in:
        with open(new_dest, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    return new_dest

def split_file(filepath, lines_per_file=100000):
    lpf = lines_per_file
    path, filename = os.path.split(filepath)
    files = []
    with open(filepath, 'r') as r:
        name, ext = os.path.splitext(filename)
        try:
            w = open(os.path.join(path, '{}_{}{}'.format(name, 0, ext)), 'w')
            for i, line in enumerate(r):
                if not i % lines_per_file:
                    w.close()
                    filename = os.path.join(path, '{}_{}{}'.format(name, i, ext))
                    w = open(filename, 'w')
                    files.append(filename)
                w.write(line)
        finally:
            w.close()
    return files

def parse_zonefile(zonefile_path, regex, document={}, n_cpus=2):
    log = logging.getLogger()
    if not path.isfile(zonefile_path):
        log.error('missing zonefile %s' % zonefile_path)
        return

    checkpoint = 0
    checkpoint_path = zonefile_path + '.checkpoint'
    if path.isfile(checkpoint_path):
        with open(checkpoint_path, 'r') as f:
            checkpoint = int(f.read())

    pattern = re.compile(bytes(regex.encode('utf8')), re.DOTALL | re.IGNORECASE | re.MULTILINE)
    log.info('Splitting %s' % zonefile_path)
    for file_path in split_file(zonefile_path):
        check = int(path.basename(file_path).split('_')[1].split('.')[0])
        if check < checkpoint:
            log.info('Already processed %s. skipping..' % file_path)
            continue
        log.info('Reading lines of %s' % file_path)
        with open(checkpoint_path, 'w') as f:
            f.write(str(check))
        gc.collect()
        p = multiprocessing.Pool()
        p.map(_save, _parse(file_path, zonefile_path, pattern, document), n_cpus)
        p.close()
        p.join()
    os.unlink(checkpoint_path)

def _parse(file_part_path, zonefile_path, pattern, document={}):
    with open(file_part_path, 'r') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            for domain, ttl, ns in pattern.findall(m):
                d = {
                    'fqdn': '%s.%s' % (domain.decode('utf-8'), document['tld']),
                    'domain': domain.decode('utf-8'),
                    'local_file': zonefile_path,
                    'nameserver': ns.decode('utf-8').lower(),
                    'ttl': 86400 if not ttl.decode('utf-8').strip() else int(ttl)
                }
                yield {**document, **d}
def _save(document):
    log = logging.getLogger()
    zonefiles_db = get_db('zonefiles')
    with zonefiles_db.open_session() as session:
        query_result = list(session.query(object_type=Domain).where(fqdn=document['fqdn'], nameserver=document['nameserver']).order_by_descending('saved_at_unix'))
        document['saved_at'] = datetime.utcnow().replace(microsecond=0).isoformat()
        domain = Domain(**document)
        if not query_result:
            log.info('Saving new document for %s' % domain.fqdn)
            session.store(domain)
            session.save_changes()
        elif is_domain_updated(domain, query_result[0]):
            log.info('Saving updated document for %s' % domain.fqdn)
            session.store(domain)
            session.save_changes()

@retry(Exception, tries=5, delay=1.5, backoff=3, logger=logging.getLogger())
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

