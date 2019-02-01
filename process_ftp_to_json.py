#!/usr/bin/env python
import time, hashlib, argparse, logging, colorlog, re, shutil, gzip, mysql.connector, shelve, json, operator, multiprocessing
from os import path, isatty, getcwd, makedirs
from yaml import load
from ftplib import FTP
from bitmath import Byte
from functools import wraps
from datetime import datetime

config = None


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


def ftp_download(ftp, remote_source, local_filename):
    log = logging.getLogger()
    log.info('downloading to %s' % local_filename)
    with open(local_filename, 'wb') as f:
        ftp.retrbinary('RETR %s' % remote_source, lambda data: f.write(data))
    return local_filename


def ftp_filesize(ftp, filename):
    global stat

    def put_stat(s):
        global stat
        stat = s

    size = 0
    log = logging.getLogger()
    log.info('checking file sze for %s' % filename)
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
    log.info('md5checksum %s == %s' % (orighash, desthash))
    return orighash == desthash


def md5_checksum(md5_file, target):
    md5hash = None
    with open(md5_file, 'r') as f:
        md5hash = ''.join(re.findall(r"([a-fA-F\d]{32})", f.read()) or [])
    return validateIntegrity(md5hash.strip(), target)


def decompress(file_path, new_dest):
    with gzip.open(file_path, 'rb') as f_in:
        with open(new_dest, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    return new_dest


def parse_file(zonefile_path, regex):
    c = get_config()
    log = logging.getLogger()
    DEFAULT_NS_TTL = 86400

    if not path.isfile(zonefile_path):
        log.error('missing zonefile %s' % zonefile_path)
        return

    zonefile = ''.join(zonefile_path.split('/')[-1:])
    with open(zonefile_path, 'r') as f:
        for line in f:
            num = sum(1 for _ in re.finditer(regex, line))
            if num == 0:
                log.debug('No match found for line\n%s' % line)
                continue

            domain, ttl, ns = re.search(regex, line).groups()
            ns = ns.lower()
            domain = domain.lower()
            if ttl:
                ttl = ttl.strip()
            if not ttl.strip():
                ttl = DEFAULT_NS_TTL

            yield {
                'domain': domain,
                'local_file': zonefile,
                'nameservers': [ns],
                'ttl': ttl
            }


def write_to_json(new_json_data):
    log = logging.getLogger()
    conf = get_config()
    data_dir = conf.get('data_dir').format(home=path.expanduser('~'))
    json_dir = path.join(data_dir, new_json_data['fqdn'])
    if not path.exists(json_dir):
        makedirs(json_dir)
    data_path = path.join(json_dir, 'zonefile.json')
    log.info('Writing %s to %s' % (new_json_data['fqdn'], data_path))
    if path.isfile(data_path):
        with open(data_path, 'r') as r:
            try:
                file_data = json.loads(r.read())
            except:
                file_data = new_json_data.copy()
                del file_data['scanned']
                file_data['last_scan'] = u''
                file_data['scans'] = []
    else:
        file_data = new_json_data.copy()
        del file_data['scanned']
        file_data['last_scan'] = u''
        file_data['scans'] = []

    file_data['local_file'] = new_json_data['local_file']
    file_data['remote_file'] = new_json_data['remote_file']
    file_data['ttl'] = new_json_data['ttl']
    will_save = False
    if file_data['last_scan'] == new_json_data['scanned']:
        will_save = True
        for i in range(len(file_data['scans'])):
            if file_data['scans'][i]['scanned'] == new_json_data['scanned']:
                scan = file_data['scans'][i].copy()
                del file_data['scans'][i]
                scan['nameservers'].append(new_json_data['nameservers'][0])
                file_data['nameservers'] = scan['nameservers']

                file_data['scans'].append(scan)
                break
    else:
        file_data['nameservers'] = new_json_data['nameservers']
        found_new = False
        if len(file_data['scans']) == 0:
            will_save = True
            found_new = True
        else:
            file_data['scans'].sort(key=operator.itemgetter('scanned'))
            if file_data['scans'][0]['remote_file'] != new_json_data['remote_file']:
                found_new = True
            if file_data['scans'][0]['local_file'] != new_json_data['local_file']:
                found_new = True
            if file_data['scans'][0]['ttl'] != new_json_data['ttl']:
                found_new = True
            if not found_new:
                for ns in new_json_data['nameservers']:
                    if ns not in file_data['scans'][0]['nameservers']:
                        found_new = True
                        break

        if found_new:
            del new_json_data['domain']
            del new_json_data['tld']
            del new_json_data['fqdn']
            file_data['last_scan'] = new_json_data['scanned']
            file_data['scans'].append(new_json_data)
            will_save = True
    if will_save:
        with open(data_path, 'w+') as f:
            f.write(json.dumps(file_data, default=lambda o: o.isoformat() if isinstance(o, (datetime)) else str(o) ))

@retry(Exception, tries=5, delay=1.5, backoff=3, logger=logging.getLogger())
def ftp_session(server, user, passwd, use_pasv=True):
    ftp = FTP(server)
    if use_pasv:
        ftp.set_pasv(True)
    ftp.login(user, passwd)
    return ftp

def main():
    log = logging.getLogger()
    conf = get_config()
    tmp_dir = conf.get('tmp_dir')
    if not path.isdir(tmp_dir):
        makedirs(tmp_dir)
    zonefile_dir = conf.get('zonefile_dir')
    if not path.isdir(zonefile_dir):
        makedirs(zonefile_dir)

    for c in conf.get('ftp'):
        server = c.get('server')
        user = c.get('user')
        passwd = c.get('passwd')
        regex = c.get('regex')
        ftp = ftp_session(server, user, passwd)
        try:
            if not c.get('files'):
                log.critical('files array needed in ftp conf')
                exit(1)
            for z in c.get('files'):
                md5hash_file = z.get('md5checksum')
                md5_file_path = path.join(tmp_dir, md5hash_file)
                ftp_download(ftp, md5hash_file, md5_file_path)
                target_file = z.get('file_path')
                target_file_path = path.join(zonefile_dir, target_file)
                zonefile_path = path.join(zonefile_dir, target_file.replace('.gz', '.txt', 1))
                download_zonefile = True
                if path.isfile(target_file_path):
                    target_size = ftp_filesize(ftp, target_file)
                    human_size = Byte(target_size).best_prefix()
                    log.info('%s is %s' % (target_file, human_size))
                    if md5_checksum(md5_file_path, target_file_path):
                        log.info('file %s matches checksum. skipping' % target_file)
                        download_zonefile = False

                if download_zonefile and ftp_download(ftp, target_file, target_file_path):
                    log.info('Download %s complete' % target_file)
        finally:
            ftp.quit()

        log.info('Decompressing %s' % target_file)
        decompress(target_file_path, zonefile_path)
        log.info('Parsing %s' % zonefile_path)
        remote = 'ftp://' + user + '@' + path.join(server, target_file)
        scanned = datetime.utcnow().replace(microsecond=0).isoformat()

        pool = multiprocessing.Pool(c.get('multiprocessing_pools', 1000))
        for new_json_data in parse_file(zonefile_path, regex):
            new_json_data['remote_file'] = remote
            new_json_data['scanned'] = scanned
            new_json_data['tld'] = z.get('tld')
            new_json_data['fqdn'] = str('.'.join([new_json_data['domain'], new_json_data['tld']]))
            pool.apply(write_to_json, args=(new_json_data, ))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='open net scans')
    parser.add_argument('-c', '--config_file', default='config.yaml', help='absolute path to config file')
    parser.add_argument('-l', '--reprocess_local_file', help='local zone file to reprocess')
    parser.add_argument('--verbose', '-v', action='count', default=0)
    args = parser.parse_args()

    log_level = args.verbose if args.verbose else 3
    setup_logging(log_level)
    get_config(config_file=args.config_file)

    main()
