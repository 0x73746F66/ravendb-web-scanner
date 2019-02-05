#!/usr/bin/env python
import logging, time, colorlog, re, shutil, gzip, argparse, json, operator, multiprocessing, requests
from os import path, isatty, getcwd, makedirs, errno
from yaml import load
from functools import wraps
from datetime import datetime
from bitmath import Byte
from glob import glob

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

@retry(LookupError, tries=5, delay=1.5, backoff=3, logger=logging.getLogger())
def authenticate(username, password, authen_base_url):
    log = logging.getLogger()
    authen_headers = {'Content-Type': 'application/json',
                      'Accept': 'application/json'}
    credential = {'username': username,
                  'password': password}
    authen_url = authen_base_url + '/api/authenticate'
    response = requests.post(authen_url, data=json.dumps(credential), headers=authen_headers)
    status_code = response.status_code

    # Return the access_token on status code 200. Otherwise, terminate the program.
    if status_code == 200:
        access_token = response.json()['accessToken']
        log.info('Received access_token')
        return access_token
    elif status_code == 404:
        log.critical("Invalid url " + authen_url)
        exit(1)
    elif status_code == 401:
        log.critical("Invalid username/password. Please reset your password via web")
        exit(1)
    elif status_code == 500:
        log.error("Internal server error. Please try again later")
        raise LookupError
    else:
        log.critical("Failed to authenticate user {0} with error code {1}".format(username, status_code))
        exit(1)

def do_get(url, access_token):
    session = get_session()
    bearer_headers = {'Content-Type': 'application/json',
                      'Accept': 'application/json',
                      'Authorization': 'Bearer {0}'.format(access_token)}

    response = session.get(url, params=None, headers=bearer_headers)

    return response

def get_local_files(dest_dir):
    files = []
    for filepath in glob('%s/*.txt.gz' % dest_dir):
        filename = ''.join(filepath.split('/')[-1:])
        files.append(filename)

    return files

def get_remote_stat(url, access_token):
    session = get_session()
    log = logging.getLogger()
    bearer_headers = {'Content-Type': 'application/json',
                      'Accept': 'application/json',
                      'Authorization': 'Bearer {0}'.format(access_token)}

    r = session.head(url, params=None, headers=bearer_headers)
    if r.status_code != 200:
        log.error("Unexpected HTTP response code %d for URL %s" % (r.status_code, url))
        return None, None
    dest_file = r.headers['Content-disposition'].replace('attachment;filename=', '').replace('"', '', 2)
    file_size = int(r.headers['Content-Length'])

    return dest_file, file_size

def download(url, output_directory, access_token):
    log = logging.getLogger()
    local_files = get_local_files(output_directory)
    remote_file, file_size = get_remote_stat(url, access_token)
    if not remote_file:
        log.error("Could not check remote file [%s] cancelling download.." % url)
        return
    file_path = '{0}/{1}'.format(output_directory, remote_file)
    if remote_file in local_files:
        try:
            local_size = path.getsize(file_path)
        except OSError as e:
            if e.errno == errno.ENOENT:
                local_size = 0
            else:
                raise
        if local_size == file_size:
            log.info("Matched local file [%s] skipping download.." % remote_file)
            return file_path

    human_size = Byte(file_size).best_prefix()
    log.info("Downloading [{size}] {uri}".format(
        size=human_size,
        uri=url
    ))
    download_zone_response = do_get(url, access_token)
    status_code = download_zone_response.status_code

    if status_code == 200:
        with open(file_path, 'wb') as f:
            for chunk in download_zone_response.iter_content(1024):
                f.write(chunk)

        log.info("Completed downloading zone to file %s" % file_path)

    elif status_code == 401:
        log.info("The access_token has been expired")
        c = get_config()
        authen_base_url = c['czdap'].get('authentication_base_url')
        username = c['czdap'].get('username')
        password = c['czdap'].get('password')
        access_token = authenticate(username, password, authen_base_url)
        return download(url, output_directory, access_token)
    elif status_code == 404:
        log.error("No zone file found for %s" % url)
    else:
        log.error('Failed to download zone from {0} with code {1}'.format(url, status_code))

    return file_path

def decompress(file_path, new_dest):
    with gzip.open(file_path, 'rb') as f_in:
        with open(new_dest, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    return new_dest


def main():
    log = logging.getLogger()
    c = get_config()
    authen_base_url = c['czdap'].get('authentication_base_url')
    czds_base_url = c['czdap'].get('czds_base_url')
    output_directory = c.get('tmp_dir')
    username = c['czdap'].get('username')
    password = c['czdap'].get('password')
    regex = c['czdap'].get('regex')
    access_token = authenticate(username, password, authen_base_url)
    links_url = czds_base_url + "/czds/downloads/links"
    links_response = do_get(links_url, access_token)
    status_code = links_response.status_code
    zone_links = None
    if status_code == 200:
        zone_links = links_response.json()
        log.info("The number of zone files to be downloaded is %d" % len(zone_links))
    elif status_code == 401:
        log.error("The access_token has been expired. Re-authenticate user {0}".format(username))
    else:
        log.error("Failed to get zone links from {0} with error code {1}".format(links_url, status_code))
    if not zone_links:
        exit(1)

    if not path.exists(output_directory):
        makedirs(output_directory)

    for link in zone_links:
        tld = ''.join(''.join(link.split('/')[-1:]).split('.')[0])
        file_path = download(link, output_directory, access_token)
        new_dest = file_path.replace('.gz', '')
        log.info("Decompressing zone file to %s" % new_dest)
        decompress(file_path, new_dest)
        log.info('Parsing %s' % new_dest)
        scanned = datetime.utcnow().replace(microsecond=0).isoformat()
        pool = multiprocessing.Pool(c.get('multiprocessing_pools', 1000))
        try:
            for new_json_data in parse_file(new_dest, regex):
                new_json_data['remote_file'] = link
                new_json_data['scanned'] = scanned
                new_json_data['tld'] = tld
                new_json_data['fqdn'] = str('.'.join([new_json_data['domain'], tld]))
                pool.apply_async(write_to_json, args=(new_json_data, ))
        finally:
            pool.close()
        pool.join()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='open net scans')
    parser.add_argument('-c', '--config_file', default='config.yaml', help='absolute path to config file')
    parser.add_argument('--verbose', '-v', action='count', default=0)
    args = parser.parse_args()

    log_level = args.verbose if args.verbose else 3
    setup_logging(log_level)
    get_config(config_file=args.config_file)

    main()

