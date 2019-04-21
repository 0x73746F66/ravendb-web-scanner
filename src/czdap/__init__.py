import logging, requests, json
from os import path, errno
from glob import glob
from bitmath import Byte

from helpers import get_config, get_session, retry

def do_get(url, access_token):
    session = get_session()
    bearer_headers = {'Content-Type': 'application/json',
                      'Accept': 'application/json',
                      'Authorization': 'Bearer {0}'.format(access_token)}

    response = session.get(url, params=None, headers=bearer_headers)

    return response

def get_remote_stat(url, access_token):
    session = get_session()
    log = logging.getLogger()
    bearer_headers = {'Content-Type': 'application/json',
                      'Accept': 'application/json',
                      'Authorization': 'Bearer {0}'.format(access_token)}

    r = session.head(url, params=None, headers=bearer_headers)
    if r.status_code != 200:
        log.error(f"Unexpected HTTP response code {r.status_code} for URL {url}")
        return None, None
    dest_file = r.headers['Content-disposition'].replace('attachment;filename=', '').replace('"', '', 2)
    file_size = int(r.headers['Content-Length'])

    return dest_file, file_size

@retry((LookupError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
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

def get_local_files(dest_dir):
    files = []
    for filepath in glob(f'{dest_dir}/*.txt.gz'):
        filename = ''.join(filepath.split('/')[-1:])
        files.append(filename)

    return files

@retry((requests.exceptions.ConnectionError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def download(url, output_directory, access_token):
    log = logging.getLogger()
    local_files = get_local_files(output_directory)
    remote_file, file_size = get_remote_stat(url, access_token)
    file_path = '{0}/{1}'.format(output_directory, remote_file)
    if not remote_file:
        log.error(f"Could not check remote file [{url}] cancelling download..")
        return file_path, False
    if remote_file in local_files:
        try:
            local_size = path.getsize(file_path)
        except OSError as e:
            if e.errno == errno.ENOENT:
                local_size = 0
            else:
                raise
        if local_size == file_size:
            log.info(f"Matched local file [{remote_file}] skipping download..")
            return file_path, False

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

        log.info(f"Completed downloading zone to file {file_path}")
        return file_path, True
    elif status_code == 401:
        log.warn("The access_token has been expired")
        c = get_config()
        authen_base_url = c['czdap'].get('authentication_base_url')
        username = c['czdap'].get('username')
        password = c['czdap'].get('password')
        access_token = authenticate(username, password, authen_base_url)
        return download(url, output_directory, access_token)
    elif status_code == 404:
        log.warn(f"No zone file found for {url}")
    else:
        log.critical('Failed to download zone from {0} with code {1}'.format(url, status_code))

    return file_path, False
