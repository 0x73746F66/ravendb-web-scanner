#!/usr/bin/env python
import logging, time, re, argparse, json
from os import path, makedirs
from datetime import datetime
from pyravendb.custom_exceptions.exceptions import AllTopologyNodesDownException

from helpers import *
from models import *
from czdap import *

@retry((AllTopologyNodesDownException), tries=5, delay=1.5, backoff=3, logger=logging.getLogger())
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

    zonefiles_db = get_db('zonefiles')
    for remote_path in zone_links:
        tld = ''.join(''.join(remote_path.split('/')[-1:]).split('.')[0])
        started_at = datetime.utcnow().replace(microsecond=0)
        local_compressed_file, downloaded = download(remote_path, output_directory, access_token)
        if downloaded:
            downloaded_at = datetime.utcnow().replace(microsecond=0)
            local_file = local_compressed_file.replace('.gz', '')
            log.info("Decompressing zone file to %s" % local_compressed_file)
            decompress(local_compressed_file, local_file)
            decompressed_at = datetime.utcnow().replace(microsecond=0)
            zonefile = Zonefile(
                tld=tld,
                source='czdap',
                started_at=started_at.isoformat(), 
                downloaded_at=downloaded_at.isoformat(), 
                decompressed_at=decompressed_at.isoformat(), 
                remote_path=remote_path,
                local_compressed_file=local_compressed_file,
                local_compressed_file_size=path.getsize(local_compressed_file),
                local_file=local_file, 
                local_file_size=path.getsize(local_file),
            )
            ravendb_key = 'Zonefile/%s' % zonefile.tld
            with zonefiles_db.open_session() as session:
                stored_zonefile = session.load(ravendb_key)
                if not stored_zonefile:
                    log.info('Saving new zonefile for %s' % zonefile.tld)
                elif is_zonefile_updated(zonefile, stored_zonefile):
                    log.info('Replacing zonefile for %s' % zonefile.tld)
                    session.delete(ravendb_key)
                    session.save_changes()
            with zonefiles_db.open_session() as session:
                session.store(zonefile, ravendb_key)
                session.save_changes()
        
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='open net scans')
    parser.add_argument('-c', '--config_file', default='config.yaml', help='absolute path to config file')
    parser.add_argument('--verbose', '-v', action='count', default=0)
    args = parser.parse_args()

    log_level = args.verbose if args.verbose else 3
    setup_logging(log_level)
    c = get_config(config_file=args.config_file)
    ravendb_conn = '{}://{}:{}'.format(
        c['ravendb'].get('proto'),
        c['ravendb'].get('host'),
        c['ravendb'].get('port'),
    )
    get_db("zonefiles", ravendb_conn)
    main()

