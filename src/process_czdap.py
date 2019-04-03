#!/usr/bin/env python
import logging, time, re, argparse, json, urllib3
from os import path, makedirs
from datetime import datetime
from pyravendb.custom_exceptions.exceptions import AllTopologyNodesDownException

from helpers import *
from models import *
from czdap import *

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def get_zonefile_previous_line_count(ravendb_key):
    stored_zonefile = None
    previous_line_count = 0
    zonefiles_db = get_db('zonefiles')
    with zonefiles_db.open_session() as session:
        stored_zonefile = session.load(ravendb_key)
        if stored_zonefile and hasattr(stored_zonefile, 'line_count') and stored_zonefile.line_count:
            previous_line_count = stored_zonefile.line_count
    return previous_line_count, stored_zonefile

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

            ravendb_key = 'Zonefile/%s' % tld
            previous_line_count, _ = get_zonefile_previous_line_count(ravendb_key)
            pattern = re.compile(bytes(regex.encode('utf8')), re.DOTALL | re.IGNORECASE | re.MULTILINE)
            line_count = file_line_count(local_file, pattern)

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
                previous_line_count=previous_line_count,
                line_count=line_count
            )
            _save(ravendb_key, zonefile)
            process_files = split_zonefile(zonefile, split_lines=10000)
            if not process_files:
                continue
            for zonefile_part_path in process_files:
                log.info('Queuing %s' % zonefile_part_path)
                ravendb_key = 'ZonefilePart/%s' % path.splitext(path.split(zonefile_part_path)[1])[0]
                _save_zonefile_part(ravendb_key, ZonefilePartQueue(
                    tld = zonefile.tld,
                    source = zonefile.source,
                    file_path = zonefile_part_path,
                    added = decompressed_at.isoformat(),
                ))

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def _save(ravendb_key, zonefile):
    log = logging.getLogger()
    zonefiles_db = get_db('zonefiles')
    _, stored_zonefile = get_zonefile_previous_line_count(ravendb_key)
    with zonefiles_db.open_session() as session:
        if not stored_zonefile:
            log.info('Saving new zonefile for %s' % zonefile.tld)
        elif is_zonefile_updated(zonefile, stored_zonefile):
            log.info('Replacing zonefile for %s' % zonefile.tld)
            session.delete(ravendb_key)
            session.save_changes()
    with zonefiles_db.open_session() as session:
        session.store(zonefile, ravendb_key)
        session.save_changes()

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def _save_zonefile_part(ravendb_key, zonefile_part_queue):
    log = logging.getLogger()
    q_db = get_db("queue")
    with q_db.open_session() as session:
        if session.load(ravendb_key):
            return
    log.info('Saving new zonefile part queue for .%s' % zonefile_part_queue.tld)
    with q_db.open_session() as session:
        session.store(zonefile_part_queue, ravendb_key)
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
    get_db("queue", ravendb_conn)
    main()