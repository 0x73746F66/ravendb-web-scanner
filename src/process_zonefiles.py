#!/usr/bin/env python
import logging, time, re, argparse, json, urllib3
from os import path, makedirs
from datetime import datetime, timezone
from pyravendb.custom_exceptions.exceptions import AllTopologyNodesDownException

from helpers import *
from models import *
from czdap import *

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def get_zonefile_by_zonefilepartqueue(zonefile_part_queue):
    store = get_db('zonefiles')
    with store.open_session() as session:
        return session.load('Zonefile/%s' % zonefile_part_queue.tld)

def main():
    log = logging.getLogger()
    c = get_config()
    n_cpus = int(c['multiprocessing_processes'].get('zonefiles', 1))
    output_directory = c.get('tmp_dir')
    if not path.exists(output_directory):
        makedirs(output_directory)

    regex = c['czdap'].get('regex')
    for zonefile_part_queue in get_next_from_queue(object_type=ZonefilePartQueue):
        if not isinstance(zonefile_part_queue, ZonefilePartQueue):
            break
        zonefile = get_zonefile_by_zonefilepartqueue(zonefile_part_queue)
        if not isinstance(zonefile, Zonefile):
            log.error('%s missing Zonefile. Skipping..' % zonefile_part_queue.file_path)
            continue
        if not path.isfile(zonefile.local_file):
            if not path.isfile(zonefile.local_compressed_file):
                access_token = authenticate(c['czdap'].get('username'), c['czdap'].get('password'), c['czdap'].get('authentication_base_url'))
                log.info('Downloading from %s' % zonefile.remote_path)
                file_path, downloaded = download(zonefile.remote_path, output_directory, access_token)
                if downloaded:
                    log.info('Decompressing to %s' % zonefile.local_file)
                    decompress(file_path, zonefile.local_file)
            else:
                log.info('Decompressing to %s' % zonefile.local_file)
                decompress(zonefile.local_compressed_file, zonefile.local_file)

        if not path.isfile(zonefile.local_file):
            log.error('Missing %s. Skipping..' % zonefile.local_file)
            continue
        log.info('Parsing %s' % zonefile.tld)
        try:
            parse_zonefile(
                zonefile=zonefile, 
                file_path=zonefile_part_queue.file_path,
                regex=regex, 
                n_cpus=n_cpus,
                document={
                    'tld': str(zonefile.tld),
                    'remote_file': str(zonefile.remote_path),
                    'scanned_at': datetime.utcnow().replace(microsecond=0).isoformat(),
                }
            )
        except:
            pass

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
    get_db('zonefiles', ravendb_conn)
    get_db('queue', ravendb_conn)
    del ravendb_conn, c, log_level, args, parser
    main()

