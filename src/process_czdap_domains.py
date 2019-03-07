#!/usr/bin/env python
import logging, time, re, argparse, json
from os import path, makedirs
from datetime import datetime, timezone
from pyravendb.custom_exceptions.exceptions import AllTopologyNodesDownException

from helpers import *
from models import *
from czdap import *

@retry((AllTopologyNodesDownException), tries=5, delay=1.5, backoff=3, logger=logging.getLogger())
def main():
    log = logging.getLogger()
    c = get_config()
    output_directory = c.get('tmp_dir')
    if not path.exists(output_directory):
        makedirs(output_directory)

    regex = c['czdap'].get('regex')
    zonefiles_db = get_db('zonefiles')
    zonefiles = set()
    tlds = set()
    three_hours = 21600
    # zonefile changed in last 3 hours
    with zonefiles_db.open_session() as session:
        query_result = list(session.query(object_type=Zonefile).where(source='czdap').where_less_than('downloaded_at_unix', datetime.utcnow().timestamp()-three_hours))
        for z in query_result:
            if z.tld not in tlds:
                tlds.add(z.tld)
                zonefiles.add(z)
    del c, zonefiles_db

    for zonefile in zonefiles:
        scanfile = path.join(output_directory, '%s.scanned' % zonefile.tld)
        if path.isfile(scanfile):
            with open(scanfile, "r") as f:
                val = float(f.read())
                if val == zonefile.decompressed_at_unix:
                    log.info('%s has been scanned. skipping..' % zonefile.local_file)
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
            log.info('Missing %s. Skipping..' % zonefile.local_file)
            continue
        log.info('Parsing %s' % zonefile.tld)
        parse_zonefile(zonefile.local_file, regex, {
            'tld': str(zonefile.tld),
            'remote_file': str(zonefile.remote_path),
            'scanned_at': datetime.utcnow().replace(microsecond=0).isoformat(),
        }, 2)
        with open(scanfile, "w") as f:
            f.write(str(zonefile.decompressed_at_unix))

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
    del ravendb_conn, c, log_level, args, parser
    main()

