#!/usr/bin/env python
import logging, time, re, argparse, json
from os import path, makedirs
from datetime import datetime

from pyravendb.store import document_store

from helpers import *
from models import *
from czdap import *


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

    ravendb_conn = '{}://{}:{}'.format(
        c['ravendb'].get('proto'),
        c['ravendb'].get('host'),
        c['ravendb'].get('port'),
    )
    scans_db = document_store.DocumentStore(urls=[ravendb_conn], database="scans")
    scans_db.initialize()
    zonefiles_db = document_store.DocumentStore(urls=[ravendb_conn], database="zonefiles")
    zonefiles_db.initialize()

    for link in zone_links:
        tld = ''.join(''.join(link.split('/')[-1:]).split('.')[0])
        started_at = datetime.utcnow().replace(microsecond=0)
        file_path = download(link, output_directory, access_token)
        downloaded_at = datetime.utcnow().replace(microsecond=0)
        new_dest = file_path.replace('.gz', '')
        log.info("Decompressing zone file to %s" % new_dest)
        decompress(file_path, new_dest)
        log.info('Parsing %s' % new_dest)        
        decompressed_at = datetime.utcnow().replace(microsecond=0)
        zonefile = Zonefile(
            tld,
            started_at.isoformat(), 
            downloaded_at.isoformat(), 
            decompressed_at.isoformat(), 
            link, 
            new_dest,
            path.getsize(new_dest),
            file_path, 
            path.getsize(file_path),
        )
        with zonefiles_db.open_session() as session:
            query_result = list(session.query(object_type=Zonefile).where(tld=zonefile.tld))
            query_result.sort(key=lambda x: x.started_at_unix, reverse=True)
            if not query_result or is_zonefile_updated(zonefile, query_result[0]):
                log.info('Writing %s to ravendb' % zonefile)
                session.store(zonefile)
                session.save_changes()
        log.info('Parsing %s' % zonefile)
        for document in parse_file(new_dest, regex):
            document['remote_file'] = link
            document['scanned_at'] = started_at.isoformat()
            document['tld'] = tld
            document['fqdn'] = str('.'.join([document['domain'], tld]))
            domain = Domain(**document)

            with scans_db.open_session() as session:
                query_result = list(session.query(object_type=Domain).where(fqdn=domain.fqdn, nameserver=domain.nameserver))
                query_result.sort(key=lambda x: x.scanned_at_unix, reverse=True)
                if not query_result or is_domain_updated(domain, query_result[0]):
                    session.store(domain)
                    session.save_changes()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='open net scans')
    parser.add_argument('-c', '--config_file', default='config.yaml', help='absolute path to config file')
    parser.add_argument('--verbose', '-v', action='count', default=0)
    args = parser.parse_args()

    log_level = args.verbose if args.verbose else 3
    setup_logging(log_level)
    get_config(config_file=args.config_file)

    main()

