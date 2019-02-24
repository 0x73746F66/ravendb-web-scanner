#!/usr/bin/env python
import time, argparse, logging, json
from os import path, isatty, getcwd, makedirs
from datetime import datetime
from pyravendb.store import document_store

from helpers import *
from models import *
from czdap import *


def main():
    log = logging.getLogger()
    conf = get_config()
    zonefile_dir = conf.get('tmp_dir')
    if not path.isdir(zonefile_dir):
        makedirs(zonefile_dir)

    ravendb_conn = '{}://{}:{}'.format(
        conf['ravendb'].get('proto'),
        conf['ravendb'].get('host'),
        conf['ravendb'].get('port'),
    )
    scans_db = document_store.DocumentStore(urls=[ravendb_conn], database="scans")
    scans_db.initialize()
    zonefiles_db = document_store.DocumentStore(urls=[ravendb_conn], database="zonefiles")
    zonefiles_db.initialize()

    for c in conf.get('ftp'):
        started_at = datetime.utcnow().replace(microsecond=0)
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
                md5_file_path = path.join(zonefile_dir, md5hash_file)
                ftp_download(ftp, md5hash_file, md5_file_path)
                target_file = z.get('file_path')
                target_file_path = path.join(zonefile_dir, target_file)
                zonefile_path = path.join(zonefile_dir, target_file.replace('.gz', '.txt', 1))
                download_zonefile = True
                if path.isfile(target_file_path):
                    target_size = ftp_filesize(ftp, target_file)
                    human_size = Byte(target_size).best_prefix()
                    log.warn('%s is %s' % (target_file, human_size))
                    if md5_checksum(md5_file_path, target_file_path):
                        log.info('file %s matches checksum. skipping' % target_file)
                        download_zonefile = False

                if download_zonefile and ftp_download(ftp, target_file, target_file_path):
                    log.info('Download %s complete' % target_file)
        finally:
            ftp.quit()

        downloaded_at = datetime.utcnow().replace(microsecond=0)
        log.info('Decompressing %s' % target_file)
        decompress(target_file_path, zonefile_path)
        decompressed_at = datetime.utcnow().replace(microsecond=0)
        remote = 'ftp://' + user + '@' + path.join(server, target_file)
        zonefile = Zonefile(
            z.get('tld'),
            started_at.isoformat(),
            downloaded_at.isoformat(),
            decompressed_at.isoformat(),
            remote, 
            zonefile_path,
            path.getsize(zonefile_path),
            target_file_path, 
            path.getsize(target_file_path),
        )
        with zonefiles_db.open_session() as session:
            query_result = list(session.query(object_type=Zonefile).where(tld=zonefile.tld))
            query_result.sort(key=lambda x: x.started_at_unix, reverse=True)
            if not query_result or is_zonefile_updated(zonefile, query_result[0]):
                log.info('Writing %s to ravendb' % zonefile)
                session.store(zonefile)
                session.save_changes()
        log.info('Parsing %s' % zonefile_path)
        for document in parse_file(zonefile_path, regex):
            document['remote_file'] = remote
            document['scanned_at'] = started_at.isoformat()
            document['tld'] = z.get('tld')
            document['fqdn'] = str('.'.join([document['domain'], document['tld']]))
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
    parser.add_argument('-l', '--reprocess_local_file', help='local zone file to reprocess')
    parser.add_argument('--verbose', '-v', action='count', default=0)
    args = parser.parse_args()

    log_level = args.verbose if args.verbose else 3
    setup_logging(log_level)
    get_config(config_file=args.config_file)

    main()
