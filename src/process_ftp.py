#!/usr/bin/env python
import time, argparse, logging, json
from os import path, isatty, getcwd, makedirs
from datetime import datetime

from helpers import *
from models import *
from czdap import *


def main():
    log = logging.getLogger()
    conf = get_config()
    zonefile_dir = conf.get('tmp_dir')
    if not path.exists(zonefile_dir):
        makedirs(zonefile_dir)

    for c in conf.get('ftp'):
        started_at = datetime.utcnow().replace(microsecond=0)
        server = c.get('server')
        user = c.get('user')
        passwd = c.get('passwd')
        regex = c.get('regex')
        if not c.get('files'):
            log.critical('files array needed in ftp conf')
            exit(1)
        for z in c.get('files'):
            ftp = ftp_session(server, user, passwd)
            md5hash_file = z.get('md5checksum')
            md5_file_path = path.join(zonefile_dir, md5hash_file)
            ftp_download(ftp, md5hash_file, md5_file_path)
            local_compressed_file = path.join(zonefile_dir, z.get('file_path'))
            local_file = local_compressed_file.replace('.gz', '.txt', 1)
            download_zonefile = True
            if path.isfile(local_compressed_file):
                if md5_checksum(md5_file_path, local_compressed_file):
                    log.info('file %s matches checksum. skipping' % z.get('file_path'))
                    download_zonefile = False

            if download_zonefile and ftp_download(ftp, z.get('file_path'), local_compressed_file):
                log.info('Download %s complete' % z.get('file_path'))
            downloaded_at = datetime.utcnow().replace(microsecond=0)
            ftp.quit()
            log.info('Decompressing %s' % local_compressed_file)
            decompress(local_compressed_file, local_file)
            decompressed_at = datetime.utcnow().replace(microsecond=0)
            remote_path = 'ftp://' + user + '@' + path.join(server, z.get('file_path'))
            zonefile = Zonefile(
                tld=z.get('tld'),
                source=c.get('server'),
                started_at=started_at.isoformat(),
                downloaded_at=downloaded_at.isoformat(),
                decompressed_at=decompressed_at.isoformat(),
                remote_path=remote_path, 
                local_compressed_file=local_compressed_file,
                local_compressed_file_size=path.getsize(local_compressed_file),
                local_file=local_file, 
                local_file_size=path.getsize(local_file),
            )
            zonefiles_db = get_db("zonefiles")
            with zonefiles_db.open_session() as session:
                query_result = list(session.query(object_type=Zonefile).where(tld=zonefile.tld))
                query_result.sort(key=lambda x: x.started_at_unix, reverse=True)
                if not query_result or is_zonefile_updated(zonefile, query_result[0]):
                    log.info('Writing %s to ravendb' % zonefile.tld)
                    session.store(zonefile)
                    session.save_changes()
            del zonefiles_db, zonefile, decompressed_at, downloaded_at, ftp
            log.info('Parsing %s' % local_file)
            parse_zonefile(local_file, regex, {
                'remote_file': remote_path,
                'scanned_at': started_at.isoformat(),
                'tld': z.get('tld'),
            }, 3)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='open net scans')
    parser.add_argument('-c', '--config_file', default='config.yaml', help='absolute path to config file')
    parser.add_argument('-l', '--reprocess_local_file', help='local zone file to reprocess')
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
    del parser, args, log_level, c, ravendb_conn
    main()
