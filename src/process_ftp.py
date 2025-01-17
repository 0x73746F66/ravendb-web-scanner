#!/usr/bin/env python
import time, argparse, logging, json, urllib3
from os import path, isatty, getcwd, makedirs
from datetime import datetime
from retry import retry

from helpers import *
from models import *
from czdap import *

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, urllib3.exceptions.ConnectionError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def get_zonefile_previous_line_count(ravendb_key):
    log = logging.getLogger()
    stored_zonefile = None
    previous_line_count = 0
    try:
        zonefiles_db = get_db('zonefiles')
        with zonefiles_db.open_session() as session:
            stored_zonefile = session.load(ravendb_key)
            if stored_zonefile and hasattr(stored_zonefile, 'line_count') and stored_zonefile.line_count:
                previous_line_count = stored_zonefile.line_count
    except Exception as e:
        log.info(f'Excception for get_zonefile_previous_line_count {e}')

    return previous_line_count, stored_zonefile

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
                    log.info(f"file {z.get('file_path')} matches checksum. skipping")
                    download_zonefile = False

            if download_zonefile:
                ftp_download(ftp, z.get('file_path'), local_compressed_file)
                log.info(f'Download {z.get("file_path")} complete')
            ftp.quit()
            downloaded_at = datetime.utcnow().replace(microsecond=0)
            if download_zonefile or conf.get('retry_decompress', False):
                log.info(f'Decompressing {local_compressed_file}')
                decompress(local_compressed_file, local_file)
                decompressed_at = datetime.utcnow().replace(microsecond=0)
                log.info(f'Decompressed to {local_file}')

                ravendb_key = f'Zonefile/{z.get("tld")}'
                previous_line_count, _ = get_zonefile_previous_line_count(ravendb_key)
                pattern = re.compile(bytes(regex.encode('utf8')), re.DOTALL | re.IGNORECASE | re.MULTILINE)
                line_count = file_line_count(local_file, pattern)

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
                    previous_line_count=previous_line_count,
                    line_count=line_count,
                )
                log.info(f'Saving {ravendb_key}')
                _save(ravendb_key, zonefile)
                process_files = split_zonefile(zonefile, split_lines=100000)
                if process_files == []:
                    log.info('Zonefile .%s unchanged' % zonefile.tld)
                elif not process_files:
                    log.error('missing zonefile %s' % zonefile.local_file)
                    continue
                for zonefile_part_path in process_files:
                    log.info(f'Queuing {zonefile_part_path}')
                    ravendb_key = f'ZonefilePart/{path.splitext(path.split(zonefile_part_path)[1])[0]}'
                    _save_zonefile_part(ravendb_key, ZonefilePartQueue(
                        tld = zonefile.tld,
                        source = zonefile.source,
                        file_path = zonefile_part_path,
                        added = decompressed_at.isoformat(),
                    ))

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, urllib3.exceptions.ConnectionError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def _save(ravendb_key, zonefile):
    log = logging.getLogger()
    zonefiles_db = get_db("zonefiles")
    _, stored_zonefile = get_zonefile_previous_line_count(ravendb_key)
    with zonefiles_db.open_session() as session:
        if not stored_zonefile:
            log.info(f'Saving new zonefile for {zonefile.tld}')
        elif is_zonefile_updated(zonefile, stored_zonefile):
            log.info(f'Replacing zonefile for {zonefile.tld}')
            session.delete(ravendb_key)
            session.save_changes()
    with zonefiles_db.open_session() as session:
        session.store(zonefile, ravendb_key)
        session.save_changes()

@retry((AllTopologyNodesDownException, urllib3.exceptions.ProtocolError, urllib3.exceptions.ConnectionError, TimeoutError), tries=15, delay=1.5, backoff=3, logger=logging.getLogger())
def _save_zonefile_part(ravendb_key, zonefile_part_queue):
    log = logging.getLogger()
    q_db = get_db("queue")
    with q_db.open_session() as session:
        if session.load(ravendb_key):
            return
    log.info(f'Saving new zonefile part queue for .{zonefile_part_queue.tld}')
    with q_db.open_session() as session:
        session.store(zonefile_part_queue, ravendb_key)
        session.save_changes()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='open net scans')
    parser.add_argument('-c', '--config_file', default='config.yaml', help='absolute path to config file')
    parser.add_argument('-l', '--log-file', default=None, help='absolute path to config file')
    parser.add_argument('--cron', default=False, type=bool, help='absolute path to config file')
    parser.add_argument('--verbose', '-v', action='count', default=0)
    args = parser.parse_args()

    log_level = args.verbose if args.verbose else 3
    setup_logging(log_level, file_path=args.log_file)
    log = logging.getLogger()
    c = get_config(config_file=args.config_file)
    if args.cron:
        filename = path.basename(__file__)
        if not c['cron_enable'].get(filename):
            log.warn(f'Configured to terminate {filename}')
            exit(0)

    ravendb_conn = '{}://{}:{}'.format(
        c['ravendb'].get('proto'),
        c['ravendb'].get('host'),
        c['ravendb'].get('port'),
    )
    get_db("queue", ravendb_conn)
    get_db("zonefiles", ravendb_conn)
    del parser, args, log_level, c, ravendb_conn
    main()
