import time
from datetime import datetime

def is_domain_updated(new, old):
    if new.ttl != old.ttl:
        return True
    if new.local_file != old.local_file:
        return True
    if new.remote_file != old.remote_file:
        return True
    return False

def is_zonefile_updated(new, old):
    if new.local_file_size != old.local_file_size:
        return True
    if new.local_file != old.local_file:
        return True
    if new.local_compressed_file_size != old.local_compressed_file_size:
        return True
    if new.local_compressed_file != old.local_compressed_file:
        return True
    if new.remote_path != old.remote_path:
        return True
    return False

class Domain(object):
    def __init__(self, domain, tld, fqdn, ttl, nameserver, scanned_at, remote_file = None, local_file = None):
        self.domain = domain
        self.tld = tld
        self.fqdn = fqdn
        self.ttl = ttl
        self.nameserver = nameserver
        self.scanned_at = scanned_at
        scanned_dt = datetime.strptime(scanned_at, '%Y-%m-%dT%H:%M:%S')
        self.scanned_at_unix = time.mktime(scanned_dt.timetuple())
        self.local_file = local_file
        self.remote_file = remote_file
    def __repr__(self):
        return 'Domain(object) >- ' + self.fqdn

class Zonefile(object):
    def __init__(self, tld, started_at, downloaded_at, decompressed_at, remote_path, local_file, local_file_size, local_compressed_file = None, local_compressed_file_size = None):
        self.tld = tld
        self.started_at = started_at
        started_dt = datetime.strptime(started_at, '%Y-%m-%dT%H:%M:%S')
        self.downloaded_at = downloaded_at
        downloaded_dt = datetime.strptime(downloaded_at, '%Y-%m-%dT%H:%M:%S')
        self.decompressed_at = decompressed_at
        decompressed_dt = datetime.strptime(decompressed_at, '%Y-%m-%dT%H:%M:%S')
        self.started_at_unix = time.mktime(started_dt.timetuple())
        self.downloaded_at_unix = time.mktime(downloaded_dt.timetuple())
        self.decompressed_at_unix = time.mktime(decompressed_dt.timetuple())
        self.remote_path = remote_path
        self.local_compressed_file = local_compressed_file
        self.local_compressed_file_size = local_compressed_file_size
        self.local_file = local_file
        self.local_file_size = local_file_size
    def __repr__(self):
        return 'Zonefile(object) >- ' + self.tld
