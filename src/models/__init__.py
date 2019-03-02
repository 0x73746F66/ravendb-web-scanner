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

def is_whois_updated(new, old):
    if new.status != old.status:
        return True
    if new.id != old.id:
        return True
    if new.registrar != old.registrar:
        return True
    if new.whois_server != old.whois_server:
        return True
    if new.emails != old.emails:
        return True
    if new.contact_registrant != old.contact_registrant:
        return True
    if new.contact_tech != old.contact_tech:
        return True
    if new.contact_admin != old.contact_admin:
        return True
    if new.contact_billing != old.contact_billing:
        return True
    if new.expiration_date_unix != old.expiration_date_unix:
        return True
    if new.updated_date_unix != old.updated_date_unix:
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
        return self.__dict__

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
        return self.__dict__

class Whois(object):
    def __init__(self, id, domain, status, registrar, emails, whois_server, contact_billing, contact_admin, contact_tech, contact_registrant, creation_date, expiration_date, updated_date, scanned_at):
        self.id = id
        self.domain = domain
        self.status = status
        self.registrar = registrar
        self.whois_server = whois_server
        self.emails = emails
        self.contact_registrant = contact_registrant
        self.contact_tech = contact_tech
        self.contact_admin = contact_admin
        self.contact_billing = contact_billing
        self.creation_date = creation_date
        creation_date_dt = datetime.strptime(creation_date, '%Y-%m-%dT%H:%M:%S')
        self.creation_date_unix = time.mktime(creation_date_dt.timetuple())
        self.expiration_date = expiration_date
        expiration_date_dt = datetime.strptime(expiration_date, '%Y-%m-%dT%H:%M:%S')
        self.expiration_date_unix = time.mktime(expiration_date_dt.timetuple())
        self.updated_date = updated_date
        updated_date_dt = datetime.strptime(updated_date, '%Y-%m-%dT%H:%M:%S')
        self.updated_date_unix = time.mktime(updated_date_dt.timetuple())
        self.scanned_at = scanned_at
        scanned_at_dt = datetime.strptime(scanned_at, '%Y-%m-%dT%H:%M:%S')
        self.scanned_at_unix = time.mktime(scanned_at_dt.timetuple())
    def __repr__(self):
        return self.__dict__

class DNS(object):
    def __init__(self, domain, A, CNAME, MX, SOA, TXT, scanned_at):
        self.domain = domain
        self.A = A
        self.CNAME = CNAME
        self.MX = MX
        self.SOA = SOA
        self.TXT = TXT
        self.scanned_at = scanned_at
        scanned_at_dt = datetime.strptime(scanned_at, '%Y-%m-%dT%H:%M:%S')
        self.scanned_at_unix = time.mktime(scanned_at_dt.timetuple())
    def __repr__(self):
        return self.__dict__
