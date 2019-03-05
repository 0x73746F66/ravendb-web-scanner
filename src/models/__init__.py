import time
from datetime import datetime
from pyravendb.store import document_store

db = {}

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
    if new.whois_id != old.whois_id:
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
    if hasattr(new, 'expiration_date_unix') and hasattr(old, 'expiration_date_unix') and new.expiration_date_unix != old.expiration_date_unix:
        return True
    if hasattr(new, 'expiration_date_unix') and not hasattr(old, 'expiration_date_unix'):
        return True
    if hasattr(new, 'updated_date_unix') and hasattr(old, 'updated_date_unix') and new.updated_date_unix != old.updated_date_unix:
        return True
    if hasattr(new, 'updated_date_unix') and not hasattr(old, 'updated_date_unix'):
        return True
    return False

def is_dns_updated(new, old):
    if new.A != old.A:
            return True
    if new.CNAME != old.CNAME:
        return True
    if new.MX != old.MX:
        return True
    if new.TXT != old.TXT:
        return True
    if old.SOA and new.SOA:
        o_matched = []
        n_dict = {}
        o_dict = {}
        for nSOA in new.SOA:
            n_dict[nSOA.serial] = nSOA
            for oSOA in old.SOA:
                o_dict[oSOA.serial] = oSOA
                if nSOA.serial == oSOA.serial:
                    o_matched.append(oSOA.serial)

        for n in new.SOA:
            if n.serial not in o_matched:
                return True
            elif n_dict[n.serial].__dict__ != o_dict[n.serial].__dict__:
                return True
    elif old.SOA and not new.SOA:
        return True
    elif not old.SOA and new.SOA:
        return True

    return False

class Domain(object):
    def __init__(self, domain, tld, fqdn, ttl, nameserver, scanned_at, saved_at = None, remote_file = None, local_file = None):
        self.domain = domain.lower()
        self.tld = tld.lower()
        self.fqdn = fqdn.lower()
        self.ttl = ttl
        self.nameserver = nameserver.lower()
        self.scanned_at = scanned_at
        scanned_dt = datetime.strptime(scanned_at, '%Y-%m-%dT%H:%M:%S')
        self.scanned_at_unix = time.mktime(scanned_dt.timetuple())
        self.saved_at = saved_at
        saved_at_dt = datetime.strptime(saved_at, '%Y-%m-%dT%H:%M:%S')
        self.saved_at_unix = time.mktime(saved_at_dt.timetuple())
        self.local_file = local_file
        self.remote_file = remote_file
    def __repr__(self):
        return self.__dict__

class Zonefile(object):
    def __init__(self, tld, source, started_at, downloaded_at, decompressed_at, remote_path, local_file, local_file_size, local_compressed_file = None, local_compressed_file_size = None):
        self.tld = tld.lower()
        self.source = source
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

class DnsQuery(object):
    def __init__(self, domain, A, CNAME, MX, SOA, TXT, scanned_at):
        self.domain = domain.lower()
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

class SOA(object):
    def __init__(self, serial, tech, refresh, retry, expire, minimum, mname):
        self.serial = serial
        self.tech = tech
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.minimum = minimum
        self.mname = mname
    def __repr__(self):
        return self.__dict__

class Certificate(object):
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            if isinstance(value, datetime):
                setattr(self, key, value.isoformat())
            else:
                setattr(self, key, str(value))
    def __repr__(self):
        return self.__dict__

class HttpHeader(object):
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            if isinstance(value, datetime):
                setattr(self, key, value.isoformat())
            else:
                setattr(self, key, str(value))
    def __repr__(self):
        return self.__dict__

class Whois(object):
    def __init__(self, domain, scanned_at, raw=None, whois_id=None, status=None, registrar=None, emails=None, whois_server=None, contact_billing=None, contact_admin=None, contact_tech=None, contact_registrant=None, creation_date=None, expiration_date=None, updated_date=None, **kwargs):
        self.domain = domain.lower()
        self.status = status
        self.registrar = registrar
        if 'id' in kwargs:
            self.whois_id = kwargs['id']
        self.whois_id = whois_id
        self.whois_server = whois_server
        self.emails = emails
        self.contact_registrant = contact_registrant
        self.contact_tech = contact_tech
        self.contact_admin = contact_admin
        self.contact_billing = contact_billing
        self.creation_date = creation_date
        if creation_date:
            creation_date_dt = datetime.strptime(creation_date, '%Y-%m-%dT%H:%M:%S')
            self.creation_date_unix = time.mktime(creation_date_dt.timetuple())
        self.expiration_date = expiration_date
        if expiration_date:
            expiration_date_dt = datetime.strptime(expiration_date, '%Y-%m-%dT%H:%M:%S')
            self.expiration_date_unix = time.mktime(expiration_date_dt.timetuple())
        self.updated_date = updated_date
        if updated_date:
            updated_date_dt = datetime.strptime(updated_date, '%Y-%m-%dT%H:%M:%S')
            self.updated_date_unix = time.mktime(updated_date_dt.timetuple())
        self.scanned_at = scanned_at
        scanned_at_dt = datetime.strptime(scanned_at, '%Y-%m-%dT%H:%M:%S')
        self.scanned_at_unix = time.mktime(scanned_at_dt.timetuple())
        if raw:
            self.raw = raw
    def __repr__(self):
        return self.__dict__

class WhoisContact(object):
    def __init__(self, **kwargs):
        def clean(key):
            if not key in kwargs:
                return None
            return kwargs[key]
        self.handle = clean('handle')
        self.name = clean('name')
        self.organization = clean('organization')
        self.city = clean('city')
        self.state = clean('state')
        self.postalcode = clean('postalcode')
        self.country = clean('country')
        self.phone = clean('phone')
        self.fax = clean('fax')
        self.email = clean('email')
        self.street = clean('street')
    def __repr__(self):
        return self.__dict__

def load_dns_query(key, value):
    if not value:
        return None
    if key == "SOA":
        soa = []
        for v in value:
            soa.append(SOA(**v))
        return soa

def load_whois(key, value):
    if not value:
        return None
    if key.startswith('contact_'):
        return WhoisContact(**value)

def get_db(database, ravendb_conn=None):
    global db

    if not db and not ravendb_conn:
        print('ravendb_conn missing')
        exit(0)
    if not database in db and not ravendb_conn:
        print('ravendb_conn missing')
        exit(0)

    if not database in db:
        db[database] = document_store.DocumentStore(urls=[ravendb_conn], database=database)
        if database == 'osint':
            db[database].conventions.mappers.update({DnsQuery: load_dns_query})
            db[database].conventions.mappers.update({Whois: load_whois})
        db[database].initialize()

    return db[database]
