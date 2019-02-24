# #!/usr/bin/env python
# # -*- coding:utf-8
# import argparse, logging

# from datetime import datetime

# from helpers import *
# from models import *
# from czdap import *
# from osint import *

# def process(fqdn):
#     c = get_config()
#     log = logging.getLogger()

#     base_dir = c['osint'].get('base_dir').format(home=path.expanduser('~'))

#     now = datetime.utcnow().replace(microsecond=0)
#     updated_date = now.strftime('%Y-%m-%d')
#     if save_whois(fqdn, whois_dir=path.join(base_dir, c['osint'].get('whois_dir').format(domain=fqdn))):
#         log.info('saved whois for %s' % fqdn)

#     nameservers = None
#     data_path = path.join(base_dir, fqdn, 'zonefile.json')
#     if path.isfile(data_path):
#         with open(data_path, 'r') as r:
#             file_data = json.loads(r.read())
#             if 'nameservers' in file_data:
#               nameservers = file_data['nameservers']
#     if nameservers:
#       host_ip = get_a(fqdn, nameservers=nameservers)
#       cname = get_cnames(fqdn, nameservers=nameservers),
#       mx = get_mx(fqdn, nameservers=nameservers),
#       soa = get_soa(fqdn, nameservers=nameservers),
#       txt = get_txt(fqdn, nameservers=nameservers)
#     else:
#       host_ip = get_a(fqdn)
#       cname = get_cnames(fqdn),
#       mx = get_mx(fqdn),
#       soa = get_soa(fqdn),
#       txt = get_txt(fqdn)

#     dns_data = {
#         'updated_date': updated_date,
#         'a': host_ip,
#         'cname': cname,
#         'mx': mx,
#         'soa': soa,
#         'txt': txt
#     }
#     dns_dir = path.join(base_dir, c['osint'].get('dns_dir').format(domain=fqdn))
#     if not path.exists(dns_dir):
#         makedirs(dns_dir)
#     file_name = path.join(dns_dir, updated_date + '.json')
#     with open(file_name, 'w+') as f:
#         log.info('saved dns data for %s' % fqdn)
#         f.write(json.dumps(dns_data, default=lambda o: o.isoformat() if isinstance(o, (datetime)) else str(o) ))

#     if host_ip and save_shodan(host_ip, shodan_dir=path.join(base_dir, c['osint'].get('shodan_dir').format(domain=fqdn))):
#         log.info('saved shodan for %s' % fqdn)

#     if save_spider(fqdn, spider_dir=path.join(base_dir, c['osint'].get('spider_dir').format(domain=fqdn))):
#         log.info('saved spider for %s' % fqdn)

#     https_dir = path.join(base_dir, c['osint'].get('https_dir').format(domain=fqdn))
#     cert = save_https(fqdn, host_ip, https_dir=https_dir)
#     if not cert:
#         return
#     log.info('saved https cert detail for %s' % fqdn)
#     # pylint: disable=no-member
#     if not cert.has_key('subjectAltName'):
#         return
#     # pylint: enable=no-member
#     log.debug('found subjectAltName %s' % cert['subjectAltName'])
#     domains = set()
#     for d in cert['subjectAltName'].split(','):
#         domain = ''.join(d.split('DNS:')).strip()
#         if not d.startswith('*'):
#             domains.add(domain)
#     for domain in domains:
#         sub_domain = fqdn, domain.replace(fqdn, '').rstrip('.')
#         sub_domain_path = path.join(fqdn, sub_domain)
#         sub_host_ip = get_a(domain)
#         if save_spider(domain, spider_dir=path.join(base_dir, c['osint'].get('spider_dir').format(domain=sub_domain_path))):
#             log.info('saved spider for %s' % domain)
        
#         if save_shodan(sub_host_ip, shodan_dir=path.join(base_dir, c['osint'].get('shodan_dir').format(domain=sub_domain_path))):
#             log.info('saved shodan for %s' % domain)
#         https_subdir = path.join(base_dir, c['osint'].get('https_dir').format(domain=sub_domain_path))
#         if save_https(domain, sub_host_ip, https_dir=https_subdir):
#             log.info('saved https cert detail for %s' % domain)


# if __name__ == '__main__':
#     parser = argparse.ArgumentParser(description='open net scans')
#     parser.add_argument('-c', '--config-file', default='config.yaml', help='absolute path to config file')
#     parser.add_argument('--verbose', '-v', action='count', default=0)
#     args = parser.parse_args()

#     log_level = args.verbose if args.verbose else 3
#     setup_logging(log_level)
#     log = logging.getLogger()
#     c = get_config(config_file=args.config_file)
#     base_dir = c['osint'].get('base_dir').format(home=path.expanduser('~'))

#     for _, domains, other_files in scandir.walk(base_dir):
#         for domain in domains:
#             log.info('Queue %s to process' % domain)
#             process(domain)
#         break
