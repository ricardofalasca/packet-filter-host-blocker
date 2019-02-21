# PacketFilterHostBuster
# --
# License: MIT
# Author: Ricardo Falasca <ricardo@falasca.com.br>
# 2019-02-20

import socket
import redis

from pprint import pprint

from ipwhois.net import Net
from ipwhois.asn import IPASN, ASNOrigin

try:
    import local_settings as settings
except:  # noqa
    import settings


class PacketFilterHostBuster(object):

    def __init__(self):
        self.redis = redis.Redis(**settings.REDIS)

    def __get_asn_cidr(self, ip):
        asn = IPASN(Net(ip)).lookup()
        return asn.get('asn_cidr')

    def __get_asn_origin(self, ip):
        asn = IPASN(Net(ip)).lookup()
        return asn.get('asn')

    def __get_asn_nets(self, ip):
        asn_origin = self.__get_asn_origin(ip)
        origin = ASNOrigin(Net(ip))
        lookup = origin.lookup(asn='AS{}'.format(asn_origin),
                               asn_methods=['whois'])
        return lookup.get('nets')

    def get_nets(self, ip):
        try:
            nets = self.__get_asn_nets(ip)
        except:  # noqa
            return []

        return [net.get('cidr') for net in nets]

    def nslookup(self, domain):
        ''' Domain name lookup '''
        if domain:
            socket.setdefaulttimeout(2)

            try:
                hosts = socket.gethostbyname_ex(domain)
            except:  # noqa
                return

            resolved = hosts[2] if len(hosts) == 3 else None
            return resolved

    def resolve_domains(self):
        ''' Get all domain groups stored on Redis to resolve each domain
        name and store it again and generate all PF rules.
        '''
        groups = {}

        domain_groups = self.redis.keys('domains_*')
        for group in domain_groups:
            # get all group domains (ie.: facebook.com, facebook.ca)

            service = (group.decode('utf-8').split('_')[-1]
                       if isinstance(group, bytes)
                       else group.split('_')[-1])

            domains = self.redis.get(group)
            if isinstance(domains, bytes):
                domains = domains.decode('utf-8')

            domains = [d.strip() for d in domains.split(',')]

            # nslookup the domain
            ips = []
            for domain in domains:
                print(' -> nslookup of {}'.format(domain))
                resolved = self.nslookup(domain)
                if not resolved:
                    print('   : {} -> skipped'.format(domain))
                else:
                    for ip in self.nslookup(domain):
                        if ip and ip not in ips:
                            ips.append(ip)

            # now, after get all ips, let's search by their ANS's and add
            # to the group.
            groups[service] = []
            for ip in ips:
                groups[service].append(ip)

                nets = self.get_nets(ip)
                # yeahp, I consider to block more than 10 IP classes a bit
                # INSANE! !@#!@# !@#!@#!$%#$#%ˆ%#ˆ
                can_block_nets = (len(nets) <= 10 or
                                  len(nets) > 10 and settings.INSANE_MODE)

                if nets and can_block_nets:
                    groups[service].extend(nets)

            # current = self.redis.get('ips_{}'.format(group))
            self.redis.set('ips_{}'.format(service), ','.join(ips))

        return groups

    def generate_pf_rules(self):
        ip_groups = self.resolve_domains()

        table_to_allow = 'table <ips_to_pass> { %s }' % (
            ', '.join(settings.PF_IPS_TO_ALLOW))

        table_to_block = 'table <ips_to_block> { %s }' % (
            ', '.join(settings.PF_IPS_TO_BLOCK))

        block_rule = ('block in {} quick on {} proto tcp from '
                      '<ips_to_block> to <group_{}>')

        groups_tables = []
        rules = []
        for group in ip_groups:
            groups_tables.append(
                'table <group_%s> { %s }' % (
                    group, ', '.join(ip_groups[group])))

            rules.append(block_rule.format(
                'log' if settings.PF_LOG_RULES else '',
                settings.PF_INBOUND_INTERFACE,
                group))

        pprint(table_to_allow)
        pprint(table_to_block)
        pprint(groups_tables)
        pprint(rules)


pfhb = PacketFilterHostBuster()
pfhb.generate_pf_rules()
