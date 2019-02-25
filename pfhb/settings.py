# PacketFilterHostBlocker - settings.py
# --
# License: MIT
# Author: Ricardo Falasca <ricardo@falasca.com.br>
# 2019-02-20

from configparser import ConfigParser, NoOptionError, NoSectionError
import os


def load_settings(path):
    ''' Load settings file '''

    config = ConfigParser()

    def value(section, option, default=None):
        try:
            value = config.get(section, option)
        except (NoSectionError, NoOptionError):
            value = default
        return value

    # if path was not passed, we're using the default installation path
    if not path:
        path = '/etc/pfhb/settings.ini'

    if not os.path.isfile(path):
        raise Exception('Cannot read settings file at "{}"'.format(path))

    config.read(path)

    settings = {
        'PF_CONFIG_SOURCE': value('pf', 'ConfigSource', '/etc/pf.conf'),

        'PF_CONFIG_TARGET': value('pf',
                                  'ConfigTarget',
                                  '/etc/pfhb/pf-merged.conf'),

        'PF_LOG_RULES': value('pf', 'LogRules', True) in ['yes', 'true', True],
        'PF_IPS_TO_BLOCK': value('pf', 'IPsOrClassesToBlock', '').split(),
        'PF_IPS_TO_PASS': value('pf', 'IPsOrClassesToPass', '').split(),
        'PF_RELOAD_COMMAND': value('pf', 'ReloadCommand', 'pfctl -f'),
        'STORAGE_TYPE': value('storage', 'Type', 'file'),

        'DOMAINS_FILE_PATH': value('storage',
                                   'DomainsFilePath',
                                   '/etc/pfhb/domains.ini'),

        'REDIS': {
            'host': value('redis', 'Host', '127.0.0.1'),
            'port': int(value('redis', 'Port', '6379')),
            'password': value('redis', 'Password', ''),
            'db': int(value('redis', 'DB', '0'))
        },

        'USE_SYSLOG': (value('misc', 'UseSyslog', True)
                       in ['yes', 'true', True]),

        'INSANE_MODE': (value('misc', 'InsaneMode', False)
                        in ['yes', 'true', True]),

        'RESOLVE_WWW_PREFIX': (value('misc', 'Resolve3wPrefix', True)
                               in ['yes', 'true', True]),

        'BLOCK_DOMAIN_NETWORKS': (value('misc', 'BlockDomainNetworks', False)
                                  in ['yes', 'true', True]),
    }

    if not settings.get('PF_CONFIG_SOURCE'):
        raise Exception('Path for original pf.conf is missing.')

    if not settings.get('PF_CONFIG_TARGET'):
        raise Exception('Path for merged pf.conf is missing.')

    if not settings.get('PF_IPS_TO_BLOCK'):
        raise Exception('Nothing to block. Do you really need this tool?')

    if not settings.get('PF_RELOAD_COMMAND'):
        raise Exception('PF reload command is missing. I need to know it.')

    if all([settings.get('STORAGE_TYPE') == 'file',
            not settings.get('DOMAINS_FILE_PATH')]):
        raise Exception('File domains.ini\'s path is missing.')

    if settings.get('STORAGE_TYPE') == 'redis' and not settings.get('REDIS'):
        raise Exception('Redis Server configuration is missing.')

    return settings
