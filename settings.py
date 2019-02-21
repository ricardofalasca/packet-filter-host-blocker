# Default PF (Packet Filter) configuration file
PF_CONFIG_PATH = 'pf.conf'

# Add replacement TAG [__PFHB_RULES__] where you want new rules
PF_CONFIG_SAMPLE = 'pf.conf.sample'

# Add 'log' argument into generated rules ?
PF_LOG_RULES = True

# Here you can use a variable (since it's declared in pf.conf sample)
PF_INBOUND_INTERFACE = '$int_if'

# IP's that will be blocked by rules - a table will be created for each IP
PF_IPS_TO_BLOCK = ['192.168.0.0/24]

# IP's that don't be blocked (exceptions)
PF_IPS_TO_ALLOW = [
    '192.168.0.10',  # Ricardo
]

# Command to reload Packet Filter (do not indicate pf.conf)
PF_RELOAD_COMMAND = 'pfctl -f'

REDIS = {
    'host': '127.0.0.1',
    'port': 6379,
    'password': '',
    'db': 0,
}

# Insane mode means that the system will look for all IP class related to
# same origin (by ASN Origin). It isn't recommended because can block lot of
# other services that can be hosted by the same provider. If you don't care
# about it (probably you're using other network or you're one of the IPs
# listed in PF_IPS_TO_ALLOW - you're a bad dog), just set to True.
#
# For test purposes, you can run the commands below to realize how bad this
# action could be:
# ps. 1: I'm using newegg.ca IP - 23.53.117.73 for this test.
# ps. 2: At the moment that I'm coding this, they're hosted at Akamai.
# --
# $ whois -h whois.radb.net 23.194.132.0
# Origin returned: AS20940
# $ whois -h whois.radb.net '!gAS20940'
INSANE_MODE = False
