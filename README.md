# packet-filter-host-blocker


A small Python package (class and cli) that digs into domains to find its related IPs and (if enabled) IP classes from the same ASN Origin due to generate PF (Packet Filter) tables and rules to block access into those services.


## Requirements

* user privileges to install `pfhb`, read `pf.conf`, write in `/etc/pfhb` and to run `pfctl`
* packet filter enabled (OpenBSD, FreeBSD, NetBSD or macOS)
