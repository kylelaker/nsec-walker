import socket

import dns.exception
import dns.resolver
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.query
import dns.message

from nsecwalker import error

def do_lookup(name, max_tries=5):
    # resolver = dns.resolver.Resolver()
    dns.resolver.get_default_resolver().nameservers = ['8.8.8.8', '8.8.4.4']
    # resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    for i in range (1, max(1, max_tries + 1)):
        try:
            return dns.resolver.resolve(name, rdtype=dns.rdatatype.NSEC)
        except (
            dns.exception.Timeout,
            dns.resolver.NXDOMAIN,
            dns.resolver.YXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
        ) as e:
            if i == max_tries:
                raise e

def query(name: str) -> dns.resolver.Answer:
    try:
        result = do_lookup(name)
        names = [rdata.next for rdata in result]
        if len(names) == 0:
            return None
        if len(names) != 1:
            raise error.DuplicateNsecError(name)
        return names[0]
    except (
        dns.exception.Timeout,
        dns.resolver.NXDOMAIN,
        dns.resolver.YXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
    ) as e:
        raise error.GenericResolutionFailureError(name) from e
