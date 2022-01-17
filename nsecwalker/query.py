import dns.exception
import dns.resolver
import dns.name
import dns.rdatatype
import dns.rrset

from nsecwalker import error


def query(name: str) -> dns.resolver.Answer:
    try:
        result = dns.resolver.resolve(name, dns.rdatatype.NSEC)
        names = [rdata.next for rdata in result]
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
