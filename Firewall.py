
class Policy:
    def __init__(self, d, proto, pr, ipr):
        self.direction = d
        self.protocol = proto
        self.portrange = pr
        self.iprange = ipr



class Firewall:

    def __init__(self,filepath):
        self.path = filepath
        self.policies = []
        with open(filepath, "r+") as fd:
            for policy in fd:
                polparms = policy.split(',')
                polparmsip = polparms[3].split("\n")
                self.policies.append(Policy(polparms[0], polparms[1], polparms[2], polparmsip[0]))



    def accept_packet(self, direction, protocol, port, ip_address):
        for p in self.policies:
            if direction == p.direction and protocol == p.protocol:
                if '-' in p.portrange:
                    prange = p.portrange.split('-')
                    if not ((port >= int(prange[0]) and port <= int(prange[1])) or
                                (port <= int(prange[0]) and port >= int(prange[1]))):
                        continue

                elif not (port == int(p.portrange)):
                        continue

                if '-' in p.iprange:
                    iprange = p.iprange.split('-')
                    ip1 = iprange[0].split('.')
                    ip2 = iprange[1].split('.')
                    ip1join = ''.join(ip1)
                    ip2join = ''.join(ip2)
                    ip = ''.join(ip_address.split('.'))
                    if (ip >= ip1join and ip <= ip2join) or \
                            (ip <= ip1join and ip >= ip2join):
                        return True

                elif ip_address == p.iprange:
                    return True
        return False

if __name__=="__main__":
    fw = Firewall('FirewallProtocol.csv')
    ip1 = fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")
    ip2 = fw.accept_packet("outbound", "udp", 10050, "192.168.10.11")
    ip3 = fw.accept_packet("abn", "cd3", 3, "123+0d2-")
    ip4 = fw.accept_packet("inbound", "udp", 53, "192.168.1.2")
    ip5 = fw.accept_packet("", "", -1, "192.168.1.2")
    print(ip1, ip2, ip3, ip4, ip5)