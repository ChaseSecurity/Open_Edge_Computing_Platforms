from dpkt.compat import compat_ord
import socket
import dpkt
import struct
from asn1crypto import x509
from collections import defaultdict
import logging


def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def parse_ip(ip):
    payload = ip.data
    ip_port = {
        "src_ip": inet_to_str(ip.src),
        "src_port": payload.sport,
        "dst_ip": inet_to_str(ip.dst),
        "dst_port": payload.dport
    }
    return ip_port, payload


def is_stun_packet(payload):
    # Check if STUN message type is valid
    try:
        stun_pkt = dpkt.stun.STUN(payload)
        msg_type = stun_pkt.type
        if msg_type < 0x0001 or msg_type > 0x0111:
            return False
        else:

            return True
    except (dpkt.NeedData, dpkt.UnpackError):
        return False


def parse_tcp(tcp):
    flags = {
        "urg_flag": (tcp.flags & dpkt.tcp.TH_URG) != 0,
        "ack_flag": (tcp.flags & dpkt.tcp.TH_ACK) != 0,
        "psh_flag": (tcp.flags & dpkt.tcp.TH_PUSH) != 0,
        "rst_flag": (tcp.flags & dpkt.tcp.TH_RST) != 0,
        "syn_flag": (tcp.flags & dpkt.tcp.TH_SYN) != 0,
        "fin_flag": (tcp.flags & dpkt.tcp.TH_FIN) != 0,
    }

    seqAck = {
        "seq_num": tcp.seq,
        "ack_num": tcp.ack,
    }
    payload = tcp.data
    return flags, seqAck, payload


def parse_dns_response(dns):
    # focus on type A CNAME and AAAA
    DNS_A = 1
    DNS_CNAME = 5
    DNS_AAAA = 28
    dns_name_set = set()
    dns_ip_set = set()
    if len(dns.an) > 0:  # DNS resource record
        for rr in dns.an:
            dns_name_set.add(rr.name)
            if rr.type == DNS_A:
                dns_ip_set.add(inet_to_str(rr.rdata))
            elif rr.type == DNS_AAAA:
                dns_ip_set.add(inet_to_str(rr.ip6))
            elif rr.type == DNS_CNAME:
                dns_name_set.add(rr.cname)
            else:
                continue
        if len(dns_name_set) > 0:
            domain_ip = {
                "dns_domain": list(dns_name_set),
                "dns_ip": list(dns_ip_set)
            }
            return domain_ip
        else:
            return None
    else:
        return None


def get_ip_port_key(ip_port):
    ip_port_key = "{0}-{1}-{2}-{3}".format(ip_port["src_ip"],
                                           ip_port["src_port"],
                                           ip_port["dst_ip"],
                                           ip_port["dst_port"])

    return ip_port_key


def get_reverse_ip_port_key(ip_port):
    reverse_ip_port_key = "{0}-{1}-{2}-{3}".format(ip_port["dst_ip"],
                                                   ip_port["dst_port"],
                                                   ip_port["src_ip"],
                                                   ip_port["src_port"])
    return reverse_ip_port_key


def unpacker(type_string, packet):
    """
    Returns network-order parsed data and the packet minus the parsed data.
    """
    if type_string.endswith('H'):
        length = 2
    if type_string.endswith('B'):
        length = 1
    if type_string.endswith('P'):  # 2 bytes for the length of the string
        length, packet = unpacker('H', packet)
        type_string = '{0}s'.format(length)
    if type_string.endswith('p'):  # 1 byte for the length of the string
        length, packet = unpacker('B', packet)
        type_string = '{0}s'.format(length)
    data = struct.unpack('!' + type_string, packet[:length])[0]
    if type_string.endswith('s'):
        # data = ''.join(data)
        data = data
    return data, packet[length:]


def check_tls_version(data):
    version2 = False
    version3 = False

    if len(data) > 2:
        # ssl
        tmp = struct.unpack("bbb", data[0:3])
    else:
        return version2, version3

    # SSL v2. OR Message body too short.
    if (tmp[0] & 0x80 == 0x80) and (((tmp[0] & 0x7f) << 8 | tmp[1]) > 9):
        version2 = True
    elif (tmp[1] != 3) or (tmp[2] > 3):  # SSL 3.0 or TLS 1.0, 1.1 and 1.2
        version3 = False
    elif (tmp[0] < 20) or (tmp[0] > 23):  # Type Error
        pass
    else:
        version3 = True

    return version2, version3


def client_hello_ssl_v2(data):
    tmp = struct.unpack("bbb", data[0:3])
    if tmp[2] == 0x01:
        # Client_hello.
        lens = (tmp[0] & 0x7f) << 8 | tmp[1]
        cipher_specs_size = (data[5] << 8) | data[6]
        if cipher_specs_size % 3 != 0: 
            return 0

        session_id_len = (data[7] << 8) | data[8]
        random_size = (data[9] << 8) | data[10]
        if lens < (9 + cipher_specs_size + session_id_len + random_size):
            return 0
        return lens + 2
    if tmp[2] == 0x04:
        # Server hello, Not processing
        lens = (tmp[0] & 0x7f) << 8 | tmp[1]
        return lens + 2

    return 0


def parse_client_records(records, https_flag):
    for record in records:
        if record.type == 22 and ord(record.data[:1]) == 1:
            try:
                hs = dpkt.ssl.TLSHandshake(record.data)
                https_flag = 1
                if isinstance(hs.data, dpkt.ssl.TLSClientHello):
                    for tuple in hs.data.extensions:
                        if tuple[0] == 0:
                            server_name = str(tuple[1][5:], 'utf-8')
                            return [server_name, https_flag]
            except Exception:
                continue
    return ["1", https_flag]


def parse_certificate_records(records, https_flag):
    cert_fingerprint_domains_certs = defaultdict(list)
    for record in records:
        if record.type == 22 and ord(record.data[:1]) == 11:
            try:
                hs = dpkt.ssl.TLSHandshake(record.data)
                https_flag = 1
                if isinstance(hs.data, dpkt.ssl.TLSCertificate):
                    for i in range(len(hs.data.certificates)):
                        cert = x509.Certificate.load(hs.data.certificates[i])
                        sha = cert.sha256_fingerprint.replace(" ", "")
                        domain = cert.valid_domains
                        cert_fingerprint_domains_certs[sha].append(
                            tuple(domain))
                        cert_fingerprint_domains_certs[sha].append(
                            hs.data.certificates[i])
            except Exception:
                return [cert_fingerprint_domains_certs, https_flag]
    return [cert_fingerprint_domains_certs, https_flag]


def is_bittorrent_handshake(data):
    return len(
        data) > 1 and data[0] == 19 and data[1:20] == b'BitTorrent protocol'


def parse_bittorrent_handshake(data):
    protocol_string = data[1:20]
    reserved = data[20:28]
    info_hash = data[28:48]
    peer_id = data[48:]
    return {
        "protocol_string": protocol_string,
        "reserved": reserved,
        "info_hash": info_hash,
        "peer_id": peer_id.split(b'\x00', 1)[0].decode('utf-8', 'ignore'),
    }


def is_bittorrent_protocol(data):
    return data[21:40] == b'BitTorrent protocol'


def parse_bittorrent(data):
    protocol_string = data[21:40]
    reserved = data[40:48]
    info_hash = data[48:68]
    peer_id = data[68:]
    return {
        "protocol_string": protocol_string,
        "reserved": reserved,
        "info_hash": info_hash,
        "peer_id": peer_id.split(b'\x00', 1)[0].decode('utf-8', 'ignore'),
    }
