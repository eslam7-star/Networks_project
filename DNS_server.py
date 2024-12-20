import socket

# DNS server configuration
DNS_PORT = 44444
DNS_IP = '127.0.0.1'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((DNS_IP, DNS_PORT))

# Simplified DNS record database
dns_records = {
    "example.com": {"A": "93.184.216.34", "CNAME": "alias.example.com", "MX": "mail.example.com", "NS": "ns.example.com"},
    "alias.example.com": {"A": "93.184.216.34"},
    "mail.example.com": {"A": "93.184.216.35"},
    "ns.example.com": {"A": "93.184.216.36"}
}

def getflags():
    QR = '1'
    OPCODE = '0000'  # Standard query
    AA = '1'  # Authoritative answer
    TC = '0'  # Truncation not set
    RD = '0'  # Recursion not desired
    RA = '0'  # Recursion not available
    Z = '000'  # Reserved
    RCODE = '0000'  # No error
    return int(QR + OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE, 2).to_bytes(1, byteorder='big')

def parse_question(data):
    domain_parts = []
    offset = 0
    while data[offset] != 0:
        length = data[offset]
        offset += 1
        domain_parts.append(data[offset:offset + length].decode())
        offset += length
    domain_name = '.'.join(domain_parts)
    qtype = data[offset + 1:offset + 3]
    return domain_name, qtype

def build_question(domain_name, qtype):
    qbytes = b''
    for part in domain_name.split('.'):
        length = len(part)
        qbytes += bytes([length]) + part.encode()
    qbytes += b'\x00'  # Null byte for the end of the domain name
    qbytes += qtype + b'\x00\x01'  # QCLASS (IN)
    return qbytes

def build_record(domain_name, qtype, ttl, value):
    rbytes = b'\xc0\x0c'  # Pointer to domain name in question
    if qtype == b'\x00\x01':  # A record
        rbytes += b'\x00\x01'  # QTYPE (A)
        rbytes += b'\x00\x01'  # QCLASS (IN)
        rbytes += int(ttl).to_bytes(4, byteorder='big')  # TTL
        rbytes += bytes([0, 4])  # Data length
        rbytes += b''.join([bytes([int(part)]) for part in value.split('.')])
    else:  # CNAME, MX, NS, etc.
        if qtype == b'\x00\x05':  # CNAME
            rbytes += b'\x00\x05'
        elif qtype == b'\x00\x0f':  # MX
            rbytes += b'\x00\x0f'
        elif qtype == b'\x00\x02':  # NS
            rbytes += b'\x00\x02'
        rbytes += b'\x00\x01'
        rbytes += int(ttl).to_bytes(4, byteorder='big')
        rbytes += len(value).to_bytes(2, byteorder='big')
        rbytes += value.encode()
    return rbytes

def find_records(domain_name, qtype):
    qtype_mapping = {
        b'\x00\x01': 'A',
        b'\x00\x05': 'CNAME',
        b'\x00\x0f': 'MX',
        b'\x00\x02': 'NS',
    }
    qtype_str = qtype_mapping.get(qtype, None)
    if qtype_str and domain_name in dns_records and qtype_str in dns_records[domain_name]:
        return [{"ttl": 300, "value": dns_records[domain_name][qtype_str]}]
    return []

def build_response(data):
    TransactionID = data[:2]
    Flags = getflags()
    QDCOUNT = b'\x00\x01'
    domain_name, qtype = parse_question(data[12:])
    records = find_records(domain_name, qtype)
    ANCOUNT = len(records).to_bytes(2, byteorder='big')
    NSCOUNT = (0).to_bytes(2, byteorder='big')
    ARCOUNT = (0).to_bytes(2, byteorder='big')
    
    dns_header = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
    dns_question = build_question(domain_name, qtype)
    dns_body = b''.join([build_record(domain_name, qtype, rec['ttl'], rec['value']) for rec in records])

    return dns_header + dns_question + dns_body

while True:
    data, addr = sock.recvfrom(512)
    response = build_response(data)
    print(f"Response sent to {addr}: {response}")
    sock.sendto(response, addr)
