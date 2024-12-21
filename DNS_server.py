import socket
import threading
import sys

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

# Track server metrics
request_count = 0

def getflags():
    QR = '1'
    OPCODE = '0000'
    AA = '1'
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '000'
    RCODE = '0000'
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
    qbytes += b'\x00'
    qbytes += qtype + b'\x00\x01'
    return qbytes

def build_record(domain_name, qtype, ttl, value):
    rbytes = b'\xc0\x0c'
    if qtype == b'\x00\x01':
        rbytes += b'\x00\x01'
        rbytes += b'\x00\x01'
        rbytes += int(ttl).to_bytes(4, byteorder='big')
        rbytes += bytes([0, 4])
        rbytes += b''.join([bytes([int(part)]) for part in value.split('.')])
    elif qtype in {b'\x00\x05', b'\x00\x0f', b'\x00\x02'}:
        if qtype == b'\x00\x05':
            rbytes += b'\x00\x05'
        elif qtype == b'\x00\x0f':
            rbytes += b'\x00\x0f'
        elif qtype == b'\x00\x02':
            rbytes += b'\x00\x02'
        rbytes += b'\x00\x01'
        rbytes += int(ttl).to_bytes(4, byteorder='big')
        alias_parts = value.split('.')
        alias_bytes = b''.join([bytes([len(part)]) + part.encode() for part in alias_parts])
        alias_bytes += b'\x00'
        rbytes += len(alias_bytes).to_bytes(2, byteorder='big')
        rbytes += alias_bytes
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

def handle_client(data, addr):
    global request_count
    request_count += 1
    response = build_response(data)
    print(f"Response sent to {addr}: {response}")
    sock.sendto(response, addr)

def main():
    print(f"DNS server running on {DNS_IP}:{DNS_PORT}")
    while True:
        data, addr = sock.recvfrom(512)
        client_thread = threading.Thread(target=handle_client, args=(data, addr))
        client_thread.start()

def cli():
    while True:
        command = input("Enter command (status/exit): ").strip().lower()
        if command == "status":
            print(f"Server running on {DNS_IP}:{DNS_PORT}")
            print(f"Requests handled: {request_count}")
        elif command == "exit":
            print("Shutting down server.")
            sys.exit()

if __name__ == "__main__":
    threading.Thread(target=main).start()
    cli()