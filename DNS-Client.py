import socket

# DNS server configuration
DNS_SERVER_IP = '127.0.0.1'
DNS_SERVER_PORT = 44444

def build_query(domain_name, qtype):
    """
    Build a DNS query.
    :param domain_name: The domain name to query.
    :param qtype: The type of DNS record to request.
    :return: The DNS query as bytes.
    """
    TransactionID = b'\xaa\xbb'  # Random transaction ID
    Flags = b'\x01\x00'  # Standard query, recursion not desired
    QDCOUNT = b'\x00\x01'  # One question
    ANCOUNT = b'\x00\x00'  # No answers
    NSCOUNT = b'\x00\x00'  # No authority records
    ARCOUNT = b'\x00\x00'  # No additional records
    
    # Encode the domain name into the DNS query format
    qbytes = b''
    for part in domain_name.split('.'):
        qbytes += bytes([len(part)]) + part.encode()
    qbytes += b'\x00'  # Null byte to terminate the domain name

    # Append QTYPE and QCLASS
    qbytes += qtype + b'\x00\x01'  # QCLASS = IN (Internet)
    
    # Construct the complete query
    return TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT + qbytes

def parse_response(response):
    """
    Parse a DNS response.
    :param response: The raw response from the server.
    :return: Parsed information about the response.
    """
    TransactionID = response[:2]
    Flags = response[2:4]
    QDCOUNT = int.from_bytes(response[4:6], byteorder='big')
    ANCOUNT = int.from_bytes(response[6:8], byteorder='big')
    NSCOUNT = int.from_bytes(response[8:10], byteorder='big')
    ARCOUNT = int.from_bytes(response[10:12], byteorder='big')

    # Skip over the question section
    offset = 12
    while response[offset] != 0:
        offset += 1 + response[offset]
    offset += 5  # Null byte, QTYPE, and QCLASS

    # Parse the answer section
    answers = []
    for _ in range(ANCOUNT):
        name = response[offset:offset + 2]
        rtype = response[offset + 2:offset + 4]
        rclass = response[offset + 4:offset + 6]
        ttl = int.from_bytes(response[offset + 6:offset + 10], byteorder='big')
        rdlength = int.from_bytes(response[offset + 10:offset + 12], byteorder='big')
        rdata = response[offset + 12:offset + 12 + rdlength]
        offset += 12 + rdlength

        if rtype == b'\x00\x01':  # A record
            ip = '.'.join(map(str, rdata))
            answers.append({'Type': 'A', 'TTL': ttl, 'IP': ip})
        elif rtype in {b'\x00\x05', b'\x00\x0f', b'\x00\x02'}:  # CNAME, MX, NS
            alias = []
            idx = 0
            while rdata[idx] != 0:
                length = rdata[idx]
                idx += 1
                alias.append(rdata[idx:idx + length].decode())
                idx += length
            answers.append({'Type': rtype.hex(), 'TTL': ttl, 'Alias': '.'.join(alias)})

    return answers

def main():
    domain = input("Enter the domain to query: ")
    record_type = input("Enter the record type (A, CNAME, MX, NS): ").upper()

    # Map record types to QTYPE values
    qtype_mapping = {
        'A': b'\x00\x01',
        'CNAME': b'\x00\x05',
        'MX': b'\x00\x0f',
        'NS': b'\x00\x02',
    }

    if record_type not in qtype_mapping:
        print("Unsupported record type.")
        return

    qtype = qtype_mapping[record_type]
    query = build_query(domain, qtype)

    # Send query to the server
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_sock:
        client_sock.settimeout(5.0)
        client_sock.sendto(query, (DNS_SERVER_IP, DNS_SERVER_PORT))

        try:
            response, _ = client_sock.recvfrom(512)
            answers = parse_response(response)
            if answers:
                for answer in answers:
                    print(f"Type: {answer['Type']}, TTL: {answer['TTL']}, Data: {answer.get('IP', answer.get('Alias'))}")
            else:
                print("No answers received.")
        except socket.timeout:
            print("Request timed out.")

if __name__ == "__main__":
    main()

