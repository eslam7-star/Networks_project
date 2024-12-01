import socket

# DNS client configuration
DNS_SERVER_IP = "127.0.0.1"
DNS_SERVER_PORT = 5555  # Updated to match the server port

def build_query(domain_name, query_type="A"):
    # Build a DNS query packet
    transaction_id = b'\xaa\xbb'  # Random transaction ID
    flags = b'\x01\x00'  # Standard query
    qdcount = b'\x00\x01'  # Number of questions
    ancount = b'\x00\x00'  # Number of answers
    nscount = b'\x00\x00'  # Number of authority records
    arcount = b'\x00\x00'  # Number of additional records

    dns_header = transaction_id + flags + qdcount + ancount + nscount + arcount

    # Convert domain name to DNS query format
    query_name = b''.join(len(part).to_bytes(1, byteorder='big') + part.encode() for part in domain_name.split('.'))
    query_name += b'\x00'

    # Map query type to its corresponding code
    query_type_map = {"A": b'\x00\x01', "CNAME": b'\x00\x05', "MX": b'\x00\x0f', "NS": b'\x00\x02'}
    qtype = query_type_map.get(query_type, b'\x00\x01')  # Default to A if type not found
    qclass = b'\x00\x01'  # Class IN (internet)

    dns_question = query_name + qtype + qclass

    return dns_header + dns_question

def decode_response(response):
    # Decode the DNS response packet to plaintext
    transaction_id = response[:2]
    flags = response[2:4]
    qdcount = int.from_bytes(response[4:6], byteorder='big')
    ancount = int.from_bytes(response[6:8], byteorder='big')
    nscount = int.from_bytes(response[8:10], byteorder='big')
    arcount = int.from_bytes(response[10:12], byteorder='big')

    print(f"Transaction ID: {transaction_id.hex()}")
    print(f"Flags: {flags.hex()}")
    print(f"Questions: {qdcount}")
    print(f"Answers: {ancount}")
    print(f"Authority Records: {nscount}")
    print(f"Additional Records: {arcount}")

    offset = 12
    for _ in range(qdcount):
        offset += decode_question(response, offset)

    for _ in range(ancount):
        offset += decode_record(response, offset)

def decode_question(response, offset):
    # Decode the question section of the DNS response
    domain_name, length = decode_domain_name(response, offset)
    qtype = response[offset+length:offset+length+2]
    qclass = response[offset+length+2:offset+length+4]

    print(f"Question: {domain_name}, Type: {qtype.hex()}, Class: {qclass.hex()}")

    return length + 4

def decode_record(response, offset):
    # Decode the resource record section of the DNS response
    domain_name, length = decode_domain_name(response, offset)
    rtype = response[offset+length:offset+length+2]
    rclass = response[offset+length+2:offset+length+4]
    ttl = int.from_bytes(response[offset+length+4:offset+length+8], byteorder='big')
    rdlength = int.from_bytes(response[offset+length+8:offset+length+10], byteorder='big')
    rdata = response[offset+length+10:offset+length+10+rdlength]

    if rtype == b'\x00\x01':  # Type A
        rdata_text = socket.inet_ntoa(rdata)
        print(f"Answer: {domain_name}, Type: A, Class: IN, TTL: {ttl}, Address: {rdata_text}")
    
    elif rtype == b'\x00\x05':  # Type CNAME
        cname, _ = decode_domain_name(rdata, 0)
        print(f"Answer: {domain_name}, Type: CNAME, Class: IN, TTL: {ttl}, CNAME: {cname}")
    
    elif rtype == b'\x00\x0f':  # Type MX
        preference = int.from_bytes(rdata[:2], byteorder='big')
        exchange, _ = decode_domain_name(rdata, 2)
        print(f"Answer: {domain_name}, Type: MX, Class: IN, TTL: {ttl}, Preference: {preference}, Exchange: {exchange}")
    
    elif rtype == b'\x00\x02':  # Type NS
        nsdname, _ = decode_domain_name(rdata, 0)
        print(f"Answer: {domain_name}, Type: NS, Class: IN, TTL: {ttl}, NSDNAME: {nsdname}")

    return length + 10 + rdlength

def decode_domain_name(data, offset):
    # Decode a domain name from the DNS packet
    domain_name = ""
    length = data[offset]
    jumped = False
    jump_offset = 0
    
    while length != 0:
        if length >= 192:  # Pointer detected
            if not jumped:
                jump_offset = offset + 2
            offset = ((length - 192) << 8) + data[offset + 1]
            length = data[offset]
            jumped = True
        else:
            if offset + 1 + length > len(data):
                raise IndexError("Index out of range while decoding domain name")
            domain_name += data[offset + 1 : offset + 1 + length].decode(errors='ignore') + "."
            offset += length + 1
            if offset >= len(data):
                raise IndexError("Index out of range while decoding domain name")
            length = data[offset]
    
    if not jumped:
        return domain_name[:-1], offset + 1 - jump_offset
    else:
        return domain_name[:-1], jump_offset

def send_dns_query(domain_name, query_type="A"):
    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Build and send the DNS query packet
        query_packet = build_query(domain_name, query_type)
        sock.sendto(query_packet, (DNS_SERVER_IP, DNS_SERVER_PORT))
        
        # Receive and decode the DNS response packet
        response_packet, _ = sock.recvfrom(600)  # Max size of DNS packet is 512 bytes
        decode_response(response_packet)
    
    except ConnectionResetError as e:
        print(f"Connection error occurred: {e}")
    except IndexError as e:
        print(f"Index error occurred: {e}")
    
if __name__ == "__main__":
    domain_to_query = "example.com"
    send_dns_query(domain_to_query)