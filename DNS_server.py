import socket
import threading
import sys
from datetime import datetime

# DNS server configuration
DNS_PORT = 44444
DNS_IP = '127.0.0.1'
GOOGLE_DNS_IP = '8.8.8.8'
GOOGLE_DNS_PORT = 53

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((DNS_IP, DNS_PORT))

# Load DNS records from file
def load_dns_records(filename='dns_records.txt'):
    dns_records = {}
    try:
        with open(filename, 'r') as file:
            for line in file:
                parts = line.strip().split(',')
                if len(parts) == 3:
                    domain_name, record_type, value = parts
                    if domain_name not in dns_records:
                        dns_records[domain_name] = {}
                    dns_records[domain_name][record_type] = value
    except FileNotFoundError:
        print("No DNS records file found, starting with an empty record set.")
    return dns_records

# Save DNS records to the file
def save_dns_record(domain_name, record_type, value, filename='dns_records.txt'):
    with open(filename, 'a') as file:
        file.write(f"{domain_name},{record_type},{value}\n")

# Load DNS records from the file
dns_records = load_dns_records()

# Track server metrics
request_count = 0

def save_request_to_file(client_address, domain_name, response, answer):
    with open('dns_requests.txt', 'a') as file:
        # Log additional information about the answer (Type, TTL, IP or Alias)
        record_type = answer['Type']
        ttl = answer['TTL']
        data = answer.get('IP', answer.get('Alias'))
        file.write(f"{datetime.now()} | {client_address} | {domain_name} | {response.hex()} | Server Response-> Type: {record_type}, TTL: {ttl}, Data: {data}\n")

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


def parse_google_dns_response(response, domain_name, qtype ,filename='dns_records.txt'):

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
            save_dns_record(domain_name, "A" , ip, filename)
        elif rtype in {b'\x00\x05', b'\x00\x0f', b'\x00\x02'}:  # CNAME, MX, NS
            alias = []
            idx = 0
            while rdata[idx] != 0:
                length = rdata[idx]
                idx += 1
                alias.append(rdata[idx:idx + length].decode())
                idx += length
            answers.append({'Type': rtype.hex(), 'TTL': ttl, 'Alias': '.'.join(alias)})
            save_dns_record(domain_name, rtype.hex() , '.'.join(alias) , filename)


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
    return None

def forward_to_google_dns(data):
    """Forward DNS query to Google DNS and return the response"""
    sock_google = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_google.settimeout(3)
    try:
        sock_google.sendto(data, (GOOGLE_DNS_IP, GOOGLE_DNS_PORT))
        response, _ = sock_google.recvfrom(512)
        return response
    except socket.timeout:
        print("Google DNS query timed out.")
        return None


def recursive_dns_query(domain_name, qtype, data):
    """Recursively query Google DNS until a valid response is received or NXDOMAIN is returned."""
    # Forward query to Google DNS
    print(f"Recursively querying Google DNS for {domain_name}...")
    
    # Create a socket to send the query to Google DNS
    sock_google = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_google.settimeout(3)
    
    try:
        # Send the query to Google DNS (8.8.8.8)
        sock_google.sendto(data, (GOOGLE_DNS_IP, GOOGLE_DNS_PORT))
        response, _ = sock_google.recvfrom(512)
        
        # Parse the response to check if it's a valid record or NXDOMAIN
        if response:
            # Here you would need to parse the response to extract the correct record type (A, CNAME, etc.)
            ip_address = "8.8.8.8"  # Placeholder for the actual IP extraction
            print(f"Received response from Google DNS for {domain_name}: {ip_address}")
            
            # Add the record to the local DNS file and in-memory records
            parse_google_dns_response(response,domain_name,qtype)
            
            # Reload DNS records from file to ensure they're in memory
            global dns_records
            dns_records = load_dns_records()
            
            return response, {"Type": 'A', "TTL": 300, "IP": ip_address}
        else:
            print(f"No response received from Google DNS for {domain_name}.")
            return None, None
    except socket.timeout:
        print(f"Google DNS query timed out for {domain_name}.")
        return None, None




def add_to_dns_file(domain_name, record_type, record_value):
    """Add a new record to the dns_records.txt file."""
    save_dns_record(domain_name, record_type, record_value)

def build_response(data):
    TransactionID = data[:2]
    Flags = getflags()
    QDCOUNT = b'\x00\x01'
    domain_name, qtype = parse_question(data[12:])
    
    # First, try to find the record locally
    records = find_records(domain_name, qtype)
    if records is None:
        # If not found locally, perform a recursive DNS query to Google DNS
        print(f"Forwarding query for {domain_name} to Google DNS recursively...")
        response, answer = recursive_dns_query(domain_name, qtype, data)
        
        if response:
            return response, domain_name, answer
        else:
            # If no valid response is received, return NXDOMAIN
            return data[:2] + getflags() + QDCOUNT + b'\x00\x00\x00\x00\x00\x00', domain_name, {"Type": 'NXDOMAIN', "TTL": 0, "Alias": "No record found"}
    
    # If the record was found locally, process the response as usual
    ANCOUNT = len(records).to_bytes(2, byteorder='big')
    NSCOUNT = (0).to_bytes(2, byteorder='big')
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dns_header = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
    dns_question = build_question(domain_name, qtype)
    dns_body = b''.join([build_record(domain_name, qtype, rec['ttl'], rec['value']) for rec in records])

    # Prepare the answer for logging
    answer = {
        "Type": 'A',  # Or extract the correct type based on records
        "TTL": 300,
        "IP": records[0]['value']  # Assuming it's an 'A' record
    }
    return dns_header + dns_question + dns_body, domain_name, answer


def handle_client(data, addr):
    global request_count
    request_count += 1
    response, domain_name, answer = build_response(data)
    
    # Log request with detailed information
    print(f"Response sent to {addr}: {response}")
    save_request_to_file(addr[0], domain_name, response, answer)
    sock.sendto(response, addr)

def main():
    print(f"DNS server running on {DNS_IP}:{DNS_PORT}")
    while True:
        data, addr = sock.recvfrom(512)
        client_thread = threading.Thread(target=handle_client, args=(data, addr))
        client_thread.start()


def auth(isauthenticated):
    while(1):
        login = input("login? y or n :")
        if login == "n":
            return 0
        user_name = input("enter username: ")
        password = input("enter password: ")
        if user_name != "admin" or password != "admin" :
            print("authentication failed, invlaid login")
        else:    
            return 1

def cli():
    isauthenticated = 0
    while True:
        command = input("Enter command (status/exit/showrecords/showrequests): ").strip().lower()
        if command == "status":
            print(f"Server running on {DNS_IP}:{DNS_PORT}")
            print(f"Requests handled: {request_count}")
        elif command == "exit":
            print("Shutting down server.")
            sys.exit()
        elif command == "showrecords":
            if not isauthenticated:
                isauthenticated = auth(isauthenticated)
                if not isauthenticated:
                    continue
            try:
                with open('dns_records.txt', 'r') as file:
                    print("DNS Records:")
                    for line in file:
                        print(line.strip())
            except FileNotFoundError:
                print("DNS records file not found.")
        elif command == "showrequests":
            if not isauthenticated:
                isauthenticated = auth(isauthenticated)
                if not isauthenticated:
                    continue
            try:
                with open('dns_requests.txt', 'r') as file:
                    print("DNS Request Log:")
                    for line in file:
                        print(line.strip())
            except FileNotFoundError:
                print("DNS requests file not found.")
        else:
            print("Invalid command. Please try again.")

if __name__ == "__main__":
    threading.Thread(target=main).start()
    cli()
