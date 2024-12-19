import socket
import threading

# DNS server configuration
DNS_PORT = 5555  # Use port 5555 for the DNS server
DNS_IP = "127.0.0.1"  # IP address for the DNS server (localhost)

# DNS record database (for simplicity, using a dictionary)
dns_records = {
    "example.com": {"A": "93.184.216.34", "CNAME": "alias.example.com", "MX": "mail.example.com", "NS": "ns.example.com"},
    "alias.example.com": {"A": "93.184.216.34"},
    "mail.example.com": {"A": "93.184.216.35"},
    "ns.example.com": {"A": "93.184.216.36"}
}

def handle_query(data, addr, sock):
    # Extract the domain name and query type from the DNS query
    domain_name, query_type = extract_domain_name_and_type(data)
    
    # Check if the domain name is in the DNS records and if the query type is supported
    if domain_name in dns_records and query_type in dns_records[domain_name]:
        record_data = dns_records[domain_name][query_type]  # Get the record data
        response = build_response(data, record_data, query_type)  # Build and return the DNS response
    else:
        response = build_response(data, None, query_type)  # Return a response indicating no record found
    
    sock.sendto(response, addr)  # Send the DNS response back to the client

def extract_domain_name_and_type(data):
    # Extract the domain name from the DNS query packet
    domain_name = ""
    i = 12  # DNS query starts at byte 12
    length = data[i]
    while length != 0:
        domain_name += data[i+1:i+1+length].decode() + "."  # Append each part of the domain name
        i += length + 1
        length = data[i]
    domain_name = domain_name[:-1]  # Remove the trailing dot
    
    # Extract the query type (last two bytes of the query section)
    query_type = data[i+5:i+7]
    query_type = int.from_bytes(query_type, byteorder='big')  # Convert bytes to integer
    
    # Map query type to human-readable format
    query_type_map = {1: "A", 5: "CNAME", 15: "MX", 2: "NS"}
    return domain_name, query_type_map.get(query_type, "A")  # Default to "A" if type not found

def build_response(query, record_data, query_type):
    # Build a DNS response packet
    transaction_id = query[:2]  # Transaction ID from the query
    flags = b'\x81\x80'  # Standard query response, no error
    qdcount = b'\x00\x01'  # Number of questions
    ancount = b'\x00\x01' if record_data else b'\x00\x00'  # Number of answers
    nscount = b'\x00\x00'  # Number of authority records
    arcount = b'\x00\x00'  # Number of additional records

    dns_header = transaction_id + flags + qdcount + ancount + nscount + arcount  # DNS header
    dns_question = query[12:]  # DNS question section

    if record_data:
        dns_answer = b'\xc0\x0c'  # Pointer to the domain name in the question section
        dns_answer += (b'\x00\x01' if query_type == "A" else
                       b'\x00\x05' if query_type == "CNAME" else
                       b'\x00\x0f' if query_type == "MX" else
                       b'\x00\x02')  # Type A, CNAME, MX, or NS
        dns_answer += b'\x00\x01'  # Class IN (internet)
        dns_answer += b'\x00\x00\x00\x3c'  # TTL (60 seconds)
        
        if query_type == "A":
            dns_answer += b'\x00\x04'  # Data length (4 bytes for IPv4 address)
            dns_answer += socket.inet_aton(record_data)  # IP address in binary format
        else:
            record_bytes = record_data.encode()  # Convert record data to bytes
            dns_answer += len(record_bytes).to_bytes(2, byteorder='big')  # Data length
            dns_answer += record_bytes  # Record data in binary format

        return dns_header + dns_question + dns_answer  # Complete DNS response
    else:
        return dns_header + dns_question  # Response with no answer

def start_dns_server():
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DNS_IP, DNS_PORT))  # Bind the socket to the IP and port
    
    print(f"DNS server started on {DNS_IP}:{DNS_PORT}")
    
    while True:
        data, addr = sock.recvfrom(512)  # Receive DNS query (max size 512 bytes)
        threading.Thread(target=handle_query, args=(data, addr, sock)).start()  # Handle each query in a new thread

if __name__ == "__main__":
    start_dns_server()  # Start the DNS server
