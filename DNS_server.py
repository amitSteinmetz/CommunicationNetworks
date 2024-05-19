import socket


def main():

    # Example for pairs of domain names and IP addresses
    dns_table = {"www.google.com": "8.8.8.8",
                 "www.youtube.com": " 208.65.153.238",
                 "www.asus.com": "192.168.2.1", "www.cisco.com": "192.168.0.30"}

    # Creating UDP socket for communication with clients
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("[SERVER] Server is working right now..")

    # Set ip and port
    ip_address = input("[SERVER] Enter client ip address: ")
    addr = (ip_address, 30775)

    # Bind server to a port which communication will go through
    sock.bind((ip_address, 20373))

    keep_going = "Y"

    # DNS is going to receive a domain name from client. The domain will be stored in 'data' variable, and the IP
    # address of sender will be stored in 'address' variable. NOTE: 1024 - number of bytes, upper bound for message
    while keep_going.upper() == "Y":

        domain_name, address = sock.recvfrom(1024)

        # Decode the received bytes to a string
        domain_name = domain_name.decode()

        print(f"[SERVER] Client wants the IP address of {domain_name}")

        # Fetch the IP address from table, and transfer it to bytes before sending
        match_ip = dns_table.get(domain_name, "Not found!")

        # If server didn't find the match ip, he will send a request to a server one level above it in the hierarchy
        # of DNS
        if match_ip == 'Not found!':
            try:
                match_ip = socket.gethostbyname(domain_name)
            except socket.gaierror:
                match_ip = 'Not found!'

        # Sending the match IP address to the sender address
        sock.sendto(match_ip.encode(), addr)
        if match_ip == 'Not found!':
            print("[SERVER] IP for this domain doesn't exist")
        else:
            print("[SERVER] Sending...")

        # Receive from client decision if continue or quit
        keep_going, client_address = sock.recvfrom(1024)
        keep_going = keep_going.decode()

    # Client decided to quit, closing connection
    print("[SERVER] Exit program... ")
    sock.close()


if __name__ == "__main__":
    main()
