from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
import socket
import sys
import time
import os
import random


# Constants
WINDOW_SIZE = 10
TIMEOUT = 3.0
INITIAL_THRESHOLD = 16
MAX_WINDOW_SIZE = 100
INITIAL_WINDOW_SIZE = 10
BUFFER_SIZE = 1024

# Global variables
seq_num = 0
un_acked_packets = []
congestion_window = 1
threshold = INITIAL_THRESHOLD
last_packet_received = 0
last_ack_received = -1
window_size = INITIAL_WINDOW_SIZE


# Generate random packet ID
def generate_packet_id():
    return random.randint(0, 10000)


def send_packet_udp(sock, data, addr):

    global seq_num

    # Packet looks like: seq_num | ID | data
    packet = (str(seq_num) + "|" + str(generate_packet_id()) + "|").encode()
    packet += data  # assume data is encode already

    # Send packet
    sock.sendto(packet, addr)
    seq_num += 1

    # Saving packet sending time
    packet_time = time.time()

    # Client stop until receiving ACK from server
    receive_ack(sock, packet, addr, packet_time)


def receive_ack(sock, data, addr, packet_time):

    global congestion_window, threshold

    # Extract packet content, in case that the packet will be needed to send again
    packet_content = data.split("|".encode())[2]

    # Prepare tp get an ACK from server
    packet, server_address = sock.recvfrom(1024)
    decoded_packet = packet.decode()

    # Extract seq_num to check reliability
    ack = int(decoded_packet.split("|")[0])

    # If client received the correct ack, everything is great
    if ack == seq_num - 1:
        # Works good, can increase the job window, carefully
        congestion_window += 1
        if congestion_window > threshold:
            congestion_window = threshold
        if congestion_window > MAX_WINDOW_SIZE:
            congestion_window = MAX_WINDOW_SIZE

    # Received ack is smaller than current ack - point on packet lost, so we send the last packet again
    else:
        send_packet_udp(sock, packet_content, addr)

    # If too long time pass till packet sent, client send it again
    if time.time() - packet_time > TIMEOUT:
        send_packet_udp(sock, packet_content, addr)
        # Maybe this happened because overload of job, so we decrease the job window
        congestion_window = 1
        threshold /= 2
        if threshold < 1:
            threshold = 1


def receive_packet_udp(sock, addr):

    global last_packet_received, window_size, seq_num

    # When receiving packet - first check seq_number for reliability
    data, client_address = sock.recvfrom(BUFFER_SIZE + 8)
    packet_content = data.split("|".encode())[2]
    ack = int((data.split("|".encode())[0]).decode())

    # If seq_num identical to received ack - everything is ok, and we can increase job window
    if seq_num == ack:
        window_size += 1
        if window_size > MAX_WINDOW_SIZE:
            window_size = MAX_WINDOW_SIZE
        # Update client with ack, that packet has safely received
        ack_update = str(ack) + "|" + str(generate_packet_id()) + "|" + "ACK"
        sock.sendto(ack_update.encode(), addr)

    # In case of duplicate - ignore the packet
    elif seq_num > ack:
        return None

    # Shouldn't happen, because if seq_num < ack it means that packet lost occurred, And we already take care of that in
    # other functions. But for safety, we exit from program, it is better to try again
    else:
        print("[SERVER] Packet lost... waiting to receive lost packets")
        sys.exit()

    seq_num += 1

    return packet_content


# upload command #
def upload(sock, protocol, addr):

    # Choose a file to upload
    with open(input("[CLIENT] Choose a file to upload: "), 'rb') as f:
        file = f.read()
        file_name = f.name

    # sending file name before sending file content
    if protocol == 'tcp':
        sock.send(file_name.encode())
    else:
        send_packet_udp(sock, file_name.encode(), addr)

    # Sending content of the file, in chunks (because it can be a big file, and there is transfer limit)
    packet_size = len(file)
    upload_chunk = 1024
    i = 0
    while packet_size > 0:
        if protocol == 'tcp':
            sock.send(file[i:i + upload_chunk])
        else:
            send_packet_udp(sock, file[i:i + upload_chunk], addr)
        i = i + upload_chunk
        packet_size -= upload_chunk

    print("[CLIENT] Finish uploading")

    # Update server that upload done
    if protocol == 'rudp':
        send_packet_udp(sock, "0".encode(), addr)


# download command #
def download(sock, protocol, addr):

    # Choose file to download
    file_path_for_download = input("[CLIENT] Enter file path for download: ")

    # Send decision
    if protocol == 'tcp':
        sock.send(file_path_for_download.encode())
    else:
        send_packet_udp(sock, file_path_for_download.encode(), addr)

    downloaded_file = bytes()

    # Receive the file from server:
    while True:
        if protocol == 'tcp':
            download_chunk = sock.recv(1024)
            downloaded_file += download_chunk
        else:
            download_chunk = receive_packet_udp(sock, addr)
            if download_chunk != '0'.encode():
                downloaded_file += download_chunk
            else:
                break
        if not download_chunk:
            break

    # Choose a folder to place the file in
    folder = input("[CLIENT] Choose a folder to place the file: ")

    # Add the file name to folder path in order to create the complete path
    last_backslash_index = file_path_for_download.rfind('\\')
    downloaded_file_name = file_path_for_download[last_backslash_index + 1:]
    downloaded_file_path = folder + "\\" + downloaded_file_name

    # Check if file is already exists, and create it (if not exists, or need to be replaced)
    if os.path.isfile(downloaded_file_path):
        print(f"[CLIENT] '{downloaded_file_name}' is already exists, do you want to replace it?")
        replace = input("Y/N: ")
        if replace == 'Y':
            print("[CLIENT] Replacing file...")
            with open(downloaded_file_path, 'wb') as new_file:
                new_file.write(downloaded_file)
        else:
            print("[CLIENT] Bye Bye...")
    else:
        print(f"[CLIENT] Downloading {downloaded_file_name} ...")
        with open(downloaded_file_path, 'wb') as new_file:
            new_file.write(downloaded_file)


# List command #
def list_of_files(sock, protocol, addr):

    server_list = bytes()

    # Receive the list from server:
    while True:
        if protocol == 'tcp':
            list_chunk = sock.recv(1024)
            server_list += list_chunk
        else:
            list_chunk = receive_packet_udp(sock, addr)
            if list_chunk.decode() != '0':
                server_list += list_chunk
            else:
                break
        if not list_chunk:
            break

    print("[CLIENT] List of files on FTP server directory:")
    print(server_list.decode())


def create_tcp_connection(addr):

    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("[CLIENT] Socket created successfully")

    # Connect to server
    sock.connect((addr[0], 30775))
    print("[CLIENT] Connected successfully")

    return sock


def handle_dhcp_packet(packet):
    if DHCP in packet and packet[DHCP].options[0][1] == 2:
        print("DHCP Offer received")
        dhcp_request = Ether(src=get_if_hwaddr(conf.iface), dst='ff:ff:ff:ff:ff:ff')/\
                       IP(src='0.0.0.0', dst='255.255.255.255')/\
                       UDP(sport=68, dport=67)/\
                       BOOTP(op=1, xid=packet[BOOTP].xid, chaddr=packet[BOOTP].chaddr)/\
                       DHCP(options=[('message-type', 'request'), ('requested_addr', packet[BOOTP].yiaddr), ('server_id', '192.168.1.1'), 'end'])
        sendp(dhcp_request, iface=conf.iface)
    elif DHCP in packet and packet[DHCP].options[0][1] == 5:
        print("DHCP Ack received")
        print("Assigned IP address: " + packet[BOOTP].yiaddr)
        return


def ftp_server(addr):

    global seq_num

    # Socket for deliver decisions about protocol type
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind it - we want to send messages from 30xxx port (last 3 digits belong to jameel ID)
    sock.bind((addr[0], 30775))

    # Choose protocol and update the server
    protocol = input("[CLIENT] Choose communication protocol, TCP or RUDP: ").lower()
    sock.sendto(protocol.encode(), addr)

    # formal details, will be sent soon
    user_name = input("[CLIENT] Enter UserName: ")
    password = input("[CLIENT] Enter password: ")
    details = (user_name + " " + password).encode()

    if protocol == 'tcp':

        # create TCP connection
        sock = create_tcp_connection(addr)

        # Send formal details
        sock.send(details)

        # Wait for OK message from server
        validation = sock.recv(512).decode()

    elif protocol == 'rudp':

        print("[CLIENT] Socket created successfully")

        # Send SYN - handshake
        sock.sendto("0|SYN".encode(), addr)
        print("[CLIENT] Send SYN for hand-shake")
        seq_num += 1

        # Wait to receive SYN-ACK
        ans_first_ack, sender_address = sock.recvfrom(1024)
        ans_first_ack = int(ans_first_ack.decode().split("|")[0])

        if ans_first_ack == 0:
            print("[CLIENT] SYN-ACK received")
        else:
            print("[CLIENT] Something went wrong, exit program...")
            sys.exit()

        # Send formal details
        send_packet_udp(sock, details, addr)

        # Wait to get OK message from server
        validation = receive_packet_udp(sock, addr).decode()

    else:
        print("[CLIENT] Wrong protocol, exit program...")
        sys.exit()

    # sleep, for visual effect only
    time.sleep(1)

    # Check the validation message
    if validation == 'ERROR':
        sock.close()
        print("[CLIENT] Got an error message, exit program...")
        sys.exit()
    else:
        print("[CLIENT] Got an OK message from server")

    # Choose command
    command_type = input("[CLIENT] Enter command type: ")

    # Send command type to server
    if protocol == 'tcp':
        sock.send(command_type.encode())
    else:
        send_packet_udp(sock, command_type.encode(), addr)

    if command_type == "upload":
        upload(sock, protocol, addr)
    elif command_type == "download":
        download(sock, protocol, addr)
    elif command_type == "list":
        list_of_files(sock, protocol, addr)
    else:
        print("[CLIENT] Invalid command, exit program...")

    # Close the connection and socket
    sock.close()


def dns_server(addr):

    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("[CLIENT] socket created successfully")

    # Bind it - we want to send messages from 30xxx port (last 3 digits belong to jameel ID)
    sock.bind((addr[0], 30775))

    # Sending domain name and receiving match ip address from DNS server
    want_ip = "Y"

    while want_ip.upper() == "Y":

        # Send domain name to server
        domain_name = input("[CLIENT] Enter domain name for which the IP is needed: ")
        sock.sendto(domain_name.encode(), addr)

        # Receive answer from server
        ip, address = sock.recvfrom(1024)

        reply_ip = ip.decode()

        print(f"[CLIENT] The IP for the domain name {domain_name} is: {reply_ip}")

        want_ip = input("[CLIENT] Do you want to continue? Y/N: ").upper()

        # Update server if continue or quit
        if want_ip == 'N':
            sock.sendto("N".encode(), addr)
            print("[CLIENT] Exit program...")
        else:
            sock.sendto("Y".encode(), addr)

    # Done, closing connection
    sock.close()


def dhcp_server():
    sniff(filter="udp and (port 67 or port 68)", prn=handle_dhcp_packet)


def main():

    # Set local IP address and port number (port 20xxx - 3 last digit belong to amit ID)
    local_ip = input("[CLIENT] Enter ip address: ")
    local_port = 20373

    addr = (local_ip, local_port)

    # Choose server to communicate with
    communication_server = input("[CLIENT] Choose a server: ").lower()

    if communication_server == 'ftp':
        ftp_server(addr)
    elif communication_server == 'dns':
        dns_server(addr)
    elif communication_server == 'dhcp':
        dhcp_server()
    else:
        print(f"[CLIENT] {communication_server} is unreachable, shutting down...")


if __name__ == "__main__":
    main()
