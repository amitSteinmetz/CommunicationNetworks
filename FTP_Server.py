import socket
import os
import json
import sys
import random
import time

# user_name = aj123, password = 2023a

# Constants
BUFFER_SIZE = 1024
INITIAL_WINDOW_SIZE = 10
MAX_WINDOW_SIZE = 100
MAX_UN_ACKED_PACKETS = 50
TIMEOUT = 3.0
INITIAL_THRESHOLD = 16

# Global variables
last_packet_received = -1
window_size = INITIAL_WINDOW_SIZE
seq_num = 0
congestion_window = 1
threshold = INITIAL_THRESHOLD


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


# Upload command: #
def upload(connection_socket, directory_name, protocol, addr):

    # Receive file path from client
    if protocol == 'tcp':
        file_name_received = connection_socket.recv(512).decode()
    else:
        file_name_received = receive_packet_udp(connection_socket, addr).decode()

    # Extract file name from the path
    last_backslash_index = file_name_received.rfind('\\')
    file_name = file_name_received[last_backslash_index + 1:]

    # Reset variable that will continue the packet with file
    file_to_upload = bytes()

    # Receive the file to upload
    while True:
        if protocol == 'tcp':
            upload_chunk = connection_socket.recv(1024)
            file_to_upload += upload_chunk
        else:
            upload_chunk = receive_packet_udp(connection_socket, addr)
            if upload_chunk != '0'.encode():
                file_to_upload += upload_chunk
            else:
                break
        if not upload_chunk:
            break

    file_path = directory_name + "\\" + file_name

    # Check if file is already exists, and create it (if not exist or need to be replaced)
    if os.path.isfile(file_path):
        print(f"[SERVER] '{file_name}' is already exists, do you want to replace it?")
        replace = input("Y/N: ")
        if replace == 'Y':
            print("[SERVER] Replacing file...")
            with open(file_path, 'wb') as new_file:
                new_file.write(file_to_upload)
        else:
            print("[SERVER] Bye Bye...")
    else:
        print("[SERVER] Uploading a new file...")
        with open(file_path, 'wb') as new_file:
            new_file.write(file_to_upload)


# Download command: #
def download(connection_socket, protocol, addr):

    # Receive file name from client
    if protocol == 'tcp':
        file_name_for_download = connection_socket.recv(512).decode()
    else:
        file_name_for_download = receive_packet_udp(connection_socket, addr).decode()

    # Check if requested file exists in server directory, and download it (if exist)
    if not os.path.isfile(file_name_for_download):
        print("[SERVER] Sorry, requested file doesn't exist :(")

    else:
        with open(file_name_for_download, 'rb') as f:
            download_file = f.read()

        print("[SERVER] Downloading requested file...")

        # Send file in chunks
        packet_size = len(download_file)
        chunk = 1024
        i = 0
        while packet_size > 0:
            if protocol == 'tcp':
                connection_socket.send(download_file[i:i + chunk])
            else:
                send_packet_udp(connection_socket, download_file[i:i + chunk], addr)
            i = i + chunk
            packet_size -= chunk

        print("[SERVER] Finish downloading")

        # Update client that download has completed
        if protocol == 'rudp':
            send_packet_udp(connection_socket, "0".encode(), addr)


# List command: #
def list_of_files(connection_socket, directory_name, protocol, addr):

    # Get the list from operating system
    files_list = os.listdir(directory_name)

    # Convert the list to bytes by 'dumps' function
    encoded_list = json.dumps(files_list).encode()

    # Sending the list
    print("[SERVER] Sending the list of files...")
    list_packet_size = len(encoded_list)
    list_chunk = 1024
    i = 0
    while list_packet_size > 0:
        if protocol == 'tcp':
            connection_socket.send(encoded_list[i:i + list_chunk])
        else:
            send_packet_udp(connection_socket, encoded_list[i:i + list_chunk], addr)
        i = i + list_chunk
        list_packet_size -= list_chunk

    print("[SERVER] Finish sending")

    # Update client that sending is finished
    if protocol == 'rudp':
        send_packet_udp(connection_socket, "0".encode(), addr)


# close the socket
def close(connection_socket):

    print("[SERVER] Close connection...")
    connection_socket.close()


def create_tcp_connection(addr):

    # create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a specific address and port
    sock.bind(addr)

    # Listen for incoming connections
    sock.listen(1)
    print('[Server] Server is listening...')

    # Accept incoming connections
    connection_socket, client_address = sock.accept()
    print(f'[Server] Accepted connection from {client_address[0]}')

    return connection_socket


def validation(connection_socket, packet, protocol, addr):

    # Receive username and password from client
    client_username = packet.split(" ")[0]
    client_password = packet.split(" ")[1]

    # Validation check
    if not (client_username == 'aj123' and client_password == '2023a'):
        if protocol == 'tcp':
            connection_socket.send("ERROR".encode())
        else:
            send_packet_udp(connection_socket, "ERROR".encode(), addr)
        print("[SERVER] Incorrect username or password! exit program...")
        sys.exit()
    else:
        print("[SERVER] Username and password are correct")
        if protocol == 'tcp':
            connection_socket.send("OK".encode())
        else:
            send_packet_udp(connection_socket, "OK".encode(), addr)


def choose_command(connection_socket, directory_name, protocol, addr):

    # Wait to receive client command
    if protocol == 'tcp':
        command = connection_socket.recv(512).decode()
    else:
        command = receive_packet_udp(connection_socket, addr).decode()

    if command == "upload":
        upload(connection_socket, directory_name, protocol, addr)
    elif command == "download":
        download(connection_socket, protocol, addr)
    elif command == "list":
        list_of_files(connection_socket, directory_name, protocol, addr)
    elif command == "close":
        close(connection_socket)
    # If the received command isn't valid, the client will fix it


def main():

    global seq_num

    # Create a directory that will contain all the server files
    directory_name = input("[SERVER] Enter directory path for all of server's files: ")
    if not os.path.exists(directory_name):
        os.makedirs(directory_name)

    # Set IP address and port number (port 30xxx - 3 last digit belong to jameel ID)
    client_ip_address = input("[SERVER] Enter client ip address: ")
    addr = (client_ip_address, 30775)

    # Create socket to get updated by client which protocol to implement
    rudp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind it - we want to send messages from 20xxx port (last 3 digits belong to amit ID)
    rudp_sock.bind((client_ip_address, 20373))

    # Receiving protocol decision from client
    protocol, address = rudp_sock.recvfrom(1024)
    protocol = protocol.decode()

    # Create TCP/RUDP connection, then receive username and password and check if valid, and finally execute client
    # command
    if protocol == 'tcp':
        connection_socket = create_tcp_connection(addr)

        packet = connection_socket.recv(512).decode()
        validation(connection_socket, packet, protocol, addr)

        choose_command(connection_socket, directory_name, protocol, addr)

    elif protocol == 'rudp':

        # We already have RUDP socket created and bind for us. Now we wait to receive SYN from client
        message, client_address = rudp_sock.recvfrom(BUFFER_SIZE)
        ack = int(message.decode().split("|")[0])

        # SYN received - sending SYN-ACK
        if ack == 0:
            ack_update = str(ack) + "|" + "SYN-ACK"
            rudp_sock.sendto(ack_update.encode(), addr)
            seq_num += 1
            print("[SERVER] Sending SYN-ACK...")
        else:
            print("[SERVER] Something went wrong, exit program...")
            sys.exit()

        details = receive_packet_udp(rudp_sock, addr).decode()

        validation(rudp_sock, details, protocol, addr)

        choose_command(rudp_sock, directory_name, protocol, addr)

    else:
        message = "You've typed a wrong protocol.."
        rudp_sock.sendto(message.encode(), addr)
        print("[SERVER] Wrong protocol, shutting down...")


if __name__ == "__main__":
    main()
