import os
# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
seq_num = 0

def func1():
   global seq_num
   seq_num = 1
   temp = seq_num
   seq_num += 1
   print(temp) # 1 - good, 2 - bad

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    func1()


# def send_packet_udp(sock, data, addr):
#    global seq_num
#
#    # packet looks like: seq_num | ID | data
#    packet = (str(seq_num) + "|" + str(generate_packet_id()) + "|").encode()
#    packet += data  # assume data is encode already
#
#    sock.sendto(packet, addr)
#    seq_num += 1
#
#    # Saving packet sending time
#    packet_time = time.time()
#
#    # Client stop until ACK from server received
#    receive_ack(sock, packet, addr, packet_time)
#
#
# def receive_ack(sock, data, addr, packet_time):
#    global congestion_window, threshold
#    packet_content = data.split("|".encode())[2]  # maybe bug here for photos
#
#    # Prepare to get an ACK from client
#    ack_packet, server_address = sock.recvfrom(1024)
#    ack = ack_packet.decode()
#
#    # Extract seq_num to check reliability
#    ack_seq_num = int(ack.split("|")[0])
#
#    # If server received the correct ack, everything is great
#    if ack_seq_num == seq_num - 1:
#       print("line 62: check")
#       # Works good, can increase the window
#       congestion_window += 1
#       if congestion_window > threshold:
#          congestion_window = threshold
#       if congestion_window > MAX_WINDOW_SIZE:
#          congestion_window = MAX_WINDOW_SIZE
#    # Received ack is smaller than current ack - point on packet lost, so we send the last packet again
#    else:
#
#       send_packet_udp(sock, packet_content, addr)
#
#    # If too long time passed till packet sent, server send it again
#    if time.time() - packet_time > TIMEOUT:
#       send_packet_udp(sock, packet_content, addr)
#       # Maybe this happened because overload of job, so we decrease the job window
#       congestion_window = 1
#       threshold /= 2
#       if threshold < 1:
#          threshold = 1
#
#
# def receive_packet_udp(sock, rudp_addr):
#    global last_packet_received, window_size, seq_num
#
#    # Receive packet - check seq_number for reliability
#    data, client_address = sock.recvfrom(BUFFER_SIZE + 8)
#    packet_content = data.split("|".encode())[2]
#    ack = int((data.split("|".encode())[0]).decode())
#    print(ack)  # ack == 1
#    # Seq_num is good, can increase job window
#    # if ack == last_packet_received + 1:
#    if ack == seq_num:  # seq_num == 0, ack == 1
#       last_packet_received += 1
#       window_size += 1
#       if window_size > MAX_WINDOW_SIZE:
#          window_size = MAX_WINDOW_SIZE
#       # Received packet, update client with ack
#       ack_update = str(ack) + "|" + str(generate_packet_id()) + "|" + "ACK"
#       sock.sendto(ack_update.encode(), rudp_addr)
#
#    # Seq_num isn't good - there is packet lost from client side, Don't send ACK, and it will force the client to
#    # send packet again
#    else:
#       print("[SERVER] Packet lost... waiting to receive lost packets")
#
#    seq_num += 1
#
#    return packet_content

# See PyCharm help at https://www.jetbrains.com/help/pycharm/

# def handle_dhcp_packet(packet):
#     if DHCP in packet and packet[DHCP].options[0][1] == 2:
#         print("DHCP Offer received")
#         dhcp_request = Ether(src=get_if_hwaddr(conf.iface), dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0', dst='255.255.255.255')/UDP(sport=68, dport=67)/BOOTP(op=1, xid=packet[BOOTP].xid, chaddr=packet[BOOTP].chaddr)/DHCP(options=[('message-type', 'request'), ('requested_addr', packet[BOOTP].yiaddr), ('server_id', '192.168.1.1'), 'end'])
#         sendp(dhcp_request, iface=conf.iface)
#     elif DHCP in packet and packet[DHCP].options[0][1] == 5:
#         print("DHCP Ack received")
#         print("Assigned IP address: " + packet[BOOTP].yiaddr)
#         return
#
#
# def main():
#     sniff(filter="udp and (port 67 or port 68)", prn=handle_dhcp_packet)
#
#
# if __name__ == "__main__":
#     main()
#
#
# # Set DNS UDP socket
# dnssocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# print("[CLIENT] socket created successfully")
#
# addr = ('127.0.0.1', 1234)
#
# c = "Y"
# while c.upper() == "Y":
#
#     req_domain = input("[CLIENT] Enter domain name for which the IP is needed: ")
#
#     send = dnssocket.sendto(req_domain.encode(), addr)
#
#     data, address = dnssocket.recvfrom(1024)
#
#     reply_ip = data.decode()
#
#     print(f"[CLIENT] The IP for the domain name {req_domain} : {reply_ip}")
#
#     c = input("[CLIENT] Continue? Y/N ")
#
# dnssocket.close()
#
#
# if __name__ == "__main__":
#     main()



# USER: This command is used to specify the username to log in to the FTP server.
#
# PASS: This command is used to specify the password for the username specified with the USER command.
#
# LIST: This command is used to retrieve a list of files in the current directory on the FTP server.
#
# CWD: This command is used to change the current working directory on the FTP server.
#
# CDUP: This command is used to move the current working directory up one level on the FTP server.
#
# RETR: This command is used to retrieve a file from the FTP server and transfer it to the client.
#
# STOR: This command is used to transfer a file from the client to the FTP server.
#
# MKD: This command is used to create a new directory on the FTP server.
#
# RMD: This command is used to delete a directory on the FTP server.
#
# DELE: This command is used to delete a file on the FTP server.
#
# RNFR: This command is used to specify the file to be renamed on the FTP server.
#
# RNTO: This command is used to specify the new name for the file specified with the RNFR command on the FTP server.
#
# QUIT: This command is used to terminate the FTP session.

# Probably there are only 3 commands in FTP: upload, download, list
#
# def handle_user_command(connection, command):
#     # Extract the username from the command
#     username = command.split()[1]
#
#     # Check if the username is valid
#     if username == "valid_username":
#         # If the username is valid, send a response code of 331 (user name okay, need password)
#         connection.sendall("331 User name okay, need password.\r\n".encode())
#     else:
#         # If the username is not valid, send a response code of 530 (not logged in)
#         connection.sendall("530 Not logged in.\r\n".encode())
#
#
# def handle_pass_command(connection, command):
#     # Extract the password from the command
#     password = command.split()[2] # change to struct.unpack
#
#     # Check if the password is valid
#     if password == "valid_password" and connection.valid_username:
#         # If the password is valid and a valid username has been provided, send a response code of 230 (user logged in)
#         connection.sendall("230 User logged in.\r\n".encode())
#     else:
#         # If the password is not valid or a valid username has not been provided, send a response code of 530 (not logged in)
#         connection.sendall("530 Not logged in.\r\n".encode())
#
#
# def handle_list_command(connection, command):
#     # Check if the user is logged in
#     if not connection.valid_username:
#         connection.sendall("530 Not logged in.\r\n".encode())
#         return
#
#     # Get the current directory
#     current_dir = os.getcwd()
#
#     # Get a list of files in the current directory
#     file_list = os.listdir(current_dir)
#
#     # Send the file list to the client
#     response = " ".join(file_list)
#     connection.sendall(f"150 Here comes the directory listing.\r\n{response}\r\n226 Directory send OK.\r\n".encode())
#
#
# def handle_cwd_command(connection, command):
#     # Check if the user is logged in
#     if not connection.valid_username:
#         connection.sendall("530 Not logged in.\r\n".encode())
#         return
#
#     # Get the directory from the command
#     directory = command[4:].strip()
#
#     # Check if the directory exists
#     if not os.path.isdir(directory):
#         connection.sendall("550 Directory not found.\r\n".encode())
#         return
#
#     # Change the current directory
#     os.chdir(directory)
#
#     # Send a response code of 250 (Directory changed)
#     connection.sendall("250 Directory changed.\r\n".encode())
#
#
# def handle_cdup_command(connection, command):
#     # Check if the user is logged in
#     if not connection.valid_username:
#         connection.sendall("530 Not logged in.\r\n".encode())
#         return
#
#     # Move up one directory level
#     os.chdir("..")
#
#     # Send a response code of 250 (Directory changed)
#     connection.sendall("250 Directory changed.\r\n".encode())
#
# # Download command:
# def handle_retr_command(connection, command):
#     # Check if the user is logged in
#     if not connection.valid_username:
#         connection.sendall("530 Not logged in.\r\n".encode())
#         return
#
#     # Get the filename from the command
#     filename = command[5:].strip()
#
#     # Check if the file exists
#     if not os.path.isfile(filename):
#         connection.sendall("550 File not found.\r\n".encode())
#         return
#
#     # Send a response code of 150 (Opening data connection)
#     connection.sendall("150 Opening data connection.\r\n".encode())
#
#     # Open the file in binary mode
#     with open(filename, "rb") as file:
#         # Send the file data to the client
#         while True:
#             data = file.read(1024)
#             if not data:
#                 break
#             connection.data_connection.sendall(data)
#
#     # Close the data connection
#     connection.close_data_connection()
#
#     # Send a response code of 226 (Closing data connection)
#     connection.sendall("226 Transfer complete.\r\n".encode())
#
# # Upload command
# def handle_stor_command(connection, command):
#     # Check if the user is logged in
#     if not connection.valid_username:
#         connection.sendall("530 Not logged in.\r\n".encode())
#         return
#
#     # Get the filename from the command
#     filename = command[5:].strip()
#
#     # Check if the file already exists
#     if os.path.isfile(filename):
#         connection.sendall("550 File already exists.\r\n".encode())
#         return
#
#     # Send a response code of 150 (Opening data connection)
#     connection.sendall("150 Opening data connection.\r\n".encode())
#
#     # Open the file in binary mode for writing
#     with open(filename, "wb") as file:
#         # Receive the file data from the client
#         while True:
#             data = connection.data_connection.recv(1024)
#             if not data:
#                 break
#             file.write(data)
#
#     # Close the data connection
#     connection.close_data_connection()
#
#     # Send a response code of 226 (Closing data connection)
#     connection.sendall("226 Transfer complete.\r\n".encode())
#
# # help func to upload function - create a directory
# def handle_mkd_command(connection, command):
#     # Check if the user is logged in
#     if not connection.valid_username:
#         connection.sendall("530 Not logged in.\r\n".encode())
#         return
#
#     # Get the directory name from the command
#     directory = command[4:].strip()
#
#     # Create the directory if it does not already exist
#     if not os.path.exists(directory):
#         os.makedirs(directory)
#         connection.sendall("257 Directory created.\r\n".encode())
#     else:
#         connection.sendall("550 Directory already exists.\r\n".encode())

# def handle_rmd_command(connection, command):
#     # Check if the user is logged in
#     if not connection.valid_username:
#         connection.sendall("530 Not logged in.\r\n".encode())
#         return
#
#     # Get the directory name from the command
#     directory = command[4:].strip()
#
#     # Delete the directory if it exists
#     if os.path.exists(directory) and os.path.isdir(directory):
#         os.rmdir(directory)
#         connection.sendall("250 Directory deleted.\r\n".encode())
#     else:
#         connection.sendall("550 Directory not found.\r\n".encode())

#
# def handle_rnfr_command(connection, command):
#     # Check if the user is logged in
#     if not connection.valid_username:
#         connection.sendall("530 Not logged in.\r\n".encode())
#         return
#
#     # Get the file name from the command
#     file_name = command[5:].strip()
#
#     # Check if the file exists on the server
#     if os.path.exists(file_name):
#         # Store the old file name for use with the RNTO command
#         connection.rnfr_filename = file_name
#         connection.sendall("350 Ready for RNTO.\r\n".encode())
#     else:
#         connection.sendall("550 File not found.\r\n".encode())

#
# def handle_rnto_command(connection, command):
#     # Check if the user is logged in
#     if not connection.valid_username:
#         connection.sendall("530 Not logged in.\r\n".encode())
#         return
#
#     # Get the new file name from the command
#     new_file_name = command[5:].strip()
#
#     # Check if an RNFR command has been issued previously
#     if not connection.rnfr_filename:
#         connection.sendall("503 Bad sequence of commands.\r\n".encode())
#         return
#
#     # Rename the file on the server
#     os.rename(connection.rnfr_filename, new_file_name)
#
#     connection.sendall("250 File renamed successfully.\r\n".encode())
#     connection.rnfr_filename = None

# Close socket
# def handle_quit_command(connection, command):
#     connection.sendall("221 Goodbye.\r\n".encode())
#     connection.close()
#
# # set the receiver's IP address and port number
# receiver_ip = "127.0.0.1"
# receiver_port = 12345
#
# # set the local file path
# # Amit - what is the purpose in that?
# local_file_path = "C:\\Users\\jamee\\OneDrive\\שולחן העבודה\\TekFTP.txt"
#
# # open the local file in binary mode
# Amit - what is the purpose in that?
# with open(local_file_path, "rb") as f:
# when to finish 'with' statement?
# create a TCP socket and connect to the receiver
# Yaakov - sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Yaakov - sock.connect((receiver_ip, receiver_port))
