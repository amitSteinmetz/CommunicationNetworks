from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether

# Define the IP address range for the pool
ip_pool = ['192.168.0.1', '192.168.0.2', '192.168.0.3', '192.168.0.4', '192.168.0.5', '192.168.0.6', '192.168.0.7', '192.168.0.8', '192.168.0.9']


# Define a function to assign IP addresses from the pool
def assign_ip():
    if len(ip_pool) > 0:
        ip_address = ip_pool.pop(0)  # Assign the first available IP address from the pool
        return str(ip_address)
    else:
        return None


def handle_dhcp_packet(packet):
    if DHCP in packet and packet[DHCP].options[0][1] == 1:
        print("DHCP Discover received")
        dhcp_offer = Ether(src=get_if_hwaddr(conf.iface), dst='ff:ff:ff:ff:ff:ff')/\
                     IP(src='192.168.1.1', dst='192.168.1.100')/\
                     UDP(sport=67, dport=68)/\
                     BOOTP(op=2, yiaddr=assign_ip(), siaddr='192.168.1.1', giaddr='192.168.1.1', xid=packet[BOOTP].xid)/\
                     DHCP(options=[('message-type', 'offer'), ('server_id', '192.168.1.1'), ('subnet_mask', '255.255.255.0'), 'end'])
        sendp(dhcp_offer, iface=conf.iface)
    elif DHCP in packet and packet[DHCP].options[0][1] == 3:
        print("DHCP Request received")
        dhcp_ack = Ether(src=get_if_hwaddr(conf.iface), dst='ff:ff:ff:ff:ff:ff')/ \
                   IP(src='192.168.1.1', dst='192.168.1.100') / \
                   UDP(sport=67, dport=68)/\
                   BOOTP(op=2, yiaddr=assign_ip(), siaddr='192.168.1.1', giaddr='192.168.1.1', xid=packet[BOOTP].xid)/\
                   DHCP(options=[('message-type', 'ack'), ('server_id', '192.168.1.1'), ('subnet_mask', '255.255.255.0'), 'end'])
        sendp(dhcp_ack, iface=conf.iface)


def main():
    sniff(filter="udp and (port 67 or port 68)", prn=handle_dhcp_packet)


if __name__ == "__main__":
    main()
