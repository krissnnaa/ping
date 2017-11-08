import socket
import time
import struct
import sys
import random
import select
import re

icmp_echo_type = 8
icmp_echo_code = socket.getprotobyname('icmp')

IP_REGEX = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')


def calculate_check_sum(message):
    """
    To compute checksum of the packet
    :param message: message of packet
    :return: checksum value
    """
    s=0;
    for i in range(0,len(message),2):
        a=ord(message[i])+(ord(message[i+1])<<8)
        b=s+a
        s=(b & 0xffff) +(b>>16)
    r= ~s & 0xffff
    return (r)


def create_icmp_packet(pkt_id):
    """
    To generate icmp echo packet
    :param id:
    :return:
    """
    seq_num = 1
    checksum = 0
    data = 'a' *224
    header = struct.pack('bbHHh', icmp_echo_type, icmp_echo_code, checksum, pkt_id, seq_num)
    message = header + data
    checksum = calculate_check_sum(message)
    header = struct.pack('bbHHh', icmp_echo_type, icmp_echo_code, checksum, pkt_id, seq_num)
    message = header + data
    return message


def send_echo_request(dst, timeout):
    """

    :param dst: destination address
    :param timeout: gives delay of icmp packet
    :return: icmp packet delay time
    """
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_echo_code)
    packet_id = int(random.randint(1,1000) % (sys.getsizeof(int) - 1))
    new_packet = create_icmp_packet(packet_id)
    while new_packet:
        pkt_sent = icmp_socket.sendto(new_packet, (dst, 100))
        new_packet = new_packet[pkt_sent:]

    pkt_delay = icmp_echo_receive(icmp_socket, packet_id, time.time(), timeout)
    icmp_socket.close()
    return pkt_delay


def icmp_echo_receive(icmp_socket, pkt_id, t, timeout):
    """
    Receive echo message
    :param icmp_socket: socket
    :param pkt_id: packet id
    :param t: sent time
    :param timeout: time out
    :return:
    """
    while True:
        select_pkt = select.select([icmp_socket],[],[],timeout)
        if not select_pkt[0]:
            return None
        time_to_rec = time.time()
        rec_pkt, addr = icmp_socket.recvfrom(1024)
        icmp_header = rec_pkt[20:28]
        type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
        if pkt_id == p_id:
            return time_to_rec - t
        timeout = timeout - (time_to_rec - t)
        if timeout <= 0:
            return None


def icmp_verbose(dst):
    timeout = 2
    c = 10
    m = IP_REGEX.match(dst)
    if not m:
        dst = socket.gethostbyname(dst)
    print('pinging ' + dst)

    for i in range(c):
        time_delay = send_echo_request(dst, timeout)
        if not time_delay:
            print('Timeout and destination is Unrechable')
        else:
            time_delay = 1000.0 * time_delay
            time.sleep(2)
            print(' 64 bytes from {}: icmp_seq= {} time= {} ms ' .format(dst,i+1,time_delay))


if __name__ == '__main__':
    icmp_verbose('127.0.0.1')
    icmp_verbose('www.google.com')

