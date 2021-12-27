import sys
import socket
from select import select
import struct
from time import time

# checksum from rfc1071, украдено у Андрея)
def calc_checksum(header):
    checksum = 0
    overflow = 0
    for i in range(0, len(header), 2):
        word = header[i] + (header[i + 1] << 8)
        checksum = checksum + word
        overflow = checksum >> 16
        while overflow > 0:
            checksum = checksum & 0xFFFF
            checksum = checksum + overflow
            overflow = checksum >> 16
    overflow = checksum >> 16
    while overflow > 0:
        checksum = checksum & 0xFFFF
        checksum = checksum + overflow
        overflow = checksum >> 16

    checksum = ~checksum
    checksum = checksum & 0xFFFF

    return checksum

timeout = 1  # в секундах(!!)
max_ttl = 30

def ping(ttl, destination_ip, socket_):

    checksum1, checksum2, checksum3 = 0, 0, 0

    header1 = struct.pack("bbHHh", 8, 0, checksum1,  0, 0)
    #header2 = struct.pack("bbHHh", 8, 0, checksum2, 0, 0)
    #header3 = struct.pack("bbHHh", 8, 0, checksum3, 0, 0)

    checksum1 = calc_checksum(header1)
    #checksum2 = calc_checksum(header2)
    #checksum3 = calc_checksum(header3)

    header1 = struct.pack("bbHHh", 8, 0, checksum1, 0, 0)

    socket_.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    #socket_.bind(('destination_ip', 65432))
    socket_.sendto(header1, (destination_ip, 65432))

    time1 = time()
    socket_response, _, _ = select([socket_], [], [], timeout)
    if socket_response == []:
        print('{}\t{} ms\t*\tПревышен интервал для ожидания запроса'.
              format(ttl, int((time() - time1) * 1000)))
        return False

    _, (ip, port) = socket_.recvfrom(128)

    #host_ = socket.gethostbyaddr(ip)
    #if len(host_) > 0:
    #    hostname = host_[0]
    print('{}\t{} ms\t{}'.format(ttl, int((time() - time1) * 1000), ip))

    if destination_ip == ip:
        return True
    else:
        return False

def main():
    if (len(sys.argv) != 2):
        sys.exit("Bad amount of parameters! Try again.")
    else:
        dest_name = sys.argv[1] # name
        dest_ip = socket.gethostbyname(dest_name) #ip
        print(dest_ip)
        print("trace route to {} with max_ttl {}".format(dest_name, max_ttl))
        ttl = 1
        icmp_protocol = socket.getprotobyname("icmp")

        while(ttl <= max_ttl):
            with socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=icmp_protocol) as socket_:
                if (ping(ttl, dest_ip, socket_)):
                    break
            ttl += 1

        sys.exit()

if __name__ == "__main__":
    main()
