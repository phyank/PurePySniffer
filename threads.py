from definition import *
import threading,socket
from struct import *
from binascii import hexlify
from time import sleep

class capthread(threading.Thread):
    def __init__(self, myId, count, device):
        self.myId = myId
        self.count = count
        self.device = device

        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.device)
        threading.Thread.__init__(self)

    def read_proto_header(self, packet, protocol, iph_length):

        if protocol == 6:
            try:
                tcp_header = packet[iph_length:iph_length + 20]
                try:
                    tcph = unpack('!HHLLBBHHH', tcp_header)
                except:
                    tcph = unpack('!HHLLBBH', tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                ctrl_flags=tcph[5]
                window_size=tcph[6]
                try:
                    chksum=tcph[7]
                    urgent_pointer=tcph[8]
                except:
                    chksum=0
                    urgent_pointer=0

                tcph_length = doff_reserved >> 4

                h_size = iph_length + tcph_length * 4
                data_size = len(packet) - h_size

                # get data from the packet

                data = packet[h_size:]

                protocol_opt = (tcph, sequence, acknowledgement, tcph_length,ctrl_flags,window_size,chksum,urgent_pointer)
                return source_port, dest_port, protocol_opt, data
            except:
                print(tcp_header)
                return UNDEFINED,UNDEFINED,UNDEFINED,packet

        elif protocol == 17:
            try:
                udp_header = packet[iph_length:iph_length + 8]

                udph = unpack('!HHH2s', udp_header)

                source_port = udph[0]
                dest_port = udph[1]
                udp_length = udph[2]


                h_size = iph_length + 8

                data = packet[h_size:]

                protocol_opt = (udph)

                return source_port, dest_port, protocol_opt, data
            except:
                return UNDEFINED,UNDEFINED,UNDEFINED,packet
        elif protocol == 1:
            icmp_header = packet[iph_length:iph_length + 4]
            icmph = unpack('!BB2s', icmp_header)
            icmp_type = icmph[0]
            icmp_msg = icmph[1]
            icmp_chksum = icmph[2]
            data = packet[iph_length + 4:]
            protocol_opt = (icmp_type, icmp_msg, icmp_chksum)
            return -1, -1, protocol_opt, data
        else:
            return UNDEFINED, UNDEFINED, UNDEFINED, packet[iph_length:]



    def cap(self):

        s = self.s

        while True:
            try:
                i = infoqueue.get(block=False)
                if i[0] == self.myId:
                    if i[1] == REFRESH_THREAD:
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, i[2])
                        infoqueue.put((THREAD_REFRESHED_CONFIRM, self.myId))
                        print('Thread refreshed')
                    elif i[1] == DELETE_THREAD:
                        s.close()
                        break
                else:
                    infoqueue.put(i)
            except :
                pass

            packet = s.recvfrom(65565)


            try:
                i = infoqueue.get(block=False)
            except:
                i = [0]
            try:
                if i[0] == self.myId:
                    if i[1] == REFRESH_THREAD:
                        print(i)
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, i[2])
                        dataqueue.put((THREAD_REFRESHED_CONFIRM, self.myId))
                        print('Thread refreshed')
                        continue
                    elif i[1] == DELETE_THREAD:
                        s.close()
                        break
                elif i[0]:
                    infoqueue.put(i)
                packet = packet[0]
            except:
                print(i)
                continue

            ethneth = unpack("!6s6sH", packet[0:14])
            destination_mac = hexlify(ethneth[0])
            source_mac = hexlify(ethneth[1])
            eth_protocol = ethneth[2]
            eth_fcs=packet[-4:]



            # take first 20 characters for the ip header
            packet=packet[14:]
            packet=packet[:-4]


            if eth_protocol == 0x0800:

                try:
                    ip_header = packet[0:20]

                    iph = unpack('!BBHHHBB2s4s4s', ip_header)

                    version_ihl = iph[0]
                    version = version_ihl >> 4
                    ihl = version_ihl & 0xF
                except:
                    dataqueue.put((eth_protocol, source_mac, destination_mac, ETHERNET_FRAME_NOT_IP, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED,
                                   UNDEFINED, UNDEFINED, UNDEFINED, packet,UNDEFINED, eth_fcs))
                    continue

                if version not in[4,6]:
                    dataqueue.put((eth_protocol, source_mac, destination_mac, ETHERNET_FRAME_NOT_IP, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED,
                                   UNDEFINED, UNDEFINED, UNDEFINED, packet,UNDEFINED,eth_fcs))
                else:


                    iph_length = ihl * 4

                    typeofservice=iph[1]
                    totallength=iph[2]
                    identification=iph[3]
                    flagsandfo=iph[4]
                    flags=(flagsandfo & 0xe000)>>13
                    fragmentoffset=flagsandfo & 0x1fff
                    ttl = iph[5]
                    protocol = iph[6]
                    iph_chksum=iph[7]
                    s_addr = socket.inet_ntoa(iph[8])
                    d_addr = socket.inet_ntoa(iph[9])

                    source_port, dest_port, protocol_opt, data = self.read_proto_header(packet, protocol, iph_length)


                    dataqueue.put((eth_protocol,source_mac,destination_mac, version, ihl,
                                   typeofservice,totallength,identification,flags,fragmentoffset,
                                   ttl,protocol, s_addr, d_addr, source_port, dest_port,
                                   protocol_opt, data,iph_chksum,eth_fcs))
            elif eth_protocol==0x0806 or eth_protocol==0x8035:
                try:
                    data=packet[:28]
                    p=unpack('!HHBBH6s4s6s4s',data)
                    device=p[0]
                    upper_proto=p[1]
                    hlen=p[2]
                    plen=p[3]
                    code=p[4]
                    smac=hexlify(p[5])
                    sip=socket.inet_ntoa(p[6])
                    dmac=hexlify(p[7])
                    dip=socket.inet_ntoa(p[8])

                    dataqueue.put((eth_protocol,source_mac,destination_mac,ETHERNET_FRAME_NOT_IP,UNDEFINED\
                            ,UNDEFINED,UNDEFINED,UNDEFINED,UNDEFINED,UNDEFINED,UNDEFINED,UNDEFINED,UNDEFINED\
                            ,UNDEFINED,UNDEFINED,UNDEFINED,(device,upper_proto,hlen,plen,code,smac,sip,dmac,dip),packet,UNDEFINED,eth_fcs))
                except:
                    data = packet[:24]
                    p=unpack('!HHBBH6s4s6s',data)
                    device=p[0]
                    upper_proto=p[1]
                    hlen=p[2]
                    plen=p[3]
                    code=p[4]
                    smac=hexlify(p[5])
                    sip=socket.inet_ntoa(p[6])
                    dataqueue.put((eth_protocol, source_mac, destination_mac, ETHERNET_FRAME_NOT_IP, UNDEFINED
                                       , UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED,
                                   UNDEFINED
                                       , UNDEFINED, UNDEFINED, UNDEFINED,
                                   (device, upper_proto, hlen, plen, code, smac, sip, UNDEFINED, UNDEFINED), packet, UNDEFINED,
                                   eth_fcs))
    def run(self):
        dataqueue.put((THREAD_START_CONFIRM, self.myId))
        print('Thread' + str(self.myId) + ' start.')
        self.cap()
        dataqueue.put((THREAD_DELETE_CONFIRM, self.myId))
        print('Thread' + str(self.myId) + ' quit.')


class refreshthread(threading.Thread):
    def __init__(self, myId, count, pcap,fliter,sl):
        self.myId = myId
        self.count = count
        self.mutex = mutex
        self.pcap = pcap
        self.fliter=fliter
        self.counter = -1
        self.sl=sl
        threading.Thread.__init__(self)

    def run(self):
        while True:
            if self.pcap.quit:
                break
            try:
                data = dataqueue.get(block=False)
                if data[0] == THREAD_DELETE_CONFIRM:
                    print('Thread' + str(data[1]) + ' quit confirmed')
                    self.pcap.threads.pop(data[1])
                    if not self.pcap.threads:
                        self.pcap.newthread=True
                elif data[0] == THREAD_REFRESHED_CONFIRM:
                    print('Thread' + str(data[1]) + ' refreshed confirmed')
                elif data[0] == THREAD_START_CONFIRM:
                    print('Thread' + str(data[1]) + ' started confirmed')
                    self.pcap.newthread=False
                else:
                    if self.pcap.start:
                        self.pcap.pcap.append(data)
                        flitered=self.fliter.fliter(data)
                        if flitered:
                            self.pcap.pcap2show.append(flitered)
                            self.sl.list_insert(data)
                            self.counter += 1
                        else:
                            pass
            except:
                sleep(0.1)

        print('Refresh Thread Quit.')
