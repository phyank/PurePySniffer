from io import StringIO
import re,queue,threading

MAIN_TITLE='PySniffer'

ALL_PROTO_NUM=[1,6,17]
#from if_ether.h
ETH_P_ALL=0x0003
ETH_P_IP=0x0800

#pcap format:(eth_protocol,source_mac,destination_mac, version, ihl,
#             typeofservice,totallength,identification,flags,fragmentoffset,
#             ttl,protocol, s_addr, d_addr, source_port, dest_port,
#             protocol_opt, data,eth_fcs)

PCAP_ETH_PROTO=0
PCAP_SRC_MAC=1
PCAP_DST_MAC=2
PCAP_VERSION=3
PCAP_IHL=4
PCAP_TYPE_OF_SERVICE=5
PCAP_TOTAL_LEN=6
PCAP_ID=7
PCAP_FLAGS=8
PCAP_F_OFFSET=9
PCAP_TTL=10
PCAP_PROTO=11
PCAP_SRC_IP=12
PCAP_DST_IP=13
PCAP_SRC_PORT=14
PCAP_DST_PORT=15
PCAP_PROTO_OPT=16
PCAP_DATA=17
PCAP_IP_H_CHKSUM=18
PCAP_ETH_FCS=19


PROTO_ICMP=1
PROTO_TCP=6
PROTO_UDP=17

FIRST_START=0
LOAD_FILE=1

FEEDBACK = -5

THREAD_START_CONFIRM = -6

DELETE_THREAD = -1
REFRESH_THREAD = -2

THREAD_DELETE_CONFIRM = -3
THREAD_REFRESHED_CONFIRM = -4

ETHERNET_FRAME_NOT_IP=3
UNDEFINED=-1

ICMP_TYPE=1
ICMP_CODE=2
ICMP_CHKSUM=3

mutex = threading.Lock()
dataqueue = queue.Queue()
infoqueue = queue.Queue()

def mac_formater(a):
 a=a.decode('ascii')
 return "%s:%s:%s:%s:%s:%s" % (a[0:2], a[2:4], a[4:6], a[6:8], a[8:10] , a[10:12])

def parseproto(proto):
    if proto == 6:
        return 'TCP'
    elif proto == 17:
        return 'UDP'
    elif proto == 1:
        return 'ICMP'
    else:
        return 'UNKNOWN'

def interpret_icmp(msg,code=0,type=ICMP_TYPE):
    if type==ICMP_TYPE:
        if msg==0:
            return "0 Echo Reply"
        elif msg==3:
            return "3 Destination Unreachable"
        elif msg==4:
            return "4 Source Quench"
        elif msg==5:
            return "5 Redirect"
        elif msg==8:
            return "8 Echo Request"
        elif msg==9:
            return "9 Router Advertisement"
        elif msg==10:
            return "10 Router Solicitation"
        elif msg==11:
            return "11 Time Exceeded"
        elif msg==17:
            return "17 Address Mask Request"
        elif msg==18:
            return "18 Address Mask Reply"
        else:
            return str(msg)+" Unknown"
    else:
        return str(msg)

def interpret_data_protocol(data):
    out=''
    data=data.decode('ascii','ignore')
    if re.match('^HTTP',data):
        out+='Content: HTTP Response'
        io=StringIO(data)
        buff=io.readline()
        status=re.findall('[0-9]{3}',buff)[0]
        info=buff[(buff.find(status)):][4:]
        info=info[:-1]
        out+='\n Status:'+status+' '+info+'\n '
    elif re.match('^(GET)|(POST)|(PUT)|(HEAD)|(Delete)|(Options)',data):
        out+='Content: HTTP Request '+(re.match('^[A-Za-z]+ ',data)).group()

    return out


class Database:
    def __init__(self):
        self.pcap = []
        self.pcap2show=[]
        self.current = UNDEFINED
        self.counter = UNDEFINED
        self.protocol_num = []
        self.new_proto_no = []
        self.threads = {}
        #self.socknum = 0
        self.start = False
        self.newthread=True
        self.quit = False
        self.device = 0
        self.deviceip={}
        self.bind2ip=''

        self.ip=True
        self.arp=True
        self.RARPrarp=True

    def append(self, d):
        self.pcap.append(d)
        self.counter += 1

    def clean(self):
        self.pcap = []
        self.pcap2show=[]
        self.current = UNDEFINED
        self.counter = UNDEFINED
        self.protocol_num = []
        self.new_proto_no = []
        self.threads = {}
        #self.socknum = 0
        self.start = False
        self.quit = False
        self.device = 0
        self.deviceip={}
        self.bind2ip=''

class fliter:
    def __init__(self):
        self.proto=[]
        self.src_mac=[]
        self.des_mac=[]
        self.src_ip=[]
        self.des_ip=[]
        self.src_port=[]
        self.des_port=[]
        self.bind=0

    def reinit(self):
        self.proto=[]
        self.src_mac=[]
        self.des_mac=[]
        self.src_ip=[]
        self.des_ip=[]
        self.src_port=[]
        self.des_port=[]
        self.bind=0

        self.ip=True
        self.arp=True
        self.rarp=True

    def add_proto(self,codes):
        for code in codes:
            self.proto.append(code)

    def delete_proto(self,codes):
        for code in codes:
            self.proto.remove(code)

    def fliter(self,data):
        if data[PCAP_ETH_PROTO]==0x0800:
            if not self.ip:
                return
            else:
                if not self.bind:
                    pass
                else:
                    if data[PCAP_SRC_IP]==self.bind:
                        pass
                    else:
                        if data[PCAP_DST_IP]==self.bind:
                            pass
                        else:
                            return
                if data[PCAP_PROTO] in self.proto:
                    if self.src_mac:
                        if data[PCAP_SRC_MAC] not in self.src_mac:
                            return
                    if self.des_mac:
                        if data[PCAP_DST_MAC] not in self.des_mac:
                            return
                    if self.src_ip:
                        if data[PCAP_SRC_IP] not in self.src_ip:
                            return
                    if self.des_ip:
                        if data[PCAP_DST_IP] not in self.des_ip:
                            return
                    if self.src_port:
                        if data[PCAP_SRC_PORT] not in self.src_port:
                            return
                    if self.des_port:
                        if data[PCAP_DST_PORT] not in self.des_port:
                            return
                    return data
                else:
                    return
        elif data[PCAP_ETH_PROTO]==0x0806:
            if not self.arp:
                return
            else:
                return data
        elif data[PCAP_ETH_PROTO]==0x8035:
            if not self.rarp:
                return
            else:
                return data