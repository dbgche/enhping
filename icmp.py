#!/usr/bin/env python3
import os, sys, socket, struct, select, time, logging, logging.handlers, signal, traceback, string, argparse
from datetime import datetime

' an IP structure module '
__author__ = 'Tim Chen'

__ENH_CLASS_VERSION__ = '1.0.1'
__ENH_IS_WIN32__ = ("win32"==sys.platform)
__ENH_CLASS_NAME__ = "ENH_PING"
__ENH_MAX_LOGFILE_SIZE__ = 8 * 1024 * 1024
__ENH_DEF_LOGFILE_COUNT__ = 8
__ENH_DEF_LOGLEVEL__ = logging.INFO
__ENH_MIN_PAYLOADS_LENGTH__ = 36
__ENH_DEF_PAYLOADS_LENGTH__ = 64
__ENH_DATETIME_FORMAT__ = '[%Y-%m-%dT%H:%M:%S.%f%zZ] '
__ENH_MAX_RECEIVE_BUFFER__ = 8192

__ENH_DESCRIPTION__ = 'A python ping/traceroute(not implement) utils covers TCP, UDP, ICMP tool test. Current Version:' + __ENH_CLASS_VERSION__
__ENH_EPILOG__ = """Example
    ICMP:   enhping.py 192.168.1.1
    UDP:    not implement
    TCP:    not implement
    """
def exception_string(e):
    return (e.args if e.args else tuple()) + ((traceback.format_exc()),)

class _ENH_BASE():
    @staticmethod
    def version():
        return __ENH_CLASS_NAME__ + ' ' + __ENH_CLASS_VERSION__

    def current_time(self,format_time=__ENH_DATETIME_FORMAT__):
        return datetime.fromtimestamp(time.time()).strftime(format_time)

    def default_timer(self):
        #__ENH_DEF_TIMER__ = time.perf_counter if __ENH_IS_WIN32__ else time.time
        if __ENH_IS_WIN32__:
            return time.perf_counter()
        return time.time()

class _IP_PACKET:
    def __init__(self, ver):
        self.ver=ver

    @staticmethod
    def chksum(data):
        s = 0
        n = len(data) % 2
        for i in range(0, len(data)-n, 2):
            s+= data[i] + (data[i+1] << 8)
        if n:
            s+= data[i+1]
        while (s >> 16):
            s = (s & 0xFFFF) + (s >> 16)
        s = ~s & 0xffff
        return s
    
class _IPV4_PACKET(_IP_PACKET):
    _IP_VERSION = 4
    _IP_DEF_TTL = 50
    _IP_HDR_MIN = 20
    _IP_MAX_TTL = 255

    def __init__(self,
                 ihl = 5,
                 tos = 0x00,
                 length = 20,
                 id = 0,
                 flags = 0,
                 offset = 0,
                 ttl = _IP_DEF_TTL,
                 protocol = 0,
                 checksum = 0,
                 src = '127.0.0.1',
                 dst = '127.0.0.1',
                 options = '',
                 payloads = ''):
        super().__init__(self._IP_VERSION)
        self.ihl = self._IP_HDR_MIN if (ihl * 4 < self._IP_HDR_MIN) else ihl        # this implement punts on options
        self.tos = tos
        self.len = length + len(payloads)      # begin with header length
        self.id = id
        self.flags = flags
        self.offset = offset
        self.ttl = self._IP_DEF_TTL if ttl>self._IP_MAX_TTL else ttl
        self.protocol = protocol
        self.checksum = checksum    #header checksum
        self.bchksum = False
        self.src = src
        self.dst = dst
        self.list = [
            self.ihl,
            self.ver,
            self.tos,
            self.len,
            self.id,
            self.flags,
            self.offset,
            self.ttl,
            self.protocol,
            self.src,
            self.dst]
        self.options = options
        self.payloads = payloads
        self.raw_packet = ''

#
# https://tools.ietf.org/html/rfc791
#
#   format:
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   BBH |Version|  IHL  |Type of Service|          Total Length         |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   HH  |         Identification        |Flags|      Fragment Offset    |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   BBH |  Time to Live |    Protocol   |         Header Checksum       |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   4s  |                       Source Address                          |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   4s  |                    Destination Address                        |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                    Options                    |    Padding    |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#

    def pack(self,bchksum=False):
        __ver_ihl = (self.ver << 4) + self.ihl
        __flags_offset = (self.flags << 13) + self.offset
        __src = socket.inet_aton(self.src)
        __dst = socket.inet_aton(self.dst)
        __ip_header = struct.pack("!BBHHHBBH4s4s",
                    __ver_ihl,
                    self.tos,
                    self.len,
                    self.id,
                    __flags_offset,
                    self.ttl,
                    self.protocol,
                    self.checksum if self.bchksum else 0,
                    __src,
                    __dst)
        if ((not self.bchksum) and bchksum):
            self.checksum = socket.htons(_IPV4_PACKET.chksum(__ip_header))
            self.bchksum = bchksum
            __ip_header = struct.pack("!BBHHHBBH4s4s",
                        __ver_ihl,
                        self.tos,
                        self.len,
                        self.id,
                        __flags_offset,
                        self.ttl,
                        self.protocol,
                        self.checksum,
                        __src,
                        __dst)  
        return __ip_header

# https://tools.ietf.org/html/rfc791
#
#   format:
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   BBH |Version|  IHL  |Type of Service|          Total Length         |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   HH  |         Identification        |Flags|      Fragment Offset    |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   BBH |  Time to Live |    Protocol   |         Header Checksum       |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   4s  |                       Source Address                          |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   4s  |                    Destination Address                        |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                    Options                    |    Padding    |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
    @staticmethod
    def unpack(packet):
        try:
            ver = packet[0] >> 4
            __ip4_ihl = (packet[0]& 0xf) * 4
            if(not 4==ver):
                raise ValueError('not an ipv4 packet')
            __ip4_header = struct.unpack("!BBHHHBBH4s4s", packet[:__ip4_ihl])
            __ip4 = _IPV4_PACKET( 
                ihl = __ip4_ihl,
                tos = __ip4_header[1],
                length = __ip4_header[2],
                id = __ip4_header[3],
                flags = __ip4_header[4] >> 13,
                offset = __ip4_header[4] & 0x1FFF,
                ttl = __ip4_header[5],
                protocol = __ip4_header[6],
                checksum = hex(__ip4_header[7]),
                src = socket.inet_ntoa(__ip4_header[8]),
                dst = socket.inet_ntoa(__ip4_header[9]),
                payloads = packet[__ip4_ihl:]
                )
            __ip4.raw_packet = packet
            return __ip4
        except Exception as e:
            raise exception_string(e)
            #raise
        return None

class _ICMPV4_PACKET(_IP_PACKET):
    _IP_VERSION = 4

    def __init__(self,
                 icmp_type = 8,
                 icmp_code = 0,
                 checksum = 0,
                 id = 0,
                 seq = 1,
                 payloads = None):
        super().__init__(self._IP_VERSION)
        self.icmp_type=icmp_type
        self.icmp_code=icmp_code
        self.checksum=checksum
        self.bchksum = False
        self.id=id
        self.seq=seq
        self.payloads=payloads
        self.list = [
            self.icmp_type,
            self.icmp_code,
            self.checksum,
            self.id,
            self.seq]
            

#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     Type(8)   |     Code(0)   |          Checksum             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           Identifier          |        Sequence Number        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                             Payload                           |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     
    def pack(self,bchksum=True):
        __icmp_header = struct.pack("!bbHHh",
                    self.icmp_type,
                    self.icmp_code,
                    self.checksum if self.bchksum else 0,
                    self.id,
                    self.seq)
        if ((not self.bchksum) and bchksum):
            self.checksum = socket.htons(_ICMPV4_PACKET.chksum(__icmp_header + self.payloads))
            #self.checksum = socket.htons(self.chksum(__icmp_header))
            self.bchksum = bchksum
            __icmp_header = struct.pack("!bbHHh",
                    self.icmp_type,
                    self.icmp_code,
                    self.checksum,
                    self.id,
                    self.seq)
        return __icmp_header + self.payloads
    
    @staticmethod
    def unpack(packet):
        try:
            __icmp_header = struct.unpack("!bbHHh", packet[:8])
            icmpp = _ICMPV4_PACKET(__icmp_header[0],__icmp_header[1],hex(__icmp_header[2]),__icmp_header[3],__icmp_header[4],packet[8:])
            icmpp.raw_packet = packet
            return icmpp
        except Exception as e:
            # __ENH_DEBUG_LOG__("Exception occurred: " + str(e))
            # __ENH_DEBUG_LOG__(traceback.format_exc())
            # raise
            raise exception_string(e)
            #raise
        return None		

class _ENH_PACKET(_ENH_BASE):
    _PAYLOAD_START_VAL = 0x42
    _MAGIC_NUMMBER = 0xCCEEEECC

    @staticmethod
    def raw_data(length):
        """
        generate 
        """
        payloads = []
        length = __ENH_DEF_PAYLOADS_LENGTH__ if __ENH_MIN_PAYLOADS_LENGTH__>length else length
        for i in range(_ENH_PACKET._PAYLOAD_START_VAL, _ENH_PACKET._PAYLOAD_START_VAL + length):
            payloads += [(i & 0xff)]  # Keep chars in the 0-255 range
        return bytes(payloads)

    def __init__(self,ihl=0,length=0,timestamp=None,payloads=None):
        self.ihl = ihl
        self.length = length if length else __ENH_DEF_PAYLOADS_LENGTH__
        self.timestamp = timestamp
        self.payloads = payloads
        self.list = [
            self.ihl,
            self.length,
            self.timestamp]

    def new(self):
        self.timestamp=None
        return self.pack()

    def pack(self):
        """
        adding format
            timestamp DWORD
            ..
        """
        payloads = []
        if(self.timestamp is None):
            self.timestamp = self.default_timer()
        __enh_header = struct.pack("!BIdI", 0,0,self.timestamp,0)
        self.ihl = len(__enh_header)
        if(self.payloads):
            self.length = self.ihl + len(payloads)
        __enh_header = struct.pack("!BIdI",self.ihl,self.length,self.timestamp,self._MAGIC_NUMMBER)
        if(self.payloads is None):
            payloads = __enh_header + _ENH_PACKET.raw_data(self.length - self.ihl)
        else:
            payloads = __enh_header + self.payloads
        self.raw_packet = payloads
        return payloads

    @staticmethod
    def unpack(packet):
        try:
            __enh_ihl = packet[0]
            __enh_header = struct.unpack("!BIdI", packet[:__enh_ihl])
            if(_ENH_PACKET._MAGIC_NUMMBER == __enh_header[3]):
                __enh_packet = _ENH_PACKET( __enh_header[0],__enh_header[1],__enh_header[2],packet[__enh_ihl:])
                __enh_packet.raw_packet = packet
                return __enh_packet
        except Exception as e:
            #__ENH_DEBUG_LOG__("type error: " + str(e))
            #__ENH_DEBUG_LOG__(traceback.format_exc())
            raise exception_string(e)
            #raise
        return None

class _ENH_PING(_ENH_BASE):
    _PROTOCOL_NUM = 0
    _PROTOCOL_NAME = ''
    _ADDR_FAMILY = 0
    _SOCKET_TYPE = 0
    _LOGFILE_SIZE = __ENH_MAX_LOGFILE_SIZE__
    _LOGFILE_COUNT = __ENH_DEF_LOGFILE_COUNT__

    def __init__(self,dst,src=None,src_port=None,dst_port=None,timeout=1,interval=1,count=-1,logflag=1,loglevel=logging.INFO):
        self.id = os.getpid() & 0xFFFF
        self.method = None
        self.src=src
        self.src_addr=None if (src is None) else socket.gethostbyname(src)
        self.dst=dst
        self.dst_addr=socket.gethostbyname(dst)
        self.src_port=src_port
        self.dst_port=dst_port
        self.timeout=timeout
        self.interval=interval
        self.count=count
        self.logging_handle(logflag,loglevel)

    def logging_handle(self,logflag,loglevel):
        self.hLogging = logging.getLogger(self.version())
        self.hLogging.setLevel(loglevel)

        if(logflag&0x1):
            stdout_formatter = logging.Formatter('%(message)s')
            stdout_handler = logging.StreamHandler()
            stdout_handler.setFormatter(stdout_formatter)
            self.hLogging.addHandler(stdout_handler)

        if(logflag&0x2):
            strLoggingname = __ENH_CLASS_NAME__ + '_' + self.dst
            strLoggingname += '_' + self.dst_port if(self.dst_port) else self._PROTOCOL_NAME
            strLoggingname += '.log'
            filout_formatter = logging.Formatter('%(levelname)s: %(asctime)s - %(filename)s[line:%(lineno)d] -  %(message)s')
            filout_handler = logging.handlers.RotatingFileHandler(strLoggingname, mode='w',
                maxBytes=self._LOGFILE_SIZE, backupCount=self._LOGFILE_COUNT)
            filout_handler.setFormatter(filout_formatter)
            self.hLogging.addHandler(filout_handler)
        return self.hLogging

    def ping(self):
        pass
    
    def done(self):
        pass
    
    def go(self):
        pass

class _ENH_STATISTICS:
    bInitialize = False
    # reachable_count = 0
    # unreachable_count = 0
    # buildin_output_format = "====== {dst}:{dst_port} {protocal_name} statistics ======"
    # customized_output_format = ""
    measure = dict()

    def __init__(self, dst, protocal_name='', dst_port=0):
        self.bInitialize = False
        self.put("dst", dst)
        self.put("protocal_name", protocal_name)
        self.put("dst_port",dst_port)
        self.put("delay_received")
        # self.measure["transmitted"] = self.measure["received"] = self.measure["timeout"] = 0
        # self.measure["min_delay"] = self.measure["max_delay"] = self.measure["avg_delay"] = 0
        # self.measure["select_cost"] = self.measure["gen_time"] = self.measure["req_create"] = 0
        # self.measure["overall_delay"] = self.measure["ping_delay"] = 0
        pass

    def put(self, name, value=0):
        self.measure[name]=value
        return self.measure[name]

    def add(self, name, value=1):
        if(not (name in self.measure)):
            self.measure[name] = 0
        self.measure[name]+=value
        return self.measure[name]
    
    def save_delay(self, value):
        if(value<=0):
            raise ValueError("Unaccepted value={0} received".format(value))
            #return value                       #unreachable maybe
        if(not self.bInitialize):
            self.measure["ping_delay"] = self.measure["min_delay"] = self.measure["max_delay"] = self.measure["avg_delay"] = self.measure["overall_delay"] = value
            self.measure["delay_received"] = 1
            self.bInitialize = True
        else:
            self.measure["ping_delay"] = value
            self.measure["delay_received"] += 1
            self.measure["min_delay"] = min(self.measure["min_delay"],value)
            self.measure["max_delay"] = max(self.measure["max_delay"],value)
            self.measure["overall_delay"] += value
            #self.measure["avg_delay"] = self.measure["overall_delay"]/self.measure["delay_received"]
        return self.measure["delay_received"]
    # mode 
    # 0 = ASSIGN  __ENH_STATISTICS_VALUE_ASSIGN__ = 0
    # 1 = SUM     __ENH_STATISTICS_VALUE_SUM__ = 1
    # 2 = DELAY   __ENH_STATISTICS_VALUE_DELAY__ = 2

    # def save1(self, name, value, mode):
    #     if (__ENH_STATISTICS_VALUE_ASSIGN__==mode):
    #         self.measure[name]=value
    #     elif(__ENH_STATISTICS_VALUE_SUM__==mode):
    #         self.measure[name]+=value
    #     elif(__ENH_STATISTICS_VALUE_DELAY__==mode):

    #     else:
    #         self.measure[name]=value
    #     return self.measure[name]

    def get(self,name):
        if((not (name in self.measure)) or (self.measure[name] is None)):
            self.put(name)
            raise ValueError("The value of {0} has not been saved".format(name))
        return self.measure[name]

    def get_as_string(self,name,lengh=6):
        str_var = '{0}'.format(self.get(name))
        if(lengh):
            return str_var[:lengh]
        return str_var

    def statistics(self):
        self.measure["lost"] = self.measure["transmitted"] - self.measure["received"]
        self.measure["lost_rate"] = self.measure["lost"]*100/self.measure["transmitted"] 
        if(self.measure["delay_received"]>0):
            self.measure["avg_delay"] = self.measure["overall_delay"]/self.measure["delay_received"]
            #self.measure["app_avg"] = self.measure["app_total"]/self.measure["delay_received"]
        else:
            self.measure["ping_delay"] = self.measure["min_delay"] = self.measure["max_delay"] = self.measure["overall_delay"] = self.measure["avg_delay"] = 0
        return self.measure

class _ENH_ICMPV4_PING(_ENH_PING):
    _PROTOCOL_NUM = socket.IPPROTO_ICMP
    _PROTOCOL_NAME = 'ICMPV4'
    _ADDR_FAMILY = socket.AF_INET
    _SOCKET_TYPE = socket.SOCK_RAW if __ENH_IS_WIN32__ else socket.SOCK_DGRAM
    #_SOCKET_TYPE = socket.SOCK_DGRAM if __ENH_IS_WIN32__ else socket.SOCK_RAW
    
    def __init__(self,dst,src=None,src_port=None,dst_port=None,timeout=1,interval=1,count=-1,sequence=1,payloads_len=56,logflag=1,loglevel=logging.DEBUG):
        super().__init__(dst,src,src_port,dst_port,timeout,interval,count,logflag,loglevel)
        #icmp = socket.getprotobyname("icmp")
        if(payloads_len<=0 or payloads_len>=__ENH_MAX_RECEIVE_BUFFER__):            #do want to handle too much payloads
            self.payloads_len = __ENH_DEF_PAYLOADS_LENGTH__ - 8
        else:
            self.payloads_len = payloads_len - 8
        self.sequence = sequence if sequence>0 else 1
        self.icmp_status = _ENH_STATISTICS(dst,self._PROTOCOL_NAME)
        self.icmp_status.put("app_start_time", self.default_timer())
        self.icmp_status.put("received")
        self.icmp_status.put("app_total")
        self.print_timestamp = False
        self.format_timestamp = __ENH_DATETIME_FORMAT__
        signal.signal(signal.SIGINT, self.__quit__)
        signal.signal(signal.SIGTERM,self.__quit__)
        try:
            self.icmp_socket = socket.socket(self._ADDR_FAMILY, self._SOCKET_TYPE, self._PROTOCOL_NUM)
        except PermissionError as e:
            e.args = (e.args if e.args else tuple()) + ((
                " NOTE: ICMP messages can only be sent as admin(root)."
            ),)
            raise

    def __del__(self):
        #stream_logging_obj.info(statistics.summary())
        self.hLogging.debug("I am deleting")
        pass
    
    def __quit__(self,signum, frame):
        self.count=0                                                                #this will break the loop in go
        #stream_logging_obj.info(statistics.summary())
        #self.hLogging.debug("I am doing exit routine" + str(signum) + str(frame))
        pass

    def go(self):
        #header_string="{0}_{1} {2}({3}) {4}({5}) bytes of data payloads"
        header_string='{0}_{1} {2}({3}) {4}({5}) bytes of data payloads'.format(
            self._PROTOCOL_NAME,
            __ENH_CLASS_NAME__,
            self.dst,
            self.dst_addr,
            self.payloads_len,
            self.payloads_len+28)
        self.hLogging.info(header_string)
        # self.hLogging.info(
        #     self._PROTOCOL_NAME + "_" + __ENH_CLASS_NAME__ + " " + self.dst + "(" + self.dst_addr + ")" + " " + 
        #     str(self.payloads_len) + "(" + str(self.payloads_len + 28) + ") bytes of data payloads"
        # )
        icount = 0
        while True:                                                                 # -1 infinite, 0 quit, >1 counts
            interval_ends = self.default_timer() + self.interval
            if(self.count and self.ping(sequence=self.sequence+icount)):
                self.done()
            icount+=1
            if(0<(self.count-icount)):
                interval_wait = interval_ends - self.default_timer()                #do we need to wait for next request?
                if (interval_wait>0):
                    time.sleep(interval_wait)
            else:
                break
        footer_string = """
====== {protocal_name} {0} {dst} statistics ======
{transmitted} packets transmitted, {received} packets received, {lost}({lost_rate:.2f}%) packets dropped.
min/avg/max = {min_delay:.4f}/{avg_delay:.4f}/{max_delay:.4f} ms
"""
        self.hLogging.info(footer_string.format(__ENH_CLASS_NAME__,**self.icmp_status.statistics()))
        return icount

    def ping(self,sequence=1):
        """
        send icmp echo request to dst_addr
        """
        self.icmp_status.put("req_create", self.default_timer())                   #the time when ping was called, we will generate payloads next
        icmp_payloads = _ENH_PACKET(length=self.payloads_len)
        # ICMP ECHO REQUEST TYPE = 8, CODE = 0 
        icmp_packet = _ICMPV4_PACKET(8,0,0,self.id,sequence,icmp_payloads.pack())  

        if self.icmp_socket.sendto(icmp_packet.pack(), (self.dst_addr, 0)):         # port is not needed for icmp
            self.icmp_status.add("transmitted")     # count the success request sent
            return True
        return False

    def done(self):
        """
        receive the icmp reply from the socket.
        """
        time_left = self.timeout
        app_time = 0
        while True:
            try:
                select_start = self.default_timer()                                 #used to caculate the time pending on receiving data.
                ready_sockets = select.select(
                    [self.icmp_socket],                                             #wait until a read is ready
                    [],                                                             #wait until the socket acccept a write
                    [],                                                             #...
                    time_left)
                #socket_time = self.default_timer()-select_start
                #self.icmp_status.put("socket_time", socket_time)
                if ready_sockets[0] == []:                                          #handling timeout situation outside the loop
                    break
                    # self.icmp_status.put("reachable", 0)
                    # self.icmp_status.add("timeout")
                    # self.hLogging.info(self.current_time() + " Request timed out.")
                    # return 0

                self.icmp_status.put("resp_received", self.default_timer())        #the time when data received
                #self.hLogging.debug(self.icmp_status.measure["resp_received"])
                ip_packet, addr = self.icmp_socket.recvfrom(__ENH_MAX_RECEIVE_BUFFER__)

                ipv4_packet = _IPV4_PACKET.unpack(ip_packet)
                self.hLogging.debug(ipv4_packet.list)
                icmpv4_packet = _ICMPV4_PACKET.unpack(ipv4_packet.payloads)
                self.hLogging.debug(icmpv4_packet.list)

                # Filters out the echo request itself.
                # This can be tested by pinging 127.0.0.1
                # You'll see your own request
                #app_time += self.default_timer() - select_start
                if icmpv4_packet.icmp_type != 8 and icmpv4_packet.id == self.id:    #type=0 echo reply, #type=? destination unreachable
                    self.icmp_status.put("reachable", 1)
                    enh_packet = _ENH_PACKET.unpack(icmpv4_packet.payloads)         #parse my own packet structure and data
                    self.icmp_status.add("received")
                    if enh_packet:                                                  #get request time from packet or use the req_create time
                        self.hLogging.debug(enh_packet.list)
                        self.icmp_status.put("req_sent", enh_packet.timestamp)     
                    else:
                        self.icmp_status.put("req_sent", self.icmp_status.get("req_create"))
                    
                    #caculate the delay and cost
                    ping_delay = (self.icmp_status.get("resp_received") - self.icmp_status.get("req_sent"))*1000
                    self.icmp_status.save_delay(ping_delay)
                    #app_time += self.icmp_status.get("req_sent") - self.icmp_status.get("req_create")
                    #app_time = app_time*1000 - ping_delay
                    #self.icmp_status.put("app_cost", app_time)
                    self.icmp_status.add("app_total",app_time)
                    #self.icmp_status.add("socket_cost",socket_time)
                    response_received_msg = '{}{} data bytes from {}: icmp_seq={} ttl={} time={:.6f}ms app={:.6f}ms'.format(
                        self.current_time(self.format_timestamp) if self.print_timestamp else '',
                        enh_packet.length,
                        ipv4_packet.src,
                        icmpv4_packet.seq,
                        ipv4_packet.ttl,
                        self.icmp_status.get("ping_delay"),
                        app_time
                    )
                    self.hLogging.info(response_received_msg)
                    # self.hLogging.info( 
                    #     self.current_time() + str(enh_packet.length) + " data bytes from " + ipv4_packet.src 
                    #     + ": icmp_seq="+str(icmpv4_packet.seq)+" ttl="+str(ipv4_packet.ttl)+" time="+self.icmp_status.get_as_string("ping_delay")+"ms"
                    #     + " app_cost=" + app_time + "ms"
                    #     )

                    return 1
                time_left = time_left + select_start - self.default_timer()         #in case it is not a response, and we still have time slot
                if (time_left<= 0):
                    break
            except Exception as e:
                self.hLogging.debug(traceback.format_exc())
                self.hLogging.info(str(e))
                return -1
#        self.icmp_status.put("reachable", 0)
        self.icmp_status.add("timeout")
        timeout_string = "{0}Request timed out.".format(self.current_time(self.format_timestamp) if self.print_timestamp else '')
        self.hLogging.info(timeout_string)
        return 0

def get_arguments():
    parser = argparse.ArgumentParser(
        prog=__ENH_CLASS_NAME__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__ENH_DESCRIPTION__,
        epilog=__ENH_EPILOG__)
    
    #refer to the help string for the argument meanings.
    # parser.add_argument('-t', '--tcp', dest='protocol', action='store_const', const='tcp',
    #     help='establishing tcp connection to estimate the host availability and network latency')
    # parser.add_argument('-u', '--udp', dest='protocol', action='store_const', const='udp',
    #     help='sending out udp packets and expecting no reply')
    # parser.add_argument('-r', '--raw', dest='protocol', action='store_const', const='raw',
    #     help='not implemented for now')
    # parser.add_argument('-m', '--icmp', dest='protocol', action='store_const', const='icmp',
    #     help='specify local ip address')
    parser.add_argument('-v', '--verbose',action='count', help="verbose logging info")
    parser.add_argument('--timestamp',action='count', help="verbose logging info")
    parser.add_argument('-i', '--interval', dest='interval', help="setup connection interval(second)", type=float,default=1)
    parser.add_argument('-t', '--timeout', dest='timeout', help="setup timeout(second)", type=float, default=4)        
    parser.add_argument('-l', '--length', dest='length', help="setup IPv4 frame payloads length (ICMP header included)", type=int,default=64)
    parser.add_argument('-c', '--count', dest='count', help="stop after outgoing packets reached this limitation", type=int,default=4)
    parser.add_argument('dst_host', nargs=1, action='store')

    return parser.parse_args()

if __name__ == '__main__':
    args = get_arguments()
    loglevel = logging.DEBUG if args.verbose else logging.INFO

    icmp_ping_handler = _ENH_ICMPV4_PING(args.dst_host[0],count=args.count,timeout=args.timeout,interval=args.interval,loglevel=loglevel,payloads_len=args.length)
    icmp_ping_handler.print_timestamp = True if args.timestamp else False

    #x = _ENH_ICMPV4_PING('192.168.128.254',count=1000,timeout=2,interval=0.05,loglevel=logging.INFO,payloads_len=9000)

    #x = _ENH_ICMPV4_PING('10.64.55.155')
    icmp_ping_handler.go()

