import pcap,socket,threading,sys
from uuid import getnode as get_mac
from parser import *
from engine import SpoofDetectorEngine

class PacketSniffer(object):
    myMac = None
    myIP = None

    def __init__(self,interface):
        self.interface = interface
        PacketSniffer.myMAC = self.getMyMAC()
        PacketSniffer.myIP = self.getMyIP()

        print 'My MAC:',PacketSniffer.myMAC
        print 'My IP:',PacketSniffer.myIP

    def start(self):
        self.verify_installation()
        sniffer = pcap.pcapObject()
        sniffer.open_live(self.interface, 4906, 0, 100)

        self.spoofEngine = SpoofDetectorEngine(self.myMAC,self.myIP,self.interface)
        sys.stdout.write('Starting read\n')
        sys.stdout.flush()
        while True:
            sniffer.dispatch(1, self.handle_packet)
        return False

    def handle_packet(self,pktlen,data,timestamp):
        if data[12:14]== ETHStructure.ARP_CODE:
            self.do_ARP(data)
        elif data[12:14]==ETHStructure.IP_CODE: #IPv4
            if data[23] == IPStructure.ICMP_CODE:#ICMP
                self.do_ICMP(data)

    def verify_installation(self):
        return True
        # from installer import InstallModule
        # status = InstallModule.get_installation_status()
        # if not status:
            # print('ARP spoof detector is not installed properly.')
            # exit(1)

    def do_ARP(self,data):
        t = threading.Thread(target=self.spoofEngine.ARP_packet_handler,args=(data,))
        t.start()
        return True

    def do_ICMP(self,data):
        t = threading.Thread(target=self.spoofEngine.ICMP_packet_handler,args=(data,))
        t.start()
        return True

    def getMyMAC(self):
        return get_mac()

    def getMyIP(self):
        for x in pcap.findalldevs():
            if x[0] == self.interface:
                return x[2][1][0]
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print 'Usage: [sudo] python',__name__,' <interface name>'
        exit(1)

    try:
        packetSnifferObject = PacketSniffer(sys.argv[1])
        packetSnifferObject.start()
    except Exception as e:
        print ('Error')
        print e.message
        exit(1)
