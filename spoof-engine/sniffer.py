import pcap,socket,threading,sys
from uuid import getnode as get_mac
from parser import *
from engine import SpoofDetectorEngine

class PacketSniffer(object):
    myMac = None
    myIP = None

    def __init__(self,interface):
        '''Intialize object by setting mac and ip globally'''
        self.interface = interface
        PacketSniffer.myMAC = self.getMyMAC()
        PacketSniffer.myIP = self.getMyIP()

        print('My MAC: %s'%(PacketSniffer.myMAC))
        print('My IP: %s'%(PacketSniffer.myIP))

    def start(self):
        '''Main function to start sniffing packet.
        Verifies intallation internally'''
        self.verify_installation() #verify before start
        sniffer = pcap.pcapObject()
        sniffer.open_live(self.interface, 4906, 0, 100) #Fetch packet of 4096 lengths

        #Start spoof detection engine
        self.spoofEngine = SpoofDetectorEngine(self.myMAC,self.myIP,self.interface)
        sys.stdout.write('Starting read\n')
        sys.stdout.flush()
        while True:
            # Handle each packet by using pcap's default callback function
            sniffer.dispatch(1, self.handle_packet)
        return False

    def handle_packet(self,pktlen,data,timestamp):
        '''Handle packet and create thread for each packet type
        Here using hardcoded packet types to save time'''
        if data[12:14]== ETHStructure.ARP_CODE:
            self.do_ARP(data)
        elif data[12:14]==ETHStructure.IP_CODE: #IPv4
            if data[23] == IPStructure.ICMP_CODE:#ICMP
                self.do_ICMP(data)

    def verify_installation(self):
        '''Support function for verifying installation.
        Exits if verification fails'''
        from installer import InstallModule
        #Verify installation status
        status = InstallModule.get_installation_status()
        if status == False:
            print('ARP spoof detector is not installed properly.')
            print('Use install.sh for installation.')
            exit(1)

    def do_ARP(self,data):
        '''Create new thread to handle ARP packets'''
        t = threading.Thread(target=self.spoofEngine.ARP_packet_handler,args=(data,))
        t.start()
        return True

    def do_ICMP(self,data):
        '''Create new thread to handle ICMP packets'''
        t = threading.Thread(target=self.spoofEngine.ICMP_packet_handler,args=(data,))
        t.start()
        return True

    def getMyMAC(self):
        '''Fetches MAC address'''
        return get_mac()

    def getMyIP(self):
        '''Fetch IP in dotted format 0.0.0.0'''
        for x in pcap.findalldevs():
            if x[0] == self.interface:
                return x[2][1][0]
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: [sudo] python %s <interface name>'%(__name__))
        exit(1)

    try:
        packetSnifferObject = PacketSniffer(sys.argv[1])
        packetSnifferObject.start()
    except Exception as e:
        print('Error')
        print(e.message)
        exit(1)
