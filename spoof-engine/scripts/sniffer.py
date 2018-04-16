import pcap,socket,threading,sys
from parser import *
from engine import SpoofDetectorEngine

class PacketSniffer(object):
    myMac = None
    myIP = None

    def __init__(self):
        '''Intialize object by setting mac and ip globally.
        Verifies installation internally'''
        import os,yaml
        self.verify_installation() #verify before start
        configPath = os.path.join(os.path.dirname(__file__),'../','config/')
        self.configArray = yaml.safe_load(open(os.path.join(configPath,'installConfig.json'),'r'))
        self.userDataArray = yaml.safe_load(open(self.configArray['userDataJsonFile'],'r'))

        self.interface = self.userDataArray['interfaceName']
        # self.interface = 'enp3s0'
        PacketSniffer.myMAC = self.getMyMAC()
        PacketSniffer.myIP = self.getMyIP()

        print('My MAC: %s'%(PacketSniffer.myMAC))
        print('My IP: %s'%(PacketSniffer.myIP))

    def start(self):
        '''Main function to start sniffing packet.'''
        sniffer = pcap.pcapObject()
        sniffer.open_live(self.interface, 4906, 0, 100) #Fetch packet of 4096 lengths

        #Start spoof detection engine
        self.spoofEngine = SpoofDetectorEngine(self.myMAC,self.myIP,self.interface)
        sys.stdout.write('Starting read\n')
        sys.stdout.flush()

        statsCount = 0
        while True:
            # Handle each packet by using pcap's default callback function
            sniffer.dispatch(1, self.handle_packet)
            if statsCount == 1000:
                print sniffer.stats()
                statsCount = 0
            else:
                statsCount += 1
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
        from install import InstallModule
        #Verify installation status
        status = InstallModule().get_installation_status()
        if status == False:
            print('ARP spoof detector is not installed properly.')
            print('Use setup.sh for installation.')
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
        '''Fetches MAC address for any interface'''
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', self.interface[:15]))
        return int(info[18:24].encode('hex'),16)

    def getMyIP(self):
        '''Fetch IP in dotted format 0.0.0.0'''
        for x in pcap.findalldevs():
            if x[0] == self.interface:
                return x[2][1][0]
        return None

if __name__ == "__main__":
    try:
        packetSnifferObject = PacketSniffer()
        packetSnifferObject.start()
    except Exception as e:
        print('Error occured')
        print(e.message)
        exit(1)
