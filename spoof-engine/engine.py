from parser import *
import socket,time
# from response import ResponseModule

class SpoofDetectorEngine(object):
    countTable = {}
    engineStatus = 'uninitialized'
    ICMPTable = {}

    def __init__(self,myMAC,myIP,interface):
        if self.engineStatus == 'running':
            print('Engine is already running')
            return False
        SpoofDetectorEngine.engineStatus = 'running'
        self.interface = interface
        self.myMAC = struct.pack('!Q',myMAC)[2:]
        self.broadcastMAC = '\xff'*6
        self.zeroMAC = '\x00'*6
        self.myIP = socket.inet_aton(myIP)

    def ARP_handler(self, data):
        # Do basic check by comparing datalink layer address with ARP's
        consistency_check = (data['eth_source_mac'] == data['arp_source_mac'])
        if not consistency_check:
            #@alert the user
            print 'consistency_check failed'
            return False

        #Handle gratuitous ARP replies
        gratuitous = (data['eth_target_mac'] in [self.broadcastMAC,self.zeroMAC])
        gratuitous = gratuitous or (data['arp_target_mac'] in [self.broadcastMAC,self.zeroMAC])

        if not gratuitous and data['eth_target_mac'] != data['arp_target_mac']:
            #@alert the user
            print 'consistency_check failed'
            return False

        # Consider the reply packet if system has sent request or it's gratuitous
        if self.countTable.get(data['arp_source_ip']) or gratuitous:
            if not gratuitous:
                self.countTable[data['arp_source_ip']] = False

            print '\n**************Sending ICMP Frame for verification to %s ************\n'%socket.inet_ntoa(data['arp_source_ip'])
            # Prepare ICMP frame to send from datalink layer
            ICMP_frame = {
            #Ethernet Frame
            'eth_target_mac':data['eth_source_mac'],
            'eth_source_mac':self.myMAC,
            'eth_type':ETHStructure.IP_CODE,
            #IP Frame
            'ip_version_header':'\x45',
            'ip_differentiated_services_field':'\x00',
            'ip_total_length':'\x00\x34',
            'ip_identification':'\x05\x07',
            'ip_flags':'\x40',
            'ip_fragment_offset':'\x00',
            'ip_ttl':'\x40',
            'ip_protocol':IPStructure.ICMP_CODE,
            'ip_checksum':'\x00\x00',
            'ip_source_ip':self.myIP,
            'ip_target_ip':data['arp_source_ip'],
            #ICMP Frame
            'icmp_type':ICMPStructure.TYPE_REQUEST,
            'icmp_code':'\x00',
            'icmp_checksum':'\x00\x00',
            'icmp_identifier':'\x6d\x34',
            'icmp_sequence':'\x00\x01',
            'icmp_timestamp':struct.pack('Q',int(time.time())),
            'icmp_data':'\x3f'*16 #Random data
            }

            #Convert packet  into string
            packet_string = PacketParser(None).get_packet_string(ICMP_frame)
            self.send_packet(packet_string)

            #Make entry in table with mac source
            self.ICMPTable[data['arp_source_ip']] = data['eth_source_mac']

            time.sleep(5) #Wait 5 seconds for  reply

            if self.ICMPTable[data['arp_source_ip']] != None: #NO reply still
                #@alert user
                print '\n**************ICMP verification failed for %s ************\n' % socket.inet_ntoa(data['arp_source_ip'])
                return False
            else:
                print '\n**************ICMP verification successfull for %s ************\n'%socket.inet_ntoa(data['arp_source_ip'])
                #Entry is safe
                pass
        else:
            #@alert the user
            return False

    def ARP_packet_handler(self, data):
        parsed_data = PacketParser(data).get_parsed_data()

        if parsed_data['arp_opcode'] == ARPStructure.OPCODE_REQUEST and parsed_data['eth_source_mac'] == self.myMAC:
            print parsed_data['arp_source_mac'].encode('hex'),'(',socket.inet_ntoa(parsed_data['arp_source_ip']),')',' ---->> ',parsed_data['eth_target_mac'].encode('hex'),'(',socket.inet_ntoa(parsed_data['arp_target_ip']),')'
            print '********countTable*************'
            self.countTable[parsed_data['arp_target_ip']] = True
            print self.countTable
            return True
        elif parsed_data['arp_opcode'] == ARPStructure.OPCODE_REPLY:
            if parsed_data['eth_target_mac'] in [self.myMAC,self.broadcastMAC,self.zeroMAC]:
                print parsed_data['arp_source_mac'].encode('hex'),'(',socket.inet_ntoa(parsed_data['arp_source_ip']),')',' ---->> ',parsed_data['eth_target_mac'].encode('hex'),'(',socket.inet_ntoa(parsed_data['arp_target_ip']),')'
                self.ARP_handler(parsed_data)
                return True

        return False

    def ICMP_handler(self, data):
        #Validate identifier and cross check mac and ip with our table
        if data['icmp_identifier'] == '\x6d\x34' and self.ICMPTable.get(data['ip_source_ip']) == data['eth_source_mac']:
            #Unlock the entry
            self.ICMPTable[data['ip_source_ip']] = None

    def ICMP_packet_handler(self,data):
        parsed_data = PacketParser(data).get_parsed_data()

        if parsed_data['icmp_type'] == ICMPStructure.TYPE_REPLY and parsed_data['eth_target_mac'] == self.myMAC:
            self.ICMP_handler(parsed_data)
            return True
        return False

    def send_packet(self,data_link_layer_packet):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((self.interface, socket.SOCK_RAW))
        s.send(data_link_layer_packet)
        return True
