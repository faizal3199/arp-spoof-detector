from packets import *

class PacketParser(object):
    def __init__(self,data):
        self.packet_data = data

    def __fetch_format(self,name):
        if name == 'ARP':
            return ARPStructure.data_format
        elif name == 'ETH':
            return ETHStructure.data_format
        elif name == 'ICMP':
            return ICMPStructure.data_format
        elif name == 'IP':
            return IPStructure.data_format
        return None

    def get_parsed_data(self):
        packet_offset = 0
        self.parsed_data = {}
        packet_offset = self.parse_protocol('ETH',packet_offset)


        if self.parsed_data['eth_type'] == ETHStructure.ARP_CODE: #ARP
            packet_offset = self.parse_protocol('ARP',packet_offset)

        elif self.parsed_data['eth_type'] == ETHStructure.IP_CODE: #IP
            packet_offset = self.parse_protocol('IP',packet_offset)

            if self.parsed_data['ip_protocol'] == IPStructure.ICMP_CODE: #ICMP
                packet_offset = self.parse_protocol('ICMP',packet_offset)

        return self.parsed_data

    def parse_protocol(self,name,offset):
        data_format = self.__fetch_format(name)

        headers_data = self.packet_data[offset:offset+data_format['length']]
        offset += data_format['length']

        headers_data = struct.unpack(data_format['struct'],headers_data)

        for i in range(len(data_format['format'])):
            self.parsed_data[data_format['format'][i]] = headers_data[i]
        return offset

    def get_packet_string(self,data):
        if data['eth_type']==ETHStructure.ARP_CODE:
            data_to_pack = []

            for x in self.__fetch_format('ETH')['format']:
                data_to_pack += [data[x]]
            for x in self.__fetch_format('ARP')['format']:
                data_to_pack += [data[x]]
            return struct.pack(self.__fetch_format('ETH')['struct']+self.__fetch_format('ARP')['struct'],*data_to_pack)

        elif data['eth_type']==ETHStructure.IP_CODE and data['ip_protocol']==IPStructure.ICMP_CODE:
            data_to_pack = []
            checksumdata = ""
            for x in self.__fetch_format('ETH')['format']:
                data_to_pack += [data[x]]

            for x in self.__fetch_format('IP')['format']:
                data_to_pack += [data[x]]
                checksumdata += data[x].encode('hex')
            data_to_pack[11] = str("%.4x" % self.ip_checksum(checksumdata,len(checksumdata)/2)).decode('hex')

            checksumdata = ""
            for x in self.__fetch_format('ICMP')['format']:
                data_to_pack += [data[x]]
                checksumdata += data[x].encode('hex')
            data_to_pack[16] = str("%.4x" % self.ip_checksum(checksumdata,len(checksumdata)/2)).decode('hex')

            return struct.pack(self.__fetch_format('ETH')['struct']+self.__fetch_format('IP')['struct']+self.__fetch_format('ICMP')['struct'],*data_to_pack)

        return None

    def ip_checksum(self,ip_header_tmp, size):
        ip_header = [ip_header_tmp[i:i+2] for i in range(0,len(ip_header_tmp),2)]
        cksum = 0
        pointer = 0

        #The main loop adds up each set of 2 bytes. They are first converted to strings and then concatenated
        #together, converted to integers, and then added to the sum.
        while size > 1:
            cksum += int(ip_header[pointer]+ip_header[pointer+1], 16)
            size -= 2
            pointer += 2
        if size: #This accounts for a situation where the header is odd
            cksum += int(ip_header[pointer],16)
        cksum = (cksum >> 16) + (cksum & 0xffff)
        cksum += (cksum >>16)

        return (~cksum) & 0xFFFF
