import struct

class ETHStructure(object):
	IP_CODE = '\x08\x00'
	ARP_CODE = '\x08\x06'
	data_format = {'struct':'6s6s2s',
					'length':14,
					'format':['eth_target_mac',
							'eth_source_mac',
							'eth_type']}

	def __init__(self):
		pass

	def get_packet(self,data):
		'''Get packet string'''
		to_pack_data = []
		for x in self.data_format['format']:
			to_pack_data += [data[x]]
		return struct.pack(self.data_format['struct'],*to_pack_data)[0]

class ARPStructure(object):
	OPCODE_REPLY = '\x00\x02'
	OPCODE_REQUEST = '\x00\x01'

	data_format = {'struct':'2s2s1s1s2s6s4s6s4s',
					'length':28,
					'format':['arp_hardware_type',
							'arp_protocol_type',
							'arp_hardware_address_length',
							'arp_protocol_address_length',
							'arp_opcode',
							'arp_source_mac',
							'arp_source_ip',
							'arp_target_mac',
							'arp_target_ip']}

	def __init__(self):
		pass

	def get_packet(self,data):
		'''Get packet string'''
		to_pack_data = []
		for x in self.data_format['format']:
			to_pack_data += [data[x]]

		arp_data = struct.pack(self.data_format['struct'],*to_pack_data)[0]
		eth_data = ETHStructure().get_packet(data)

class IPStructure(object):
	ICMP_CODE = '\x01'

	data_format = {'struct':'1s1s2s2s1s1s1s1s2s4s4s',
					'length':20,
					'format':['ip_version_header',
							'ip_differentiated_services_field',
							'ip_total_length',
							'ip_identification',
							'ip_flags',
							'ip_fragment_offset',
							'ip_ttl',
							'ip_protocol',
							'ip_checksum',
							'ip_source_ip',
							'ip_target_ip']}

	def __init__(self):
		pass

	def get_packet(self,data):
		'''Get packet string'''
		to_pack_data = []
		for x in self.data_format['format']:
			to_pack_data += [data[x]]

		arp_data = struct.pack(self.data_format['struct'],*to_pack_data)[0]
		eth_data = ETHStructure().get_packet(data)

class ICMPStructure(object):
	TYPE_REPLY = '\x00'
	TYPE_REQUEST = '\x08'

	data_format = {'struct':'1s1s2s2s2s8s16s',
					'length':32,
					'format':['icmp_type',
							'icmp_code',
							'icmp_checksum',
							'icmp_identifier',
							'icmp_sequence',
							'icmp_timestamp',
							'icmp_data']}

	def __init__(self):
		pass

	def get_packet(self,data):
		'''Get packet string'''
		to_pack_data = []
		for x in self.data_format['format']:
			to_pack_data += [data[x]]

		arp_data = struct.pack(self.data_format['struct'],*to_pack_data)[0]
		eth_data = ETHStructure().get_packet(data)
