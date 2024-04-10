from detect import Detect
from scapy.layers.l2 import Dot1Q, Ether
from scapy.layers.l2 import ARP
from scapy.all import *
import json
import time


class Analysis:
    def __init__(self):
        self.detect = None
        self.interfaces = set()
        self.current_blocked_interfaces = set()
        self.enable_arp_spoof_detect = False
        self.apr_spoof_method = ''
        self.enable_cam_table_owerflow_detect = False
        self.enable_vlan_hopping_detect = False
        self.arp_and_mac_buffer = {interface: {'mac': set(), 'arp': set()} for interface in self.interfaces}

    def load_config(self):
        with open("config.json", 'r') as file:
            conf = json.load(file)
            self.detect = Detect(conf['path_to_log'], set(conf['static_ip_mac_table']), conf['cam_table_owerflow'],
                                 conf['vlan_hopping'], conf['arp_spoofing'])
            self.interfaces = set(conf['listening_interfaces'])
            self.current_blocked_interfaces = set(conf['blocked_interfaces'])
            self.enable_arp_spoof_detect = bool(conf['arp_spoofing']['enable'])
            self.apr_spoof_method = conf['arp_spoofing']['detection_method']
            self.enable_cam_table_owerflow_detect = bool(conf['cam_table_owerflow']['enable'])
            self.enable_vlan_hopping_detect = bool(conf['vlan_hopping']['enable'])

    def periodic_analysis_count_mac(self):
        while True:
            list_blocked_interfaces, arp_mac_buf = self.detect.cam_or_arp_table_owerflow_detection(self.arp_and_mac_buffer)
            self.arp_and_mac_buffer = arp_mac_buf
            self.current_blocked_interfaces.union(list_blocked_interfaces)
            list_interfaces = self.detect.cam_or_arp_table_owerflow_detection(self.arp_and_mac_buffer)
            if list_interfaces:
                for interface in list_interfaces:
                    self.current_blocked_interfaces.add(interface)
                    self.arp_and_mac_buffer[interface]['mac'].clear()
                    self.arp_and_mac_buffer[interface]['arp'].clear()
            time.sleep(0.5)

    def determining_the_package_type(self, packet):
        try:
            packet_interface = packet.sniffed_on
            if packet_interface not in self.current_blocked_interfaces:
                if self.enable_cam_table_owerflow_detect:
                    if packet.haslayer(Ether):
                        mac_src = packet[Ether].src
                        self.arp_and_mac_buffer[packet_interface]['mac'].add(mac_src)

                if self.enable_arp_spoof_detect:
                    if packet.haslayer(ARP):
                        if packet[ARP].op == 2:
                            print("Get ARP response")
                            ip = packet[ARP].psrc
                            mac = packet[ARP].hwsrc
                            self.arp_and_mac_buffer[packet_interface]['arp'].add(ip)

                            if self.apr_spoof_method == 'time':
                                self.detect.arp_mac_spoof_detection_time(ip, mac, packet_interface)

                            elif self.apr_spoof_method == 'static_table':
                                self.detect.arp_mac_spoof_detection_static(ip, mac, packet_interface)

                if self.enable_vlan_hopping_detect:
                    if packet.haslayer(Dot1Q):
                        vlan_id = packet[Dot1Q].vlan
                        src_mac = packet[Ether].src
                        packet_type = packet[Ether].type
                        self.detect.vlan_hopping_detection(src_mac, vlan_id, packet_type, packet_interface)

        except Exception as e:
            print(f"An error occurred: {e}")

    def start_analysis(self):
        self.load_config()

        if any([self.enable_arp_spoof_detect,
                self.enable_vlan_hopping_detect,
                self.enable_cam_table_owerflow_detect]):

            if self.current_blocked_interfaces:
                self.interfaces = [inter for inter in self.interfaces if inter not in self.current_blocked_interfaces]

            if self.enable_cam_table_owerflow_detect:

                timer = threading.Thread(target=self.periodic_analysis_count_mac)
                timer.daemon = True
                timer.start()

            print('Start')
            sniff(prn=self.determining_the_package_type, store=False, iface=self.interfaces)
