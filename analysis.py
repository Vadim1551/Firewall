from detect import Detect
from scapy.layers.l2 import Dot1Q, Ether
from scapy.layers.l2 import ARP
from scapy.all import *
import json
import time


class Analysis:
    def __init__(self):
        self.detect = None
        self.interfaces = None
        self.current_blocked_interfaces = None
        self.enable_arp_spoof_detect = False
        self.apr_spoof_method = ''
        self.enable_cam_table_overflow_detect = False
        self.enable_vlan_hopping_detect = False
        self.arp_and_mac_buffer = None
        self.restart_required = False
        self.sniffers = []
        self.blocked_mac = set()

    def load_config(self):
        with open("config.json", 'r') as file:
            conf = json.load(file)
            self.detect = Detect(conf['path_to_log'], conf['cam_table_overflow'],
                                 conf['vlan_hopping'], conf['arp_spoofing'])
            self.interfaces = set(conf['listening_interfaces'])
            self.current_blocked_interfaces = set(conf['blocked_interfaces'])
            self.enable_arp_spoof_detect = bool(conf['arp_spoofing']['enable'])
            self.apr_spoof_method = conf['arp_spoofing']['detection_method']
            self.enable_cam_table_overflow_detect = bool(conf['cam_table_overflow']['enable'])
            self.enable_vlan_hopping_detect = bool(conf['vlan_hopping']['enable'])
            self.arp_and_mac_buffer = {interface: {'mac': set(), 'arp': set()} for interface in self.interfaces}

    def periodic_analysis_count_mac(self):
        while True:
            list_blocked_interfaces, arp_mac_buf = self.detect.cam_or_arp_table_overflow_detection(self.arp_and_mac_buffer)
            self.arp_and_mac_buffer = arp_mac_buf
            if list_blocked_interfaces:
                self.current_blocked_interfaces = self.current_blocked_interfaces.union(list_blocked_interfaces)
                self.interfaces = self.interfaces - self.current_blocked_interfaces
                self.restart_required = True
            time.sleep(0.35)

    def determining_the_package_type(self, packet):
        try:
            packet_interface = packet.sniffed_on
            if packet_interface not in self.current_blocked_interfaces:
                if self.enable_cam_table_overflow_detect:
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
                            if ip not in self.blocked_mac:
                                if self.apr_spoof_method == 'time':
                                    ip = self.detect.arp_mac_spoof_detection_time(ip, mac, packet_interface)
                                    if ip:
                                        self.blocked_mac.add(mac)

                                elif self.apr_spoof_method == 'static_table':
                                    ip = self.detect.arp_mac_spoof_detection_static(ip, mac, packet_interface)
                                    if ip:
                                        self.blocked_mac.add(mac)

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
                self.enable_cam_table_overflow_detect]):

            if self.current_blocked_interfaces:
                self.interfaces = [inter for inter in self.interfaces if inter not in self.current_blocked_interfaces]

            self.start_sniffing()
        else:
            print("Не включен ни один режим анализа угроз")
            exit()

    def _start_sniffers(self):
        for iface in list(self.interfaces):
            print(f"Start sniffer on {iface}")
            sniffer = AsyncSniffer(iface=iface, prn=self.determining_the_package_type, store=False)
            sniffer.start()
            self.sniffers.append((sniffer, iface))

    def _stop_blocked_sniffers(self):
        for sniffer in self.sniffers:
            if sniffer[1] not in self.interfaces:
                sniffer[0].stop()
                print(f"Stop sniffer on {sniffer[1]}")
                self.sniffers.remove(sniffer)

    def _stop_all_sniffers(self):
        for sniffer in self.sniffers:
            sniffer[0].stop()
            print("Stop all sniffers")

    def start_sniffing(self):
        try:
            self._start_sniffers()

            if self.enable_cam_table_overflow_detect:
                thread = threading.Thread(target=self.periodic_analysis_count_mac)
                thread.daemon = True
                thread.start()

            while True:
                self.restart_required = False

                # Проверяем, требуется ли перезапуск каждые n секунд
                while not self.restart_required:
                    time.sleep(2)
                self._stop_blocked_sniffers()

        except KeyboardInterrupt:
            self._stop_all_sniffers()
