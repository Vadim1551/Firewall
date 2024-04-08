from scapy.all import *
from detect import Detect
import threading
from scapy.layers.l2 import Dot1Q, Ether
from scapy.layers.l2 import ARP


class Analys():
    def __init__(self, conf):
        self.detect = Detect(conf['path_to_log'])
        self.current_arp_table = {}
        # Время, в течение которого изменение MAC-адреса считается подозрительным#
        self.mac_address_change_time = float(conf['MAC_address_change_time'])
        self.detection_mode = conf['Detection_mode']
        self.enable_block_ip = conf['Enable_block_ip'].lower()
        self.enable_send_correct_arp = conf['Enable_send_correct_ARP'].lower()
        self.static_ip_mac_table = {}
        self.path_to_static_table = conf.get('Static_ip_mac_table_path')
        self.analysis_max_mac_time = int(conf['Analysis_max_mac_time'])
        self.max_new_mac = int(conf['Max_new_MAC_in_the_analyzed_time'])
        self.mac_buffer = {}
        self.allowed_vlan = set(conf['Expected_VLAN_IDs'].split(','))
        self.enable_arp_spoof_detect = conf['Enable_ARP_spoofing_detect'].lower()
        self.enable_cam_table_owerflow_detect = conf['Enable_CAM_table_overflow_detect'].lower()
        self.enable_vlan_hopping_detect = conf['Enable_VLAN_hopping_detect'].lower()
        self.enable_block_mac = conf['Enable_block_mac'].lower()
        self.arp_buffer = {}
        self.max_new_arp = int(conf['Max_new_ARP_in_the_analyzed_time'])
        self.interfaces = conf['Listening_Interfaces'].split(',')

    def get_static_ip_mac_table(self):
        if self.path_to_static_table is not None:
            with open(self.path_to_static_table, 'r') as file:
                # Построчное чтение файла
                for line in file:
                    # Удаление пробельных символов с обеих сторон строки (включая символ новой строки)
                    stripped_line = line.strip()
                    # Проверка на пустую строку после удаления пробельных символов
                    if stripped_line:
                        # Разделение строки на IP и MAC по символу ':'
                        ip, mac = stripped_line.replace(' ', '').split('=')
                        # Добавление пары IP-MAC в словарь
                        self.static_ip_mac_table[ip] = mac
        else:
            self.path_to_static_table = False

    def get_current_arp_table(self):
        # Запускаем команду для получения таблицы соседей по IP
        try:
            output = subprocess.check_output(["ip", "neigh", "show"], text=True)
        except subprocess.CalledProcessError as e:
            self.detect.loger.log_message(f"Ошибка при выполнении команды ip neigh show: {e}")
            self.current_arp_table = False
            return

        # Регулярное выражение для поиска IP и MAC адресов в выводе команды
        pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\w+\s+lladdr\s+([\da-fA-F:]+)\s+\w+")

        # Ищем все совпадения в выводе команды ip neigh show
        matches = pattern.findall(output)

        ip_mac_mapping = {}
        current_local_time = datetime.now()

        for match in matches:
            ip_mac_mapping[match[0]] = (match[1], current_local_time)

        self.current_arp_table = ip_mac_mapping

    def periodic_analysis_count_mac(self):
        while True:
            print(self.mac_buffer)
            print(self.arp_buffer)
            self.detect.cam_or_arp_table_owerflow_detection(self.mac_buffer,
                                                            self.mac_buffer,
                                                            self.max_new_mac,
                                                            self.max_new_arp)
            for interface in self.interfaces:
                self.mac_buffer[interface].clear()
                self.arp_buffer[interface].clear()
            print(self.mac_buffer)
            print(self.arp_buffer)
            time.sleep(self.analysis_max_mac_time)

    def determining_the_package_type(self, packet):
        try:
            packet_interface = packet.sniffed_on
            if self.enable_cam_table_owerflow_detect == 'yes':
                if packet.haslayer(Ether):
                    mac_src = packet[Ether].src
                    self.mac_buffer[packet_interface].add(mac_src)

            if self.enable_arp_spoof_detect == 'yes':
                if packet.haslayer(ARP):
                    ip = packet[ARP].psrc
                    mac = packet[ARP].hwsrc
                    self.arp_buffer[packet_interface].add(ip)
                    if packet[ARP].op == 2:
                        if self.detection_mode == 'time':
                            if self.current_arp_table:
                                self.current_arp_table = self.detect.arp_mac_spoof_detection_time(ip,
                                                                                                  mac,
                                                                                                  self.current_arp_table,
                                                                                                  self.mac_address_change_time,
                                                                                                  self.enable_block_ip,
                                                                                                  self.enable_send_correct_arp,
                                                                                                  packet_interface)
                            else:
                                self.detect.loger.log_message("[ERROR] Failed to get ARP-table")

                        elif self.detection_mode == 'static_table':
                            if self.static_ip_mac_table:
                                self.detect.arp_mac_spoof_detection_static(ip,
                                                                           mac,
                                                                           self.static_ip_mac_table,
                                                                           self.enable_block_ip,
                                                                           self.enable_send_correct_arp,
                                                                           packet_interface)
                            else:
                                self.detect.loger.log_message(
                                    "[ERROR] You cannot use arp_spoof_static without a static IP:MAC table")

            if self.enable_vlan_hopping_detect == 'yes':
                if packet.haslayer(Dot1Q):
                    vlan_id = packet[Dot1Q].vlan
                    src_mac = packet[Ether].src
                    packet_type = packet[Ether].type
                    self.detect.vlan_hopping_detection(src_mac, vlan_id, packet_type, self.allowed_vlan,
                                                       self.enable_block_mac, packet_interface)

        except Exception as e:
            print(f"An error occurred: {e}")

    def start_analysis(self):
        self.get_current_arp_table()
        self.get_static_ip_mac_table()

        if 'yes' in (self.enable_arp_spoof_detect,
                     self.enable_vlan_hopping_detect,
                     self.enable_cam_table_owerflow_detect):

            if self.enable_cam_table_owerflow_detect == 'yes':
                for interface in self.interfaces:
                    self.mac_buffer[interface] = set()
                    self.arp_buffer[interface] = set()

                timer = threading.Thread(target=self.periodic_analysis_count_mac)
                timer.daemon = True
                timer.start()

            sniff(prn=self.determining_the_package_type, store=False, iface=self.interfaces)
