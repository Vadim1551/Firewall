import subprocess
import re
from concurrent.futures import ThreadPoolExecutor
from send_message import Sender
from reaction import Reaction
from log import Loger
from datetime import datetime


class Detect:
    def __init__(self, path_to_log='',
                 cam_table_overflow=None,
                 vlan_hopping=None,
                 arp_and_mac_spoofing=None):

        self.ethertype_vlan = 0x8100
        self.current_arp_table = self.get_current_arp_table()
        self.cam_table_overflow = cam_table_overflow
        self.vlan_hopping = vlan_hopping
        self.arp_and_mac_spoofing = arp_and_mac_spoofing
        self.loger = Loger(path_to_log)
        self.reaction = Reaction()
        self.sender = Sender()
        self.executor = ThreadPoolExecutor(max_workers=4)

    def get_current_arp_table(self):
        # Запускаем команду для получения таблицы соседей по IP
        try:
            output = subprocess.check_output(["ip", "neigh", "show"], text=True)
        except subprocess.CalledProcessError as e:
            self.loger.log_message(f"Ошибка при выполнении команды ip neigh show: {e}")
            print(e)
            return {}

        # Регулярное выражение для поиска IP и MAC адресов в выводе команды
        pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\w+\s+lladdr\s+([\da-fA-F:]+)\s+\w+")

        # Ищем все совпадения в выводе команды ip neigh show
        matches = pattern.findall(output)


        ip_mac_mapping = {}
        current_local_time = datetime.now()

        for match in matches:
            ip_mac_mapping[match[0]] = (match[1], current_local_time)

        return ip_mac_mapping

    def arp_mac_spoof_detection_time(self, ip, mac, packet_interface):
        current_local_time = datetime.now()
        block_mac = ""
        block_ip = ''
        block_interface = ''
        if ip in self.current_arp_table:
            print("IP IN self table")
            last_mac, last_time = self.current_arp_table[ip]
            print(f"{last_mac} {last_time}")
            time_difference = (current_local_time - last_time).total_seconds() / 3600
            print(time_difference)
            # Проверяем, изменился ли MAC-адрес и произошло ли изменение в пределах порога времени
            if last_mac != mac and time_difference < self.arp_and_mac_spoofing['suspicious_time_of_address_change_measured_in_hours']:
                message = f"[WARNING] Обнаружена ARP Spoofing атака! \
                {ip} изменил MAC адрес с {last_mac} на {mac}, \
                менее чем за {self.arp_and_mac_spoofing['suspicious_time_of_address_change_measured_in_hours']} \
                на интерфейсе {packet_interface}"
                print(message)

                self.executor.submit(self.loger.log_message(message))

                self.executor.submit(self.sender.send_message_to_owner(message))

                if self.arp_and_mac_spoofing['enable_reactions']['block_mac']:
                    self.reaction.block_mac(mac)
                    self.loger.log_message(f"[+] Входящий и исходящий трафик для MAC {mac} был заблокирован")
                    block_mac = mac

                if self.arp_and_mac_spoofing['enable_reactions']['block_ip']:
                    self.reaction.block_ip(ip)
                    self.loger.log_message(f"[+] Входящий и исходящий трафик для IP {ip} был заблокирован")
                    block_ip = ip

                if self.arp_and_mac_spoofing['enable_reactions']['block_interface']:
                    self.reaction.block_interface(packet_interface)
                    self.loger.log_message(f"[+] трафик с интерфейса {packet_interface} был заблокирован")
                    block_interface = packet_interface

            else:
                self.current_arp_table[ip] = (mac, current_local_time)
        else:
            self.current_arp_table[ip] = (mac, current_local_time)

        return block_mac, block_ip, block_interface

    # Функция для обнаружения атаки arp or mac spoofing на основе статической ARP таблицы
    def arp_mac_spoof_detection_static(self, ip, mac, packet_interface):
        block_mac = ''   # O(1)
        block_ip = ''    # O(1)
        block_interface = ''   # O(1)
        # Проверка на наличие полученного ip в ARP таблице
        if ip in self.arp_and_mac_spoofing['static_ip_mac_table']:   # O(N)
            # Если MAC-адрес, ассоциированный с известным IP, не совпадает с доверенным...
            if mac != self.arp_and_mac_spoofing['static_ip_mac_table'][ip]:   # O(1)

                message = f"[WARNING] Обнаружена ARP Spoofing атака! \
                {ip} изменил MAC адрес с {self.arp_and_mac_spoofing['static_ip_mac_table'][ip]} на {mac} \
                 на интерфейсе {packet_interface}"   # O(1)
                #Параллельный запуск логирования и оповещения администратора на почту
                self.executor.submit(self.loger.log_message, message)   # O(1)
                self.executor.submit(self.sender.send_message_to_owner, message)   # O(1)

                if self.arp_and_mac_spoofing['enable_reactions']['send_correct_arp_response']:   # O(1)
                    self.reaction.send_correct_arp(ip, self.arp_and_mac_spoofing['static_ip_mac_table'])   # O(1)
                    self.loger.log_message(f"[+] Отправлен корректный ARP ответ для {ip}")   # O(1)

                if self.arp_and_mac_spoofing['enable_reactions']['block_mac']:   # O(1)
                    self.reaction.block_mac(mac)   # O(N)
                    self.loger.log_message(f"[+] Входящий и исходящий трафик для MAC {mac} был заблокирован")   # O(1)
                    block_mac = mac   # O(1)

                if self.arp_and_mac_spoofing['enable_reactions']['block_ip']:   # O(1)
                    self.reaction.block_ip(ip)   # O(N)
                    self.loger.log_message(f"[+] Входящий и исходящий трафик для IP {ip} был заблокирован")   # O(1)
                    block_ip = ip   # O(1)

                if self.arp_and_mac_spoofing['enable_reactions']['block_interface']:   # O(1)
                    self.reaction.block_interface(packet_interface)   # O(1)
                    self.loger.log_message(f"[+] трафик с интерфейса {packet_interface} был заблокирован")   # O(1)
                    block_interface = packet_interface   # O(1)

        else:
            self.arp_and_mac_spoofing[ip] = mac   # O(1)
        return block_mac, block_ip, block_interface

    def vlan_hopping_detection(self, src_mac, vlan_id, packet_type, second_layer, packet_interface):
        block_mac = ''
        block_interface = ''
        if vlan_id not in self.vlan_hopping['allowed_vlan_ids'] or packet_type != self.ethertype_vlan or second_layer != 0:
            message = f"[WARNING] Обнаружена атака VLAN-hopping. \
            Подозрительный VLAN ID: {vlan_id} на интерфейсе {packet_interface}"

            self.executor.submit(self.loger.log_message, message)
            self.executor.submit(self.sender.send_message_to_owner, message)

            if self.vlan_hopping['enable_reactions']['block_mac']:
                self.reaction.block_mac(src_mac)
                self.loger.log_message(f"[+] Входящий трафик от MAC {src_mac} был заблокирован")
                block_mac = src_mac

            if self.vlan_hopping['enable_reactions']['block_interface']:
                self.reaction.block_interface(packet_interface)
                self.loger.log_message(f"[+] трафик с интерфейса {packet_interface} был заблокирован")
                block_interface = packet_interface

        return block_mac, block_interface

    def cam_or_arp_table_overflow_detection(self, arp_and_mac_buffer):
        # Очистить буфер после обработки
        list_blocked = set()
        if arp_and_mac_buffer:
            for key, value in arp_and_mac_buffer.items():
                if (
                        len(value['mac']) > self.cam_table_overflow['max_new_mac_address'] or
                        len(value['arp']) > self.cam_table_overflow['max_new_ip_address']
                ):
                    message = f"[WARNING] Обнаружена атака CAM_table_overflow на интерфейсе {key}"
                    print(message)

                    self.executor.submit(self.loger.log_message, message)
                    self.executor.submit(self.sender.send_message_to_owner, message)

                    if self.cam_table_overflow['enable_reactions']['block_interface']:
                        print('Start blocking')
                        print(f'Interface {key}')
                        self.reaction.block_interface(key)
                        self.loger.log_message(f"[+] трафик с интерфейса {key} был заблокирован")
                        list_blocked.add(key)

            if list_blocked:
                for interface in arp_and_mac_buffer:
                    arp_and_mac_buffer[interface]['mac'].clear()
                    arp_and_mac_buffer[interface]['arp'].clear()

        return list_blocked, arp_and_mac_buffer
