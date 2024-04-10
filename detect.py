import subprocess
import re
from send_message import Sender
from reaction import Reaction
from log import Loger
from datetime import datetime


class Detect:
    def __init__(self, path_to_log='', cam_table_owerflow=None, vlan_hopping=None, arp_and_mac_spoofing=None):
        self.ethertype_vlan = 0x8100
        self.current_arp_table = self.get_current_arp_table()
        self.cam_table_owerflow = cam_table_owerflow
        self.vlan_hopping = vlan_hopping
        self.arp_and_mac_spoofing = arp_and_mac_spoofing
        self.loger = Loger(path_to_log)
        self.reaction = Reaction(set(self.arp_and_mac_spoofing['static_ip_mac_table']))
        self.sender = Sender()

    def get_current_arp_table(self):
        # Запускаем команду для получения таблицы соседей по IP
        try:
            output = subprocess.check_output(["ip", "neigh", "show"], text=True)
        except subprocess.CalledProcessError as e:
            self.loger.log_message(f"Ошибка при выполнении команды ip neigh show: {e}")
            self.current_arp_table = None
            print(e)
            return

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

        if ip in self.current_arp_table:
            last_mac, last_time = self.current_arp_table[ip]
            time_difference = (current_local_time - last_time).total_seconds() / 3600

            # Проверяем, изменился ли MAC-адрес и произошло ли изменение в пределах порога времени
            if last_mac != mac and time_difference < self.arp_and_mac_spoofing['suspicious_time_of_address_change_measured_in_hours']:
                message = f"[WARNING] Обнаружена ARP Spoofing атака! \
                {ip} изменил MAC адрес с {last_mac} на {mac}, \
                менее чем за {self.arp_and_mac_spoofing['suspicious_time_of_address_change_measured_in_hours']} \
                на интерфейсе {packet_interface}"

                self.loger.log_message(message)

                self.sender.send_message_to_owner(message)  # Додумать отправку сообщения

                if self.arp_and_mac_spoofing['enable_reactions']['block_ip']:
                    self.reaction.block_ip(ip)
                    self.loger.log_message(f"[+] Входящий и исходящий трафик для IP {ip} был заблокирован")

                if self.arp_and_mac_spoofing['enable_reactions']['send_correct_arp_response']:
                    correct_arp = {ip: mac for ip, (mac, _) in self.current_arp_table.items()}
                    self.reaction.send_correct_arp(ip, correct_arp)
                    self.loger.log_message(f"[+] Отправлен корректный ARP ответ для {ip}")
        else:
            self.current_arp_table[ip] = (mac, current_local_time)

    def arp_mac_spoof_detection_static(self, ip, mac, packet_interface):
        # Проверка на атаку ARP spoofing
        if ip in self.arp_and_mac_spoofing['static_ip_mac_table']:
            # Если MAC-адрес, ассоциированный с известным IP, не совпадает с доверенным...
            if mac != self.arp_and_mac_spoofing['static_ip_mac_table'][ip]:
                message = f"[WARNING] Обнаружена ARP Spoofing атака! \
                {ip} изменил MAC адрес с {self.arp_and_mac_spoofing['static_ip_mac_table'][ip]} на {mac} \
                 на интерфейсе {packet_interface}"

                self.loger.log_message(message)
                self.sender.send_message_to_owner(message)  # Додумать отправку сообщения
                if self.arp_and_mac_spoofing['enable_reactions']['block_ip']:
                    self.reaction.block_ip(ip)
                    self.loger.log_message(f"[+] Входящий и исходящий трафик для IP {ip} был заблокирован")

                if self.arp_and_mac_spoofing['enable_reactions']['send_correct_arp_response']:
                    self.reaction.send_correct_arp(ip, self.arp_and_mac_spoofing['static_ip_mac_table'])
                    self.loger.log_message(f"[+] Отправлен корректный ARP ответ для {ip}")

    def vlan_hopping_detection(self, src_mac, vlan_id, packet_type, packet_interface):

        if vlan_id not in self.vlan_hopping['allowed_vlan_ids'] or packet_type != self.ethertype_vlan:

            message = f"[WARNING] Обнаружена атака VLAN-hopping. \
            Подозрительный VLAN ID: {vlan_id} на интерфейсе {packet_interface}"

            self.loger.log_message(message)
            self.sender.send_message_to_owner(message)  # Додумать отправку сообщения

            if self.vlan_hopping['enable_reactions']['block_mac']:
                self.reaction.block_mac(src_mac)
                self.loger.log_message(f"[+] Входящий трафик от MAC {src_mac} был заблокирован")

    def cam_or_arp_table_owerflow_detection(self, arp_and_mac_buffer):
        # Очистить буфер после обработки
        list_blocked = set()
        if arp_and_mac_buffer:
            for key, value in arp_and_mac_buffer.items():
                if (
                        len(value['mac']) > self.cam_table_owerflow['max_new_mac_address'] or
                        len(value['arp']) > self.cam_table_owerflow['max_new_ip_address']
                ):
                    message = f"[WARNING] Обнаружена атака CAM_table_owerflow на интерфейсе {key}"
                    print(message)
                    if self.cam_table_owerflow['enable_reactions']['block_interface']:
                        print('Start blocking')
                        print(f'Interface {key}')
                        self.reaction.block_interface(key)
                        self.loger.log_message(f"[+] трафик с интерфейса {key} был заблокирован")
                        list_blocked.add(key)
                    self.loger.log_message(message)
                    self.sender.send_message_to_owner(message)

            if list_blocked:
                for interface in arp_and_mac_buffer:
                    arp_and_mac_buffer[interface]['mac'].clear()
                    arp_and_mac_buffer[interface]['arp'].clear()

        return list_blocked, arp_and_mac_buffer
