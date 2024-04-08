from datetime import datetime
from send_message import Sender
from reaction import Reaction
from log import Loger


class Detect():
    def __init__(self, path_to_log):
        self.loger = Loger(path_to_log)
        self.reaction = Reaction()
        self.sender = Sender()
        self.ethertype_vlan = 0x8100

    def arp_mac_spoof_detection_time(self, ip, mac, current_arp_table, mac_address_change_time, enable_block_ip, enable_send_correct_arp, packet_interface):
        current_local_time = datetime.now()

        if ip in current_arp_table:
            last_mac, last_time = current_arp_table[ip]
            time_difference = (current_local_time - last_time).total_seconds() / 3600

            # Проверяем, изменился ли MAC-адрес и произошло ли изменение в пределах порога времени
            if last_mac != mac and time_difference < mac_address_change_time:
                message = f"[WARNING] Обнаружена ARP Spoofing атака! {ip} изменил MAC адрес с {last_mac} на {mac}, менее чем за {mac_address_change_time} на интерфейсе {packet_interface}"

                self.loger.log_message(message)

                self.sender.send_message_to_owner(message)  # Додумать отправку сообщения

                if enable_block_ip == 'yes':
                    self.reaction.block_ip(ip)
                    self.loger.log_message(f"[+] Входящий и исходящий трафик для IP {ip} был заблокирован")

                if enable_send_correct_arp == 'yes':
                    correct_arp = {ip: mac for ip, (mac, _) in current_arp_table.items()}
                    self.reaction.send_correct_ARP(ip, correct_arp)
                    self.loger.log_message(f"[+] Отправлен корректный ARP ответ для {ip}")
        else:
            current_arp_table[ip] = (mac, current_local_time)

        return current_arp_table

    def arp_mac_spoof_detection_static(self, ip, mac, static_ip_mac_table, enable_block_ip, enable_send_correct_arp, packet_interface):
        # Проверка на атаку ARP spoofing
        if ip in static_ip_mac_table:
            # Если MAC-адрес, ассоциированный с известным IP, не совпадает с доверенным...
            if mac != static_ip_mac_table[ip]:
                message = f"[WARNING] Обнаружена ARP Spoofing атака! {ip} изменил MAC адрес с {static_ip_mac_table[ip]} на {mac} на интерфейсе {packet_interface}"
                self.loger.log_message(message)
                self.sender.send_message_to_owner(message)  # Додумать отправку сообщения
                if enable_block_ip == 'yes':
                    self.reaction.block_ip(ip)
                    self.loger.log_message(f"[+] Входящий и исходящий трафик для IP {ip} был заблокирован")

                if enable_send_correct_arp == 'yes':
                    self.reaction.send_correct_ARP(ip, static_ip_mac_table)
                    self.loger.log_message(f"[+] Отправлен корректный ARP ответ для {ip}")

    def vlan_hopping_detection(self, src_mac, vlan_id, packet_type, allowed_vlan, enable_block_mac, packet_interface):

        if vlan_id not in allowed_vlan or packet_type != self.ethertype_vlan:

            message = f"[WARNING] Обнаружена атака VLAN-hopping. Подозрительный VLAN ID: {vlan_id} на интерфейсе {packet_interface}"
            self.loger.log_message(message)
            self.sender.send_message_to_owner(message)  # Додумать отправку сообщения

            if enable_block_mac == 'yes':
                self.reaction.block_mac(src_mac)
                self.loger.log_message(f"[+] Входящий трафик от MAC {src_mac} был заблокирован")

    def cam_or_arp_table_owerflow_detection(self, mac_buffer, arp_buffer, max_new_mac, max_new_arp):
        # Очистить буфер после обработки
        for key, value in mac_buffer.items():
            if len(value) > max_new_mac:
                message = f"[WARNING] Обнаружена атака CAM_table_owerflow на интерфейсе {key}"
                self.loger.log_message(message)
                self.sender.send_message_to_owner(message)  # Додумать отправку сообщения
                self.reaction.block_interface(key)
                self.loger.log_message(f"[+] Входящий трафик с интерфейса {key} был заблокирован")

        for key, value in arp_buffer.items():
            if len(value) > max_new_arp:
                message = f"[WARNING] Обнаружена атака CAM_table_owerflow  на интерфейсе {key}"
                self.loger.log_message(message)
                self.sender.send_message_to_owner(message)  # Додумать отправку сообщения
                self.reaction.block_interface(key)
                self.loger.log_message(f"[+] Входящий трафик с интерфейса {key} был заблокирован")
