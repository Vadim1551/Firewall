import os
from scapy.layers.l2 import ARP
from scapy.all import send


class Reaction:
    def send_correct_ARP(self, ip, static_ip_mac_table):
        # Отправка корректного ARP ответа для восстановления правильной ассоциации
        # в ARP таблицах в сети
        correct_packet = ARP(op=2, psrc=ip, hwsrc=static_ip_mac_table[ip])
        send(correct_packet, verbose=0)

    def block_ip(self, ip_address):
        # Блокируем входящий трафик от указанного IP
        block_incoming = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
        os.system(block_incoming)

        # Блокируем исходящий трафик к указанному IP
        block_outgoing = f"sudo iptables -A OUTPUT -d {ip_address} -j DROP"
        os.system(block_outgoing)


    def block_mac(self, src_mac):
        block_incoming = f"sudo iptables -A INPUT -m mac --mac-source {src_mac} -j DROP"
        os.system(block_incoming)

    def block_interface(self, interface):
        block_incoming = f"sudo iptables -A INPUT -i {interface} -j DROP"
        os.system(block_incoming)