import subprocess
from scapy.layers.l2 import ARP
from scapy.all import send


class Reaction:
    def __init__(self, rules):
        self.rules = rules

    def is_rule_in_table(self, rule, table):
        if rule in table:
            return True
        else:
            return False

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
        block_incoming = f"sudo ebtables -A INPUT -i {interface} -j DROP"
        block_forwarding = f"sudo ebtables -A FORWARD -i {interface} -j DROP"
        block_outgoing = f"sudo ebtables -A OUTPUT -i {interface} -j DROP"
        if not(self.is_rule_in_table(block_incoming[14:], self.rules[1])):
            os.system(block_incoming)
            print('block_inc')
        if not(self.is_rule_in_table(block_forwarding[14:], self.rules[1])):
            os.system(block_forwarding)
            print("BLOCK forw")
        if not(self.is_rule_in_table(block_outgoing[14:], self.rules[1])):
            os.system(block_outgoing)
            print("BLOCK out")
