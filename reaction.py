from scapy.layers.l2 import ARP
from scapy.all import send
import os
import subprocess


class Reaction:
    def __init__(self):
        self.rules = self.get_ip_eb_tables()

    @staticmethod
    def get_ip_eb_tables():
        try:
            ip_rules = subprocess.check_output("iptables-save", shell=True).decode()
            eb_rules = subprocess.check_output("ebtables-save", shell=True).decode()
            return [ip_rules, eb_rules]

        except subprocess.CalledProcessError:
            exit()

    @staticmethod
    def rule_not_in_table(rule, rules):
        if rule in rules:
            return False
        else:
            return True

    @staticmethod
    def send_correct_arp(ip, ip_mac_table):
        # Отправка корректного ARP ответа для восстановления правильной ассоциации
        # в ARP таблицах в сети
        correct_packet = ARP(op=2, psrc=ip, hwsrc=ip_mac_table[ip])
        send(correct_packet, verbose=0)

    @staticmethod
    def block_ip(ip_address):
        # Блокируем входящий трафик от указанного IP
        block_incoming = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
        os.system(block_incoming)

        # Блокируем исходящий трафик к указанному IP
        block_outgoing = f"sudo iptables -A OUTPUT -d {ip_address} -j DROP"
        os.system(block_outgoing)

    @staticmethod
    def block_mac(src_mac):
        block_incoming = f"sudo iptables -A INPUT -m mac --mac-source {src_mac} -j DROP"
        os.system(block_incoming)

    def block_interface(self, interface):
        commands = []
        block_incoming = f"sudo ebtables -A INPUT -i {interface} -j DROP && sudo iptables -A INPUT -i {interface} -j DROP"
        block_forwarding = f"sudo ebtables -A FORWARD -i {interface} -j DROP"
        block_outgoing = f"sudo ebtables -A OUTPUT -o {interface} -j DROP"

        if self.rule_not_in_table(block_incoming[14:], self.rules[1]):
            block_incoming = f"sudo ebtables -A INPUT -i {interface} -j DROP"
            commands.append(block_incoming)
        if self.rule_not_in_table(block_forwarding[14:], self.rules[1]):
            block_forwarding = f"sudo ebtables -A FORWARD -i {interface} -j DROP"
            commands.append(block_forwarding)
        if self.rule_not_in_table(block_outgoing[14:], self.rules[1]):
            block_outgoing = f"sudo ebtables -A OUTPUT -o {interface} -j DROP"
            commands.append(block_outgoing)
        os.system(" && ".join(commands))
