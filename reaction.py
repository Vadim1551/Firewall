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
            print(eb_rules)
            print(type(eb_rules))
            return [ip_rules, eb_rules]

        except subprocess.CalledProcessError:
            exit()

    @staticmethod
    # Находится ли правило в списке правил
    def rule_not_in_table(rule, rules):
        if rule in rules:   # O(N)
            return False
        else:
            return True

    @staticmethod
    def send_correct_arp(ip, ip_mac_table):
        # Отправка корректного ARP ответа для восстановления правильной ассоциации
        # в ARP таблицах в сети
        correct_packet = ARP(op=2, psrc=ip, hwsrc=ip_mac_table[ip])
        send(correct_packet, verbose=0)

    # Блокировка интерфейса
    def block_ip(self, ip_address):
        commands = []   # O(1)
        # Создание правил прокировки для iptables
        block_incoming = f"sudo iptables -A INPUT -s {ip_address} -j DROP"    # O(1)
        block_outgoing = f"sudo iptables -A OUTPUT -d {ip_address} -j DROP"   # O(1)

        # Проверка на дубликацию правила
        if self.rule_not_in_table(block_incoming[14:], self.rules[1]):   # O(N)
            commands.append(block_incoming)   # O(1)
        if self.rule_not_in_table(block_outgoing[14:], self.rules[1]):   # O(N)
            commands.append(block_outgoing)   # O(1)
        os.system(" && ".join(commands))   # O(1)
        self.rules[1] += f"\n{block_incoming[14:]}"   # O(1)
        self.rules[1] += f"\n{block_outgoing[14:]}"   # O(1)

    def block_mac(self, src_mac):
        commands = []
        block_incoming = f"sudo ebtables -A INPUT -s {src_mac} -j DROP"
        block_outgoing = f"sudo ebtables -A OUTPUT -d {src_mac} -j DROP"
        if self.rule_not_in_table(block_incoming[14:], self.rules[1]):
            commands.append(block_incoming)
        if self.rule_not_in_table(block_outgoing[14:], self.rules[1]):
            commands.append(block_outgoing)
        os.system(" && ".join(commands))
        self.rules[1] += f"\n{block_incoming[14:]}"
        self.rules[1] += f"\n{block_outgoing[14:]}"

    def block_interface(self, interface):
        commands = []
        block_incoming = f"sudo ebtables -A INPUT -i {interface} -j DROP"
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
