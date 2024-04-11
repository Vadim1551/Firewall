from analysis import *
from send_message import Sender

def start():
    #firewall = Analysis()
    #firewall.start_analysis()
    x = Sender()
    x.send_message_to_owner('123321')

if __name__ == "__main__":
    start()
