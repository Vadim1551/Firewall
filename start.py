from analysis import *
from concurrent.futures import ThreadPoolExecutor

def start():
    firewall = Analysis()
    firewall.start_analysis()


if __name__ == "__main__":
    start()
