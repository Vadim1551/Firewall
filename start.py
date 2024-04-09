from analysis import *

def getConf():
    config = {}
    try:
        with open('config.conf', 'r') as file:
            for line in file:
                # Игнорируем строки с комментариями и пустые строки
                if line.startswith('#') or not line.strip():
                    continue
                # Удаление лишних пробелов и разделение строки на ключ и значение
                key, value = [item.strip() for item in line.replace('=', ' ').split(None, 1)]
                # Добавление ключа и значения в словарь конфигураций
                config[key] = value

        return config

    except:
        print("Не удалось получить конфигурацию")


def start():
    conf = getConf()
    firewall = Analys(conf)
    firewall.start_analysis()

if __name__ == "__main__":
    start()
