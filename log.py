from datetime import datetime
class Loger:
    def __init__(self, path_to_log):
        self.path_to_log = path_to_log
        if self.path_to_log == '':
            self.path_to_log = 'logs.txt'

    def log_message(self, message):
        with open(self.path_to_log, "a") as file:
            file.write(f"{datetime.now()} {message}\n")

