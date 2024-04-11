import smtplib
from email.mime.text import MIMEText
from email.header import Header
import os
from dotenv import load_dotenv
import time
from concurrent.futures import ThreadPoolExecutor


class Sender:
    def __init__(self):
        load_dotenv()

    @staticmethod
    def send_message_to_owner(text):
        login = os.getenv("LOGIN")
        password = os.getenv("PASSWORD")
        msg = MIMEText(f'{text}', 'plain', 'utf-8')
        msg['Subject'] = Header('Важно!!', 'utf-8')
        msg['From'] = login
        msg['To'] = login
        try:
            with smtplib.SMTP('smtp.yandex.ru', 587, timeout=10) as s:
                s.starttls()
                s.login(login, password)
                s.sendmail(msg['From'], msg['To'], msg.as_string())
        except Exception as ex:
            print(ex)

