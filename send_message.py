import smtplib
from email.mime.text import MIMEText
from email.header import Header
import os
from dotenv import load_dotenv


class Sender:
    def __init__(self):
        load_dotenv()

    def send_message_to_owner(self, text):
        login = os.getenv("LOGIN")
        password = os.getenv("PASSWORD")
        print(login, password)
        msg = MIMEText(f'{text}', 'plain', 'utf-8')
        msg['Subject'] = Header('Важно!!', 'utf-8')
        msg['From'] = login
        msg['To'] = login
        s = smtplib.SMTP('smtp.yandex.ru', 587, timeout=10)
        try:
            s.starttls()
            s.login(login, password)
            s.sendmail(msg['From'], msg['To'], msg.as_string())
        except Exception as ex:
            print(ex)
        finally:
            s.quit()
