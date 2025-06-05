import threading
import itertools
import sys
import time

class Spinner:
    def __init__(self, message="Scanning..."):
        self.spinner = itertools.cycle(['-', '\\', '|', '/'])
        self.stop_running = threading.Event()
        self.message = message
        self.thread = threading.Thread(target=self._spin)

    def _spin(self):
        while not self.stop_running.is_set():
            sys.stdout.write(f"\r{self.message} {next(self.spinner)}")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * (len(self.message) + 2) + "\r")  # Clear line

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_running.set()
        self.thread.join()
