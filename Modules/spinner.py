import threading
import itertools
import sys
import time

class Spinner:
    def __init__(self, message="Scanning..."):
        # Create an infinite loop of spinner characters
        self.spinner = itertools.cycle(['-', '\\', '|', '/'])
        # Event used to signal the spinner thread to stop
        self.stop_running = threading.Event()
        # Message to display alongside spinner
        self.message = message
        # Thread running the spinner animation
        self.thread = threading.Thread(target=self._spin)

    def _spin(self):
        # Run spinner animation until stop signal is set
        while not self.stop_running.is_set():
            sys.stdout.write(f"\r{self.message} {next(self.spinner)}")  # Write message and spinner
            sys.stdout.flush()
            time.sleep(0.1)  # Wait before next spin character
        # Clear the line once spinner is stopped
        sys.stdout.write("\r" + " " * (len(self.message) + 2) + "\r")

    def start(self):
        # Start the spinner in a separate thread
        self.thread.start()

    def stop(self):
        # Signal the spinner to stop and wait for thread to finish
        self.stop_running.set()
        self.thread.join()