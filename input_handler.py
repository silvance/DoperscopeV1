from gpiozero import Button
import threading
import time

# Confirmed GPIO map for Waveshare Game HAT
BUTTON_MAP = {
    "up":     5,
    "down":   6,
    "left":   13,
    "right":  19,
    "a":      12,
    "b":      20,
    "x":      16,
    "y":      18,
    "start":  26,
    "select": 21,
    "joy":    4,
}

class InputHandler:
    def __init__(self):
        self._callbacks = {}
        self._lock = threading.Lock()
        self._running = True
        self._buttons = {}

        # Try gpiozero first with retries
        success = False
        for attempt in range(15):
            try:
                self._buttons = {}
                for name, pin in BUTTON_MAP.items():
                    btn = Button(pin, pull_up=True, bounce_time=0.05)
                    btn.when_pressed = lambda n=name: self._handle_press(n)
                    self._buttons[name] = btn
                success = True
                break
            except Exception as e:
                # Clean up partial buttons
                for btn in self._buttons.values():
                    try:
                        btn.close()
                    except:
                        pass
                self._buttons = {}
                if attempt < 14:
                    time.sleep(2)
                else:
                    raise

    def _handle_press(self, name):
        with self._lock:
            cb = self._callbacks.get(name)
        if cb:
            cb()

    def on(self, button_name, callback):
        with self._lock:
            self._callbacks[button_name] = callback

    def off(self, button_name):
        with self._lock:
            self._callbacks.pop(button_name, None)

    def cleanup(self):
        self._running = False
        for btn in self._buttons.values():
            try:
                btn.close()
            except:
                pass
