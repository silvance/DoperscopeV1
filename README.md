# DoperscopeV1

A handheld Wi-Fi and BLE scanner for the **Raspberry Pi 4B** with a
**Waveshare Game HAT**. Renders a pygame UI directly to the framebuffer and
uses the Game HAT's GPIO buttons for navigation.

## Hardware

- Raspberry Pi 4B
- Waveshare Game HAT (480x320 IPS, GPIO buttons + joystick)
- USB Wi-Fi adapter on `wlan1` that supports monitor mode (the Pi's built-in
  `wlan0` is not used for scanning)

## Software stack

- **Python 3** — entry point is `main.py`
- **pygame** — UI rendered to a 640x480 surface and pushed to `/dev/fb0`
  (`SDL_VIDEODRIVER=offscreen`); `pygame.mixer` plays UI tick sounds
- **gpiozero** — Game HAT button input (`input_handler.py`)
- **lgpio** — used at startup to release any GPIO pins claimed by a previous run
- **scapy** — 802.11 sniffing for the Wi-Fi scanner (`wifi_scanner.py`)
- **bleak** — BLE advertisement scanning (`ble_scanner.py`)
- **iw / ip / rfkill / wpa_supplicant** — `start.sh` puts `wlan1` into
  monitor mode on channel 6 before launching `main.py`

## Game HAT GPIO map

Defined in `input_handler.py`:

| Button | BCM pin |
|--------|---------|
| Up     | 5  |
| Down   | 6  |
| Left   | 13 |
| Right  | 19 |
| A      | 12 |
| B      | 20 |
| X      | 16 |
| Y      | 18 |
| Start  | 26 |
| Select | 21 |
| Joy    | 4  |

## Files

- `main.py` — pygame UI, tab/filter/DF-mode state machine, framebuffer blit loop
- `wifi_scanner.py` — scapy-based AP/client/probe-request scanner with OUI lookup
- `ble_scanner.py` — bleak-based BLE scanner with company-ID lookup and
  MAC-rotation fingerprinting
- `input_handler.py` — Game HAT button bindings
- `start.sh` — boot script: settles USB, frees `wlan1`, sets monitor mode,
  launches `main.py`
