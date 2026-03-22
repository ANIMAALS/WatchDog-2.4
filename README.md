<div align="center">


██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗██████╗  ██████╗  ██████╗     ██████╗    ██╗  ██╗
██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔═══██╗██╔════╝    ╚════██╗   ██╔╝  ╚██╗
██║ █╗ ██║███████║   ██║   ██║     ███████║██║  ██║██║   ██║██║  ███╗     █████╔╝  ██╔╝    ╚██╗
██║███╗██║██╔══██║   ██║   ██║     ██╔══██║██║  ██║██║   ██║██║   ██║    ██╔═══╝   ╚██╗    ██╔╝
╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║██████╔╝╚██████╔╝╚██████╔╝   ███████╗   ╚██╗  ██╔╝
 ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝   ╚══════╝    ╚═╝  ╚═╝


# WatchDog 2.4

**Portable 2.4 GHz Wireless Security Analyser**

[![Version](https://img.shields.io/badge/version-v3.1%20ENGINEERING%20HARDENED-1e82ff?style=for-the-badge&logo=arduino)](.)
[![Platform](https://img.shields.io/badge/platform-ESP32-orange?style=for-the-badge&logo=espressif)](.)
[![Status](https://img.shields.io/badge/status-Production%20%7C%20Hardware%20Tested-22cc66?style=for-the-badge)](.)
[![License](https://img.shields.io/badge/license-Closed%20Source-red?style=for-the-badge)](.)

*Real-time RF jammer detection · WiFi scanning · BLE tracker identification · Wireless IDS*

---

</div>

## What is WatchDog 2.4?

WatchDog 2.4 is a **handheld, battery-powered, offline wireless security analyser** built on the ESP32 microcontroller. It passively monitors the entire 2.4 GHz radio band — the frequency range shared by Wi-Fi, Bluetooth, BLE, RC drones, and many wireless protocols — and detects jamming attacks, rogue devices, and anomalous RF behaviour in real time.

No cloud. No server. No Wi-Fi needed during operation. Everything runs on the device.

---

## Features

### RF Spectrum Analysis
- Sweeps all **125 nRF24 channels** (2.400–2.524 GHz) continuously
- Live **125-channel spectrum waterfall** with peak-hold display
- Adaptive per-channel **noise floor calibration** (64-sample IIR)
- Asymmetric exponential smoothing filter (fast attack, slow decay)

### Jammer Detection — 9 Threat Types
| Threat Type | Label | Detection Method |
|---|---|---|
| Broadband burst | `Broadband_Jammer` | Instant path — early-exit spike detection (~80ms) |
| WiFi deauth flood | `WiFi_Deauth_Flood` | Contiguous block ≥10 ch, persistence ≥3 |
| Drone FHSS link | `Drone_FHSS_Link` | Hop counter ≥5, distance sum ≥80 ch in 2s |
| Sweep jammer | `RF_Sweep_Jammer` | Directional peak movement >6 consecutive steps |
| High entropy noise | `High_Entropy_Noise` | Shannon entropy H>3.8 or anomaly score >200 |
| RC/drone band | `RC_Drones_1-125_CH` | Active ch 84–124, activePct >30% |
| WiFi band | `WiFi_14_CH` | Dense contiguous block with peak energy |
| BLE band | `BLE_40_CH` | Even-channel dominant pattern |
| Bluetooth band | `Bluetooth_80_CH` | Broadband non-RC energy, btCount ≥15 |

### WiFi Scanner
- Async non-blocking scan — **never freezes the main loop**
- Detects **open access points** (zero encryption)
- **Evil Twin detection** — flags duplicate SSIDs
- **Camera OUI detection** — Hikvision, Dahua, Reolink, Wyze, TP-Link Tapo, Ezviz
- Channel usage map across all 14 Wi-Fi channels

### Bluetooth / BLE Mapper
- **Active BLE scan** — requests scan response packets for full device names
- Detects **AirTag, Tile, SmartTag, FindMy, Chipolo** trackers by OUI + name
- **Hidden device heuristic** — flags nameless devices with RSSI > -65 dBm
- 5-bar signal strength indicator per device

### Wireless IDS (Intrusion Detection)
- Five **persistence counter gauges** — WiFi, BT, Sweep, RC, Anomaly
- Live alert log — last 5 events with type, detail, elapsed time
- **Buzzer alarm** with unique tone patterns per threat type
- Alarm cadence scales with threat severity (activePct)

### Special Modes
- **RF Foxhunt** — proximity audio feedback (Geiger counter style) for signal hunting
- **Lens Scanner** — detects reflective patterns from hidden camera lenses
- **BT Foxhunt / WiFi Foxhunt** — single-target proximity bar
- **Geiger Counter** — click interval inversely proportional to signal strength

### Power & UI
- **ECO / Battery Saver mode** — dims backlight 70%, suspends BLE scan
- **Deep sleep with touch wakeup** — GPIO4 (T_IRQ) as ext0 wakeup source (v3.1)
- Light / Dark UI theme switching
- 6-page touchscreen UI: HOME · RF · WiFi · BT · IDS · SYS

---

## Hardware

### Bill of Materials

| Component | Qty | Approx. Price (India) |
|---|---|---|
| ESP32 DevKit v1 (30-pin) | 1 | ₹280–350 |
| nRF24L01+ PA/LNA module | 1 | ₹150–220 |
| ILI9341 2.4" TFT w/ XPT2046 | 1 | ₹350–450 |
| Passive buzzer (3-pin, 3.3V) | 1 | ₹20–40 |
| 100µF electrolytic capacitor | 2 | ₹10 |
| TP4056 LiPo charge module | 1 | ₹40–70 |
| 3.7V LiPo battery (1000–2000mAh) | 1 | ₹200–350 |
| Slide switch (SPDT) | 1 | ₹10–20 |
| 7×9cm perfboard | 1 | ₹30–50 |
| Headers, jumper wires, misc | — | ₹100–150 |
| **Total** | | **~₹1,200–1,700** |

> **Sources:** Robu.in · Evelta.com · Robokits.co.in · Amazon.in · SP Road, Bengaluru

### Pin Assignment

```
ESP32 DevKit         ←→  nRF24L01+
─────────────────────────────────────
GPIO18 (SCK)         →   SCK
GPIO23 (MOSI)        →   MOSI
GPIO19 (MISO)        →   MISO
GPIO22 (CE)          →   CE
GPIO21 (CSN)         →   CSN
3.3V                 →   VCC  ← + 100µF cap to GND (MANDATORY)
GND                  →   GND

ESP32 DevKit         ←→  ILI9341 TFT
─────────────────────────────────────
GPIO18 (SCK)         →   SCK  (shared SPI)
GPIO23 (MOSI)        →   MOSI (shared SPI)
GPIO19 (MISO)        →   MISO (shared SPI)
GPIO5  (TFT_CS)      →   CS
GPIO32 (TFT_DC)      →   DC
GPIO33 (TFT_RST)     →   RST
GPIO27 (BL_PWM)      →   BL   (LEDC PWM backlight)

ESP32 DevKit         ←→  XPT2046 Touch (onboard TFT)
─────────────────────────────────────
GPIO13 (TOUCH_CS)    →   T_CS
GPIO4  (TOUCH_IRQ)   →   T_IRQ  ← ALSO: deep sleep wakeup source (v3.1)

ESP32 DevKit         ←→  Buzzer
─────────────────────────────────────
GPIO26               →   Signal
3.3V                 →   VCC
GND                  →   GND

Power
─────────────────────────────────────
TP4056 BAT+/BAT-     →   LiPo cell (+)/(-)
TP4056 OUT+          →   Slide switch → ESP32 VIN
TP4056 OUT-          →   GND
ESP32 3.3V rail      →   nRF24L01 VCC  ← NOT from TP4056 OUT+
```

> ⚠️ **Critical:** The nRF24L01 must be powered from the ESP32 3.3V LDO rail, never directly from TP4056 OUT+ (up to 4.2V at full charge). Always place the 100µF cap across nRF24 VCC/GND.

---

## Software

### Architecture

```
┌─────────────────────────────────────────────────┐
│              loop()  ─  Core 1                  │
│                                                 │
│  handleTouch() → processPendingActions()        │
│  buzzerUpdate() → handlePowerAndBacklight()     │
│  runGeigerCounter() → runRFChunk() [10ms]       │
│  scanWifiAsync() → triggerAsyncBLE() [gated]    │
│  runHealthMonitor() → redrawPage() [120ms]      │
└────────────────────┬────────────────────────────┘
                     │  FreeRTOS mutex (bleMutex)
┌────────────────────▼────────────────────────────┐
│         BLECb::onResult()  ─  Core 0            │
│  (ESP-IDF BLE stack callback task)               │
│  Writes: bDevs[], bCount2, bSus, bTrackers       │
└─────────────────────────────────────────────────┘
```

**Design Principles:**
- **Single cooperative loop** — no custom RTOS tasks, no stack overflow risk
- **Async network stacks** — WiFi and BLE never block `loop()`
- **Deferred-action queue** — touch handler enqueues, main loop executes
- **FreeRTOS BLE mutex** — eliminates Core 0 / Core 1 data race on BLE shared data
- **Heap-safe char\* stack** — zero Arduino `String` objects in the entire codebase

### Library Dependencies

| Library | Install via |
|---|---|
| RF24 (TMRh20) | Arduino Library Manager |
| Adafruit GFX Library | Arduino Library Manager |
| Adafruit ILI9341 | Arduino Library Manager |
| XPT2046_Touchscreen (Stoffregen) | Arduino Library Manager |
| BLEDevice / BLEScan | Built into ESP32 Arduino core |
| WiFi | Built into ESP32 Arduino core |
| FreeRTOS | Built into ESP32 Arduino core |

---

## Installation

### 1. Arduino IDE Setup

```
Board:     ESP32 Dev Module
           (esp32 by Espressif Systems v2.x or v3.x)
CPU:       240 MHz
Flash:     4MB — Default Partition Scheme
Upload:    115200 or 921600 baud
```

Add ESP32 board package URL in Preferences:
```
https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
```

### 2. Install Libraries

In Library Manager, install:
- `RF24` by TMRh20
- `Adafruit GFX Library`
- `Adafruit ILI9341`
- `XPT2046_Touchscreen` by Paul Stoffregen

### 3. Upload

Open `Watchdog_Final_V1.ino` → Select correct COM port → Upload.

**Expected boot output (Serial Monitor @ 115200):**
```
RF Scanner Started
[OK] WatchDog v3.1 HARDENED running
Active: 2/125 (2%) -- clean
Active: 1/125 (1%) -- clean
```

**Expected display:** `WATCHDOG 2.4 · Wireless Security Analyser · Engine v3.1 | PRODUCTION BUILD` with cyan progress bar.

---

## Usage

### Navigation

| Gesture | Action |
|---|---|
| Short tap — nav bar (bottom) | Jump to that page directly |
| Short tap — content area | Cycle to next page |
| Hold 0.8s | Cycle sub-mode within current page |
| Hold 5s | Toggle ECO / Battery Saver mode |
| Any touch | Dismiss active alarm |

### Pages

| Page | Key Info |
|---|---|
| **HOME** | Threat level · active channel % · summary counters |
| **RF** | 125-channel live spectrum · 6 sub-modes including Foxhunt & Lens Scanner |
| **WiFi** | Network list · channel map · evil twin · camera OUI · Foxhunt |
| **BT** | BLE device list · tracker highlight · Foxhunt |
| **IDS** | Persistence counters · live alert log · alarm status |
| **SYS** | Uptime · diagnostics · loop health · noise calibration · theme |

### Sub-Mode Cycling (Hold 0.8s)

**RF Page (6 modes):** Live Spectrum → Jamming Focus → Freeze → Max Hold → RF Foxhunt → Lens Scanner

**WiFi Page (5 modes):** All Networks → Suspicious Cameras → Channel Map → WiFi Foxhunt → Deep Flush

**BT Page (4 modes):** All Devices → Trackers Only → BT Foxhunt → Deep Flush

**SYS Page (3 modes):** System Info → Noise Zero (calibrate floor) → Theme Switch

---

## v3.1 Changelog — Engineering Hardened

| Severity | Fix |
|---|---|
| 🔴 CRITICAL | FreeRTOS mutex protecting all BLE shared data (Core 0 / Core 1 race) |
| 🔴 CRITICAL | Deep sleep wakeup source configured on TOUCH_IRQ — no more power-cycle required |
| 🟠 HIGH | `earlyActive` reset per scan pass — prevents cross-pass false positive accumulation |
| 🟠 HIGH | `scaleMultiplier` capped at 4× — prevents single-pass early trigger saturation |
| 🟠 HIGH | All `String` heap allocations replaced with `char[]` arrays |
| 🟠 HIGH | RF PA level set to `RF24_PA_MIN` — eliminates SPI self-interference |
| 🟡 MEDIUM | Active BLE scan enabled — captures scan response device names |
| 🟡 MEDIUM | `reflectionSpike` capped at 20 — prevents integer overflow |
| 🟡 MEDIUM | `totalAlerts` capped at 99999 — prevents long-run overflow |
| 🟡 MEDIUM | `anomalyScore` wired into high-entropy path — catches burst sources |
| 🟢 LOW | Named colour constants replace inline magic values |
| 🟢 LOW | Camera OUI database: 4 → 7 entries (added Wyze, TP-Link Tapo, Ezviz) |
| 🟢 LOW | Tracker database: added Tile OUI + tile/chipolo name keywords |

---

## Roadmap

- **v3.2** — Edge Impulse neural network classifier replacing heuristic pattern gates
- **v3.3** — SD card logging of spectrum snapshots with timestamps
- **v3.4** — MQTT over WiFi for remote alert push to server dashboard
- **v3.5** — GPS tagging of jammer detection events
- **v7.0** — Custom PCB, hardware LiPo fuel gauge, USB-C native, 3D-printed enclosure

---

## Legal

> **Passive device only.** WatchDog 2.4 does not transmit any radio signal. It is designed for legitimate security research, education, and portfolio demonstration. The deliberate use of RF jammers is illegal in most jurisdictions. This device detects them — it does not create them.

---

## Copyright

Copyright © 2025 Anirudh N.S. All rights reserved.

This project and all associated source code, schematics, and documentation are the exclusive intellectual property of Anirudh N.S. No part of this project may be reproduced, distributed, modified, or used in any form without the express written permission of the author.

**Unauthorised copying, forking, or redistribution is strictly prohibited.**

---

<div align="center">

*Built on ESP32 + nRF24L01 + ILI9341 TFT · Bengaluru, India · 2025*

*AI collaboration: Claude Sonnet 4.6 (Anthropic) · Gemini 2.5 Pro (Google)*

</div>
