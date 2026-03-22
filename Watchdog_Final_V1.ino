/*
 * ============================================================
 * WATCHDOG 2.4 — Portable Wireless Intrusion Detection System
 * VERSION: v3.1 — ENGINEERING HARDENED
 * ARCHITECTURE: Single-Loop, Asynchronous Nets, Deferred-Action
 * ============================================================
 * FIXES IN v3.1:
 *  [CRITICAL] BLE callback data race fixed with FreeRTOS mutex
 *  [CRITICAL] Deep sleep now has wakeup source on TOUCH_IRQ
 *  [HIGH]     String heap allocations replaced with char arrays
 *  [HIGH]     scaleMultiplier capped at 4x — prevents energy saturation
 *  [HIGH]     earlyActive reset per scan pass — reduces false positives
 *  [MEDIUM]   RF PA level set to MIN for passive receive-only scanning
 *  [MEDIUM]   Active BLE scan enabled — captures scan response names
 *  [MEDIUM]   reflectionSpike overflow capped at 20
 *  [MEDIUM]   totalAlerts overflow protected at 99999
 *  [LOW]      Dead extern void declarations removed from loop()
 *  [LOW]      Magic color values replaced with named constants
 *  [LOW]      Extended OUI/tracker database (Tile, Chipolo added)
 *  [LOW]      anomalyScore wired into anomalyHist acceleration
 * ============================================================
 */

#include <SPI.h>
#include <RF24.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ILI9341.h>
#include <XPT2046_Touchscreen.h>
#include <WiFi.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <math.h>
#include <ctype.h>

// ============================================================
// HARDWARE PINS & CONSTANTS
// ============================================================
#define TFT_CS               5
#define TFT_DC              32
#define TFT_RST             33
#define TFT_BL_PIN          27

#define TOUCH_CS            13
#define TOUCH_IRQ            4
#define CE_PIN              22
#define CSN_PIN             21
#define BUZZER_PIN          26
#define BAT_ADC_PIN         35

#define TOTAL_CHANNELS      125
#define SCAN_PASSES         24
#define EARLY_JAM_THRESHOLD 30
#define JAM_SPIKE_THRESHOLD 18
#define DETECT_THRESHOLD    1
#define SCALE_MULT_CAP      4.0f   // FIX: prevent early-pass energy saturation

#define DISPLAY_INTERVAL    120
#define RF_INTERVAL         10
#define IDLE_TIMEOUT        30000
#define PEAK_HOLD_MS        1000
#define WIFI_SCAN_COOLDOWN  5000
#define BLE_SCAN_COOLDOWN   4000

// Touch Constants
#define TX_MIN 200
#define TX_MAX 3800
#define TY_MIN 200
#define TY_MAX 3800
#define LONG_PRESS_MS 800
#define TOUCH_DB 300

// Colors — standard
#define C_BLACK   ILI9341_BLACK
#define C_WHITE   ILI9341_WHITE
#define C_RED     ILI9341_RED
#define C_GREEN   ILI9341_GREEN
#define C_YELLOW  ILI9341_YELLOW
#define C_CYAN    ILI9341_CYAN
#define C_ORANGE  0xFD20
#define C_PURPLE  0xF81F
#define C_GREY    0x7BEF
#define C_DGREY   0x2945
#define C_DRED    0x8000
#define C_DGREEN  0x03E0
#define C_LIME    0x07E0
#define C_DBLUE   0x001F
#define C_LIGHTBG 0xDEFB

// FIX: named magic color constants
#define C_HIGHLIGHT_ROW  0x2000   // dark red row tint for threats
#define C_DARK_TEAL      0x0410   // separator/panel tint
#define C_DIM_BOOT       0x4208   // boot screen dim text
#define C_DIM_GREEN      0x0631   // very dim green

// ============================================================
// ENUMS & STRUCTURES
// ============================================================
enum Page { PG_HOME, PG_RF, PG_WIFI, PG_BT, PG_IDS, PG_SYS, PG_COUNT };
enum JamType { JAM_NONE, JAM_RC, JAM_BT, JAM_BLE, JAM_BT_WIFI, JAM_WIFI,
               JAM_WIFI_DEAUTH, JAM_DRONE_FHSS, JAM_SWEEP, JAM_ANOMALY, JAM_BROADBAND };
enum PendingAction { ACT_NONE, ACT_THEME_TOGGLE, ACT_ZERO_NOISE,
                     ACT_BLE_FLUSH, ACT_WIFI_FLUSH, ACT_IDS_FLUSH };

struct WNet   { char ssid[33], mac[18]; int rssi, ch; bool open, twin, isCam; };
struct BDev   { char name[32], mac[18]; int rssi; bool sus, isTracker; };
struct IAlert { char type[20], detail[28]; unsigned long ts; };

// ============================================================
// GLOBALS
// ============================================================
Adafruit_ILI9341 tft(TFT_CS, TFT_DC, TFT_RST);
XPT2046_Touchscreen touch(TOUCH_CS, TOUCH_IRQ);
RF24 radio(CE_PIN, CSN_PIN);
BLEScan* bleScan = nullptr;

// FIX: FreeRTOS mutex protecting BLE shared data (bDevs, bCount2, bSus, bTrackers)
SemaphoreHandle_t bleMutex = nullptr;

// RTC memory — persists across deep sleep, used to skip splash on wake
RTC_DATA_ATTR bool wakeFromSleep = false;

// Theme & Colors
bool isLightMode = false;
uint16_t bgCol = C_BLACK, textCol = C_WHITE, textDimCol = C_GREY, panelCol = C_DGREY;

// System Timers
unsigned long lastDisplayUpdate = 0, lastRFUpdate = 0, lastActiveTime = 0;
unsigned long lastBatteryDrain = 0, pageEntryTime = 0, lastHealthyLoop = 0;
unsigned long lastWifiScanStart = 0, lastBleScanStart = 0;
unsigned long maxLoopDelay = 0;
int stallWarnings = 0;

// State Flags
Page curPage = PG_HOME;
PendingAction pendingAction = ACT_NONE;
bool needRedraw = true, isDimmed = false, batterySaver = false;
float virtualBattery = 100.0;
bool showPopup = false;
unsigned long popupTimer = 0;
char popT[32] = "", popL1[32] = "", popL2[32] = "", popInd[8] = "";

// Detection State
uint8_t energy[TOTAL_CHANNELS], smoothEnergy[TOTAL_CHANNELS], prevEnergy[TOTAL_CHANNELS];
uint8_t peakEnergy[TOTAL_CHANNELS], prevPeak[TOTAL_CHANNELS];
float noiseFloor[TOTAL_CHANNELS] = {0};
unsigned long peakTime[TOTAL_CHANNELS];
int scanCh = 0, scanPass = 0, earlyActive = 0, instantSpike = 0;
bool scanDone = false, isInstantJam = false;
int activeCount = 0;
float activePct = 0;

int wifiCount = 0, btCount = 0, bleCount = 0, rcCount = 0;
int wifiHist = 0, btHist = 0, bleHist = 0, rcHist = 0, anomalyHist = 0, sweepHist = 0;
int hopCounter = 0, hopDistanceSum = 0, lastPeakChannel = -1;
int lastSweepPeak = -1, sweepDirection = 0, sweepCount = 0;
unsigned long lastHopReset = 0, lastJamDetectTime = 0;

int stabilityBuffer[8] = {0};
int stabilityIndex = 0, reflectionSpike = 0, lastSignalForLens = 0, deviationScore = 0;
bool stableSignal = false, jamming = false, prevJamming = false;
JamType jamType = JAM_NONE, heldJamType = JAM_NONE;

// Alarms & Geiger
bool alarmActive = false, buzzerIsOn = false;
unsigned long buzzerOffTime = 0, lastAlarmTick = 0, lastGeigerTick = 0;
int alarmPhase = 0, alarmRepeat = 0;
JamType alarmJamType = JAM_NONE;
int currentFoxSig = -100;
// FIX: char array instead of String — eliminates heap fragmentation
char foxDir[16] = "=== HOLD ===";

// Modes
int homeMode = 1, rfMode = 0, wifiMode = 0, btMode = 0, idsMode = 0, sysMode = 0;

// Network Data
WNet wNets[20];
int wCount = 0, wOpen = 0, wTwins = 0, wCams = 0;
BDev bDevs[20];
int bCount2 = 0, bSus = 0, bTrackers = 0;
IAlert alerts[5];
int alertCount = 0, totalAlerts = 0;

// ============================================================
// FORWARD DECLARATIONS
// ============================================================
void runDetection();
void redrawPage();
void drawNav(Page p);
void drawHome();
void updateHomeBar();
void drawRF_Static();
void drawRF_Dynamic();
void updateRFBars();
void drawWifi();
void drawBT();
void drawIDS();
void drawSys();
void scanWifiAsync();
void triggerAsyncBLE();
void addAlert(const char* t, const char* d);
const char* jamLabel(JamType j);   // FIX: const char* not String
void buzzerStartAlarm(JamType j);
void buzzerStopAlarm();
void triggerPopup(const char* t, const char* l1, const char* l2, const char* ind);
void drawPopup();
void drawFeaturePrompt(int current, int total);
void applyTheme();
void drawStatusBar();
void drawCenteredText(const char* text, int y, int size, uint16_t color);
void runGeigerCounter();
bool checkCameraOUI(const char* mac);
bool checkTrackerOUI(const char* mac, const char* name);
void handleTouch();
void processPendingActions();
void buzzerUpdate();
void handlePowerAndBacklight();
void runRFChunk(unsigned long now);

// ============================================================
// ASYNC BLE CALLBACKS
// ============================================================
void bleScanCompleteCB(BLEScanResults results) {
    // Async completion — intentionally empty
}

class BLECb : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice d) {
    // FIX: mutex guard — this runs on BLE task (Core 0), main loop on Core 1
    if (!bleMutex) return;
    if (xSemaphoreTake(bleMutex, pdMS_TO_TICKS(10)) != pdTRUE) return;

    if (bCount2 < 20) {
        if (d.haveName() && d.getName().length() > 0) {
            strncpy(bDevs[bCount2].name, d.getName().c_str(), 31);
        } else {
            strncpy(bDevs[bCount2].name, d.getAddress().toString().c_str(), 31);
        }
        bDevs[bCount2].name[31] = '\0';
        strncpy(bDevs[bCount2].mac, d.getAddress().toString().c_str(), 17);
        bDevs[bCount2].mac[17] = '\0';
        bDevs[bCount2].rssi = d.getRSSI();
        bDevs[bCount2].sus = (!d.haveName() && d.getRSSI() > -65);
        bDevs[bCount2].isTracker = checkTrackerOUI(bDevs[bCount2].mac, bDevs[bCount2].name);
        if (bDevs[bCount2].sus) bSus++;
        if (bDevs[bCount2].isTracker) {
            bTrackers++;
            addAlert("Tracker Found", bDevs[bCount2].mac);
        }
        bCount2++;
    }
    xSemaphoreGive(bleMutex);
  }
};
BLECb bleCallbackHandler;

// ============================================================
// UI TEXT UTILITY
// ============================================================
void drawCenteredText(const char* text, int y, int size, uint16_t color) {
    int16_t x1, y1;
    uint16_t w, h;
    tft.setTextSize(size);
    tft.getTextBounds(text, 0, 0, &x1, &y1, &w, &h);
    int x = (320 - w) / 2 - x1;
    tft.setTextColor(color);
    tft.setCursor(x, y);
    tft.print(text);
}

// ============================================================
// SETUP
// ============================================================
void setup() {
    Serial.begin(115200);

    // FIX: create BLE mutex before anything else touches BLE
    bleMutex = xSemaphoreCreateMutex();

    pinMode(BUZZER_PIN, OUTPUT); noTone(BUZZER_PIN);
#if ESP_ARDUINO_VERSION >= ESP_ARDUINO_VERSION_VAL(3, 0, 0)
    ledcAttach(TFT_BL_PIN, 5000, 8);
    ledcWrite(TFT_BL_PIN, 255);
#else
    ledcSetup(0, 5000, 8);
    ledcAttachPin(TFT_BL_PIN, 0);
    ledcWrite(0, 255);
#endif

    pinMode(TFT_CS, OUTPUT);  digitalWrite(TFT_CS, HIGH);
    pinMode(TOUCH_CS, OUTPUT); digitalWrite(TOUCH_CS, HIGH);
    pinMode(CSN_PIN, OUTPUT);  digitalWrite(CSN_PIN, HIGH);
    pinMode(CE_PIN, OUTPUT);   digitalWrite(CE_PIN, LOW);

    pinMode(TFT_RST, OUTPUT);
    digitalWrite(TFT_RST, LOW);  delay(80);
    digitalWrite(TFT_RST, HIGH); delay(80);

    tft.begin(); tft.setRotation(1); tft.fillScreen(C_BLACK);
    touch.begin(); touch.setRotation(1);

    // ── Startup Splash ──────────────────────────────────────
    if (!wakeFromSleep) {
        tft.fillScreen(C_BLACK);
        tft.fillRect(0, 0, 320, 2, C_CYAN);
        tft.fillRect(0, 238, 320, 2, C_CYAN);
        tft.fillRoundRect(12, 10, 52, 13, 3, C_CYAN);
        tft.setTextColor(C_BLACK); tft.setTextSize(1);
        tft.setCursor(17, 13); tft.print("2.4 GHz");
        drawCenteredText("WATCHDOG 2.4", 38, 3, C_CYAN);
        drawCenteredText("Wireless Security Analyser", 90, 2, C_WHITE);
        tft.fillRect(60, 115, 200, 1, C_GREY);
        drawCenteredText("Engine v3.1  |  PRODUCTION BUILD", 122, 1, C_GREY);
        drawCenteredText("Initialising...", 155, 1, C_DIM_BOOT);
        tft.drawRect(60, 170, 200, 8, C_GREY);
        for (int i = 0; i <= 200; i += 4) {
            tft.fillRect(61, 171, i, 6, C_CYAN);
            delay(5000 / 50);
        }
    }
    wakeFromSleep = false; // reset for next normal boot

    if (!radio.begin()) {
        tft.fillScreen(C_BLACK);
        drawCenteredText("HARDWARE ERROR", 80, 2, C_RED);
        drawCenteredText("nRF24 Radio Not Found", 120, 2, C_WHITE);
        while (true) delay(100);
    }
    radio.setAutoAck(false);
    radio.disableCRC();
    radio.setAddressWidth(2);
    radio.setPayloadSize(32);
    radio.setDataRate(RF24_2MBPS);
    // FIX: PA_MIN — passive scanner does not need PA_MAX; avoids SPI self-interference
    radio.setPALevel(RF24_PA_MIN);
    radio.stopListening();

    BLEDevice::init("WATCHDOG");
    bleScan = BLEDevice::getScan();
    // FIX: active scan true — requests scan response packets, gets more device names
    bleScan->setActiveScan(true);
    bleScan->setInterval(100);
    bleScan->setWindow(99);
    bleScan->setAdvertisedDeviceCallbacks(&bleCallbackHandler);

    memset(smoothEnergy, 0, sizeof(smoothEnergy));
    for (int i = 0; i < TOTAL_CHANNELS; i++) noiseFloor[i] = 0.0;
    lastActiveTime   = millis();
    lastBatteryDrain = millis();
    pageEntryTime    = millis();
    lastHealthyLoop  = millis();

    applyTheme();
    needRedraw = true;
    redrawPage();
}

// ============================================================
// NON-DESTRUCTIVE HEALTH MONITOR
// ============================================================
void runHealthMonitor() {
    unsigned long now = millis();
    unsigned long loopDuration = now - lastHealthyLoop;
    if (loopDuration > maxLoopDelay) maxLoopDelay = loopDuration;
    if (loopDuration > 2000) {
        stallWarnings++;
        Serial.printf("WARN: Loop delayed %lu ms\n", loopDuration);
        needRedraw = true; // FIX: notify user of stall visually
    }
    lastHealthyLoop = now;
}

// ============================================================
// MAIN EXECUTION LOOP
// ============================================================
void loop() {
    unsigned long now = millis();
    if (buzzerIsOn && now >= buzzerOffTime) {
        noTone(BUZZER_PIN); buzzerIsOn = false;
    }

    // FIX: removed unnecessary extern void declarations — all functions
    // are in the same translation unit and declared above
    handleTouch();
    processPendingActions();
    buzzerUpdate();
    handlePowerAndBacklight();
    runGeigerCounter();

    if (showPopup && now - popupTimer > 1800) {
        showPopup = false;
        needRedraw = true;
        if (curPage == PG_RF) {
            tft.fillScreen(bgCol);
            drawNav(curPage); drawRF_Static();
            memset(prevEnergy, 0, sizeof(prevEnergy));
            memset(prevPeak,   0, sizeof(prevPeak));
        }
    }

    if (!showPopup) runRFChunk(now);

    if (now - lastDisplayUpdate > DISPLAY_INTERVAL) {
        lastDisplayUpdate = now;
        if (needRedraw) { redrawPage(); needRedraw = false; }
        if (!showPopup) {
            if (curPage == PG_RF)   drawRF_Dynamic();
            else if (curPage == PG_HOME) updateHomeBar();
            drawStatusBar();
        }
    }

    if (!batterySaver && !showPopup) {
        if (curPage == PG_WIFI && wifiMode != 4) scanWifiAsync();
        if (curPage == PG_BT && btMode != 3 &&
            now - lastBleScanStart > BLE_SCAN_COOLDOWN) {
            triggerAsyncBLE();
        }
    }

    runHealthMonitor();
    delay(1);
}

// ============================================================
// CHUNKED RF SCANNER
// ============================================================
void runRFChunk(unsigned long now) {
    bool rfFrozen = (curPage == PG_RF && rfMode == 2);
    if (now - lastRFUpdate > RF_INTERVAL && !rfFrozen) {
        lastRFUpdate = now;
        if ((curPage == PG_HOME || curPage == PG_RF || curPage == PG_IDS) && !scanDone) {
            for (int i = 0; i < 6; i++) {
                radio.setChannel(scanCh);
                radio.startListening();
                delayMicroseconds(130);
                bool rpd = radio.testRPD();
                delayMicroseconds(60);

                if (rpd) {
                    energy[scanCh]++;
                    earlyActive++; instantSpike++;
                } else {
                    if (instantSpike > 0) instantSpike--;
                }
                radio.stopListening();

                if (instantSpike > 8 && earlyActive > 12) {
                    isInstantJam = true;
                    scanDone = true; runDetection(); break;
                }
                if (earlyActive > JAM_SPIKE_THRESHOLD && scanPass >= 1) {
                    scanDone = true; runDetection(); break;
                }
                if (earlyActive > EARLY_JAM_THRESHOLD && scanPass >= 3) {
                    scanDone = true; runDetection(); break;
                }

                scanCh++;
                if (scanCh >= TOTAL_CHANNELS) {
                    scanCh = 0;
                    scanPass++;
                    // FIX: reset earlyActive per pass — prevents cross-pass accumulation
                    // causing false positives in benign RF environments
                    earlyActive = 0;
                    if (scanPass >= SCAN_PASSES) {
                        scanDone = true; runDetection(); break;
                    }
                }
            }
        } else if (scanDone) {
            memset(energy, 0, sizeof(energy));
            scanPass = 0; scanCh = 0; earlyActive = 0;
            scanDone = false; instantSpike = 0;
        }
    }
}

// ============================================================
// DEFERRED ACTION PROCESSOR
// ============================================================
void processPendingActions() {
    if (pendingAction == ACT_NONE) return;
    switch (pendingAction) {
        case ACT_THEME_TOGGLE:
            isLightMode = !isLightMode;
            applyTheme(); needRedraw = true; break;
        case ACT_ZERO_NOISE:
            for (int i = 0; i < TOTAL_CHANNELS; i++) noiseFloor[i] = smoothEnergy[i];
            break;
        case ACT_BLE_FLUSH:
            if (xSemaphoreTake(bleMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
                bCount2 = 0; bSus = 0; bTrackers = 0;
                if (bleScan) bleScan->clearResults();
                xSemaphoreGive(bleMutex);
            }
            break;
        case ACT_WIFI_FLUSH:
            wCount = 0; break;
        case ACT_IDS_FLUSH:
            totalAlerts = 0; alertCount = 0;
            wifiHist = btHist = bleHist = rcHist = anomalyHist = sweepHist = 0;
            break;
        default: break;
    }
    pendingAction = ACT_NONE;
}

// ============================================================
// TOUCH HANDLING
// ============================================================
void handleTouch() {
    static bool isHolding = false;
    static unsigned long touchStartTime = 0;
    static bool actionFired800 = false;
    static bool actionFired5000 = false;
    static int savedX = 0, savedY = 0;
    unsigned long now = millis();

    bool isTouched = touch.touched();
    if (isTouched) {
        if (!isHolding) {
            if (now - lastActiveTime < TOUCH_DB) return;
            isHolding = true; actionFired800 = false; actionFired5000 = false;
            touchStartTime = now; lastActiveTime = now;
            TS_Point p = touch.getPoint();
            savedX = constrain(map(p.x, TX_MIN, TX_MAX, 0, 319), 0, 319);
            savedY = constrain(map(p.y, TY_MIN, TY_MAX, 0, 239), 0, 239);
            if (isDimmed && !batterySaver) {
                isDimmed = false;
#if ESP_ARDUINO_VERSION >= ESP_ARDUINO_VERSION_VAL(3, 0, 0)
                ledcWrite(TFT_BL_PIN, 255);
#else
                ledcWrite(0, 255);
#endif
                actionFired800 = true;
            }
        }
        lastActiveTime = now;

        if (!actionFired5000 && (now - touchStartTime > 5000)) {
            actionFired5000 = true;
            batterySaver = !batterySaver;
            if (batterySaver) {
                isLightMode = false;
                pendingAction = ACT_THEME_TOGGLE;
                triggerPopup("BATTERY SAVER ON", "Scanners Disabled", "5s hold to wake", "ECO");
#if ESP_ARDUINO_VERSION >= ESP_ARDUINO_VERSION_VAL(3, 0, 0)
                ledcWrite(TFT_BL_PIN, 75);
#else
                ledcWrite(0, 75);
#endif
                isDimmed = true; tone(BUZZER_PIN, 2000, 200);
            } else {
                triggerPopup("BATTERY SAVER OFF", "Full power restored", "", "PWR");
#if ESP_ARDUINO_VERSION >= ESP_ARDUINO_VERSION_VAL(3, 0, 0)
                ledcWrite(TFT_BL_PIN, 255);
#else
                ledcWrite(0, 255);
#endif
                isDimmed = false; tone(BUZZER_PIN, 3000, 200);
            }
        }

        if (!actionFired800 && !actionFired5000 && (now - touchStartTime > LONG_PRESS_MS)) {
            actionFired800 = true;
            if (curPage == PG_HOME) {
                homeMode = (homeMode + 1) % 3;
                if (homeMode == 0) { triggerPopup("ARMED MODE",   "System audio activated", "",     "1/3"); tone(BUZZER_PIN, 4000, 150); }
                if (homeMode == 1)   triggerPopup("STEALTH MODE", "Alarms completely muted", "",     "2/3");
                if (homeMode == 2) { triggerPopup("NOISE ZEROED", "Environment calibrated",  "",     "3/3"); pendingAction = ACT_ZERO_NOISE; }
            }
            else if (curPage == PG_RF) {
                if (homeMode == 0) tone(BUZZER_PIN, 4000, 100);
                rfMode = (rfMode + 1) % 6;
                if (rfMode == 0) triggerPopup("LIVE SPECTRUM",  "Standard waterfall",       "", "1/6");
                if (rfMode == 1) triggerPopup("JAMMING FOCUS",  "Only anomalies",           "", "2/6");
                if (rfMode == 2) triggerPopup("FREEZE GRAPH",   "Scanner paused",           "", "3/6");
                if (rfMode == 3) triggerPopup("MAX HOLD",       "Infinite peak mapping",    "", "4/6");
                if (rfMode == 4) triggerPopup("RF FOXHUNT",     "Geiger counter enabled",   "", "5/6");
                if (rfMode == 5) triggerPopup("LENS SCANNER",   "Sweep room for cameras",   "", "6/6");
            }
            else if (curPage == PG_WIFI) {
                if (batterySaver) { triggerPopup("WIFI DISABLED", "ECO Mode Active", "", ""); return; }
                wifiMode = (wifiMode + 1) % 5;
                if (wifiMode == 0) triggerPopup("ALL NETWORKS",       "Standard environment",   "", "1/5");
                if (wifiMode == 1) triggerPopup("SUSPICIOUS CAMERAS", "Open APs & Known OUIs",  "", "2/5");
                if (wifiMode == 2) triggerPopup("CHANNEL MAP",        "Spectrum congestion",    "", "3/5");
                if (wifiMode == 3) triggerPopup("WIFI FOXHUNT",       "Tracking strongest AP",  "", "4/5");
                if (wifiMode == 4) { triggerPopup("DEEP FLUSH", "Clearing memory...", "", "5/5"); pendingAction = ACT_WIFI_FLUSH; wifiMode = 0; }
            }
            else if (curPage == PG_BT) {
                if (batterySaver) { triggerPopup("BT DISABLED", "ECO Mode Active", "", ""); return; }
                btMode = (btMode + 1) % 4;
                if (btMode == 0) triggerPopup("ALL DEVICES",   "Standard BLE environment", "", "1/4");
                if (btMode == 1) triggerPopup("TRACKERS ONLY", "Hidden MACs & Trackers",   "", "2/4");
                if (btMode == 2) triggerPopup("BT FOXHUNT",    "Tracking strongest BT",    "", "3/4");
                if (btMode == 3) { triggerPopup("DEEP FLUSH",  "Clearing memory...",       "", "4/4"); pendingAction = ACT_BLE_FLUSH; btMode = 0; }
            }
            else if (curPage == PG_SYS) {
                sysMode = (sysMode + 1) % 3;
                if (sysMode == 0) triggerPopup("SYSTEM INFO",   "Standard diagnostics",    "", "1/3");
                if (sysMode == 1) { triggerPopup("NOISE ZEROED","Environment calibrated",   "", "2/3"); pendingAction = ACT_ZERO_NOISE; }
                if (sysMode == 2) {
                    if (batterySaver) triggerPopup("THEME LOCKED", "Disable ECO Mode First", "", "3/3");
                    else { triggerPopup("THEME SWITCH", "Colors inverted", "", "3/3"); pendingAction = ACT_THEME_TOGGLE; }
                }
            }
        }
    } else {
        if (isHolding && (now - lastActiveTime > 50)) {
            isHolding = false;
            if (!actionFired800 && !actionFired5000 && (now - touchStartTime < LONG_PRESS_MS)) {
                alarmActive = false;
                noTone(BUZZER_PIN); buzzerIsOn = false;

                Page newPage = curPage;
                if (savedY > 212) newPage = (Page)constrain(savedX / (320 / PG_COUNT), 0, PG_COUNT - 1);
                else              newPage = (Page)((curPage + 1) % PG_COUNT);

                if (curPage == PG_BT && newPage != PG_BT && bleScan) {
                    bleScan->stop();
                    bleScan->clearResults();
                }
                curPage = newPage;
                needRedraw = true;
                pageEntryTime = millis();
                if (curPage == PG_RF) {
                    memset(prevEnergy, 0, sizeof(prevEnergy));
                    memset(prevPeak,   0, sizeof(prevPeak));
                }
            }
        }
    }
}

// ============================================================
// ASYNC NETWORK SCANNERS
// ============================================================
void scanWifiAsync() {
    unsigned long now = millis();
    int16_t scanState = WiFi.scanComplete();

    if ((scanState == WIFI_SCAN_FAILED || scanState == -2) &&
        (now - lastWifiScanStart > WIFI_SCAN_COOLDOWN)) {
        lastWifiScanStart = now;
        WiFi.scanNetworks(true, true);
    }
    else if (scanState >= 0) {
        wCount = 0; wOpen = 0; wTwins = 0; wCams = 0;
        int n = min((int)scanState, 20);
        for (int i = 0; i < n; i++) {
            strncpy(wNets[i].ssid, WiFi.SSID(i).c_str(), 32); wNets[i].ssid[32] = '\0';
            strncpy(wNets[i].mac,  WiFi.BSSIDstr(i).c_str(), 17); wNets[i].mac[17] = '\0';
            wNets[i].rssi  = WiFi.RSSI(i);
            wNets[i].ch    = WiFi.channel(i);
            wNets[i].open  = (WiFi.encryptionType(i) == WIFI_AUTH_OPEN);
            wNets[i].twin  = false;
            wNets[i].isCam = checkCameraOUI(wNets[i].mac);
            if (wNets[i].open) wOpen++;
            if (wNets[i].isCam) { wCams++; addAlert("Camera Found", wNets[i].mac); }
            for (int j = 0; j < i; j++) {
                if (strcmp(wNets[j].ssid, wNets[i].ssid) == 0) {
                    wNets[i].twin = wNets[j].twin = true;
                    wTwins++;
                    addAlert("Evil Twin", wNets[i].ssid);
                }
            }
        }
        WiFi.scanDelete();
        wCount = n; needRedraw = true; lastWifiScanStart = now;
    }
}

void triggerAsyncBLE() {
    if (curPage != PG_BT || !bleScan) return;
    // FIX: guard the reset under mutex — write side
    if (xSemaphoreTake(bleMutex, pdMS_TO_TICKS(20)) == pdTRUE) {
        bCount2 = 0; bSus = 0; bTrackers = 0;
        xSemaphoreGive(bleMutex);
    }
    lastBleScanStart = millis();
    bleScan->start(1, bleScanCompleteCB, false);
}

// ============================================================
// POWER & BACKLIGHT
// ============================================================
void applyTheme() {
    if (isLightMode) {
        bgCol = C_LIGHTBG; textCol = C_BLACK; textDimCol = C_DGREY; panelCol = 0xCE59;
    } else {
        bgCol = C_BLACK; textCol = C_WHITE; textDimCol = C_GREY; panelCol = C_DGREY;
    }
    tft.fillScreen(bgCol);
}

void handlePowerAndBacklight() {
    unsigned long now = millis();
    if (now - lastBatteryDrain > 5000) {
        float drainPer5s = batterySaver ? (100.0 / 1440.0) : (100.0 / 780.0);
        virtualBattery -= drainPer5s;
        if (virtualBattery < 0) virtualBattery = 0;
        lastBatteryDrain = now;
    }

    if (batterySaver && !isDimmed) {
#if ESP_ARDUINO_VERSION >= ESP_ARDUINO_VERSION_VAL(3, 0, 0)
        ledcWrite(TFT_BL_PIN, 75);
#else
        ledcWrite(0, 75);
#endif
        isDimmed = true;
    }
    else if (!batterySaver && isDimmed && !jamming) {
#if ESP_ARDUINO_VERSION >= ESP_ARDUINO_VERSION_VAL(3, 0, 0)
        ledcWrite(TFT_BL_PIN, 255);
#else
        ledcWrite(0, 255);
#endif
        isDimmed = false;
    }

    if (jamming && isDimmed) {
#if ESP_ARDUINO_VERSION >= ESP_ARDUINO_VERSION_VAL(3, 0, 0)
        ledcWrite(TFT_BL_PIN, 255);
#else
        ledcWrite(0, 255);
#endif
        isDimmed = false; lastActiveTime = millis();
    }

    if (now - lastActiveTime > IDLE_TIMEOUT) {
        int countdown = 10 - ((now - lastActiveTime - IDLE_TIMEOUT) / 1000);
        if (countdown <= 0) {
            tft.fillScreen(C_BLACK);
            drawCenteredText("DEVICE POWERED OFF", 100, 2, C_RED);
            drawCenteredText("Touch screen to wake.", 130, 1, C_GREY);
            delay(100);
            // FIX: configure wakeup source before sleep so touch wakes the device
            wakeFromSleep = true;
            esp_sleep_enable_ext0_wakeup((gpio_num_t)TOUCH_IRQ, 0);
            esp_deep_sleep_start();
        } else {
            if ((now / 500) % 2 == 0) {
                tft.fillRect(20, 80, 280, 80, C_RED);
                tft.drawRect(20, 80, 280, 80, C_WHITE);
                drawCenteredText("ARE YOU USING DEVICE?", 95, 2, C_WHITE);
                char cd[32];
                snprintf(cd, 32, "Powering off in %d", countdown);
                drawCenteredText(cd, 130, 2, C_WHITE);
            } else {
                needRedraw = true;
            }
            static unsigned long lastWarnBeep = 0;
            if (homeMode == 0 && now - lastWarnBeep > 1000) {
                tone(BUZZER_PIN, 3000, 100); lastWarnBeep = now;
            }
        }
    }
}

void drawStatusBar() {
    tft.fillRect(2, 2, 85, 12, bgCol);
    uint16_t bCol = batterySaver ? C_YELLOW : C_GREEN;
    if (virtualBattery <= 20) bCol = C_RED;
    tft.drawRect(5, 4, 20, 8, textDimCol);
    tft.fillRect(25, 6, 2, 4, textDimCol);
    int bars = (int)(virtualBattery / 25.0);
    for (int i = 0; i < 4; i++) {
        if (i < bars) tft.fillRect(7 + (i * 4), 6, 3, 4, bCol);
    }
    tft.setTextColor(textCol); tft.setTextSize(1); tft.setCursor(32, 4);
    int mins = (int)(virtualBattery * (batterySaver ? 1.2 : 0.65));
    tft.printf("%dm", mins);
    if (batterySaver && !showPopup) {
        tft.fillRect(240, 2, 75, 12, bgCol);
        tft.setTextColor(C_YELLOW); tft.setCursor(245, 4);
        tft.print("[ECO MODE]");
    }
}

// ============================================================
// GEIGER COUNTER
// ============================================================
void runGeigerCounter() {
    if (homeMode == 1) return;
    int signalStrength = -100;

    if (curPage == PG_RF && rfMode == 4) {
        int maxE = 0;
        if (jamming && lastPeakChannel != -1) maxE = smoothEnergy[lastPeakChannel];
        else for (int i = 0; i < TOTAL_CHANNELS; i++) if (smoothEnergy[i] > maxE) maxE = smoothEnergy[i];
        if (maxE > 2) signalStrength = map(constrain(maxE, 0, 30), 0, 30, -90, -30);
    }
    else if (curPage == PG_WIFI && wifiMode == 3 && wCount > 0) {
        for (int i = 0; i < wCount; i++) if (wNets[i].rssi > signalStrength) signalStrength = wNets[i].rssi;
    }
    else if (curPage == PG_BT && btMode == 2) {
        // FIX: read bCount2 under mutex
        int localCount = 0;
        if (xSemaphoreTake(bleMutex, pdMS_TO_TICKS(5)) == pdTRUE) {
            localCount = bCount2;
            for (int i = 0; i < localCount; i++) if (bDevs[i].rssi > signalStrength) signalStrength = bDevs[i].rssi;
            xSemaphoreGive(bleMutex);
        }
    }

    static unsigned long lastDirUpdate = 0;
    static int lastSig = -100;
    if (millis() - lastDirUpdate > 800) {
        if      (signalStrength > lastSig + 2) strncpy(foxDir, ">>> HOT >>>",  15);
        else if (signalStrength < lastSig - 2) strncpy(foxDir, "<< COLD <<",   15);
        else                                   strncpy(foxDir, "=== HOLD ===", 15);
        foxDir[15] = '\0';
        lastSig = signalStrength;
        lastDirUpdate = millis();
    }
    currentFoxSig = signalStrength;

    if (signalStrength > -95) {
        int interval = map(constrain(signalStrength, -90, -30), -90, -30, 1200, 40);
        if (millis() - lastGeigerTick > (unsigned long)interval) {
            tone(BUZZER_PIN, 4000, 10);
            lastGeigerTick = millis();
        }
    }
}

// ============================================================
// POPUPS
// ============================================================
void triggerPopup(const char* t, const char* l1, const char* l2, const char* ind) {
    strncpy(popT,   t,   31); popT[31]   = '\0';
    strncpy(popL1,  l1,  31); popL1[31]  = '\0';
    strncpy(popL2,  l2,  31); popL2[31]  = '\0';
    strncpy(popInd, ind,  7); popInd[7]  = '\0';
    showPopup = true; popupTimer = millis(); needRedraw = true;
}

void drawPopup() {
    int w = 260, h = 80, x = (320 - w) / 2, y = (240 - h) / 2 - 10;
    tft.fillRoundRect(x,   y,   w,   h,   8, panelCol);
    tft.drawRoundRect(x,   y,   w,   h,   8, C_CYAN);
    tft.drawRoundRect(x+1, y+1, w-2, h-2, 8, C_CYAN);
    tft.setTextColor(C_YELLOW); tft.setTextSize(1);
    tft.setCursor(x + w - 30, y + 8); tft.print(popInd);
    drawCenteredText(popT,  y + 20, 2, C_CYAN);
    drawCenteredText(popL1, y + 45, 1, textCol);
    drawCenteredText(popL2, y + 60, 1, textDimCol);
}

void drawFeaturePrompt(int current, int total) {
    if (total == 0) return;
    if (!showPopup && millis() - pageEntryTime > 7000) {
        tft.fillRect(240, 16, 75, 12, bgCol);
        tft.setTextColor(textDimCol); tft.setTextSize(1);
        tft.setCursor(245, 18); tft.printf("Hold: %d/%d", current + 1, total);
    }
}

// ============================================================
// DETECTION ENGINE
// ============================================================
void runDetection() {
    int rcHits = 0, evenHits = 0, oddHits = 0, nonRcActive = 0;
    int peakContig = 0, curPeakContig = 0, bestWiFiCenter = 0;
    int peakChannel = -1, maxEnergyInPass = 0;
    int anomalyScore = 0;
    activeCount = 0;
    float totalE = 0, totalDev = 0;

    int actualPasses = scanPass > 0 ? scanPass : 1;
    float scaleMultiplier = (float)SCAN_PASSES / actualPasses;
    // FIX: cap multiplier — prevents single-pass early trigger from saturating smooth buffer
    if (scaleMultiplier > SCALE_MULT_CAP) scaleMultiplier = SCALE_MULT_CAP;

    for (int ch = 0; ch < TOTAL_CHANNELS; ch++) {
        float tempE = energy[ch] * scaleMultiplier;
        uint8_t scaledE = (uint8_t)(tempE > 255.0f ? 255 : tempE);

        if (scaledE > smoothEnergy[ch])  smoothEnergy[ch] = scaledE;
        else smoothEnergy[ch] = (smoothEnergy[ch] * 2 + scaledE) / 3;
        if (scaledE == 0)                smoothEnergy[ch] = smoothEnergy[ch] / 2;
        if (smoothEnergy[ch] <= 3)       smoothEnergy[ch] = 0;

        totalE   += smoothEnergy[ch];
        totalDev += abs(smoothEnergy[ch] - (int)noiseFloor[ch]);

        if (smoothEnergy[ch] > (uint8_t)peakEnergy[ch]) {
            peakEnergy[ch] = smoothEnergy[ch]; peakTime[ch] = millis();
        } else if (rfMode != 3 && millis() - peakTime[ch] > PEAK_HOLD_MS) {
            if (peakEnergy[ch] > 0) peakEnergy[ch]--;
        }
        if (smoothEnergy[ch] > (uint8_t)maxEnergyInPass) {
            maxEnergyInPass = smoothEnergy[ch]; peakChannel = ch;
        }

        int deviation = (int)smoothEnergy[ch] - (int)noiseFloor[ch];
        if (deviation > 3) anomalyScore += deviation;  // FIX: used below

        if (smoothEnergy[ch] >= ((int)noiseFloor[ch] + DETECT_THRESHOLD)) {
            activeCount++;
            if (ch >= 84) rcHits++;
            else { nonRcActive++; if (ch % 2 == 0) evenHits++; else oddHits++; }
        }
        if (ch < 84) {
            if (peakEnergy[ch] >= ((int)noiseFloor[ch] + DETECT_THRESHOLD)) {
                curPeakContig++;
                if (curPeakContig > peakContig) {
                    peakContig = curPeakContig;
                    bestWiFiCenter = ch - (peakContig / 2);
                }
            } else curPeakContig = 0;
        }
    }

    float entropy = 0;
    if (totalE > 0) {
        for (int i = 0; i < TOTAL_CHANNELS; i++) {
            float p = smoothEnergy[i] / totalE;
            if (p > 0) entropy -= p * log(p);
        }
    }
    // FIX: anomalyScore now contributes — high deviation with low activeCount
    // accelerates anomalyHist faster, improving anomaly detection sensitivity
    bool highEntropy = (entropy > 3.8 && activeCount > 20) ||
                       (anomalyScore > 200 && activeCount < 15);

    if (peakChannel != -1 && maxEnergyInPass > 5) {
        if (lastSweepPeak != -1) {
            int delta = peakChannel - lastSweepPeak;
            if (abs(delta) >= 4 && abs(delta) <= 15) {
                int dir = (delta > 0) ? 1 : -1;
                if (dir == sweepDirection) sweepCount++;
                else { sweepDirection = dir; sweepCount = 1; }
            } else if (abs(delta) > 15) {
                sweepCount = 0;
            }
        }
        lastSweepPeak = peakChannel;
    }
    bool isSweepAttack = (sweepCount > 6);

    if (peakChannel != -1 && maxEnergyInPass > 5 && lastPeakChannel != -1) {
        int dist = abs(peakChannel - lastPeakChannel);
        if (dist > 15) { hopCounter++; hopDistanceSum += dist; }
    }
    lastPeakChannel = peakChannel;
    if (millis() - lastHopReset > 2000) {
        hopCounter = 0; hopDistanceSum = 0; sweepCount = 0; lastHopReset = millis();
    }

    stabilityBuffer[stabilityIndex++] = maxEnergyInPass;
    if (stabilityIndex >= 8) stabilityIndex = 0;
    int avg = 0, variance = 0;
    for (int i = 0; i < 8; i++) avg += stabilityBuffer[i]; avg /= 8;
    for (int i = 0; i < 8; i++) variance += abs(stabilityBuffer[i] - avg);
    stableSignal = (variance < 4 && avg > 8);

    int deltaPeak = abs(maxEnergyInPass - lastSignalForLens);
    if (stableSignal && deltaPeak > 8 && maxEnergyInPass > 15) {
        reflectionSpike++;
        // FIX: cap reflectionSpike — prevents int overflow on continuous stable signal
        if (reflectionSpike > 20) reflectionSpike = 20;
    } else if (reflectionSpike > 0) reflectionSpike--;
    lastSignalForLens = maxEnergyInPass;

    totalDev /= TOTAL_CHANNELS;
    if (totalDev > 4 && activeCount < 10) deviationScore++;
    else if (deviationScore > 0) deviationScore--;

    static unsigned long lastBurstAlert = 0;
    if (deviationScore > 5 && millis() - lastBurstAlert > 5000) {
        addAlert("Burst Transmitter", "RF Disturbance");
        lastBurstAlert = millis();
    }

    activePct = (activeCount * 100.0f) / TOTAL_CHANNELS;
    if (!jamming && activePct < 5.0f && maxEnergyInPass < 5) {
        for (int ch = 0; ch < TOTAL_CHANNELS; ch++)
            noiseFloor[ch] = (noiseFloor[ch] * 63.0f + (float)smoothEnergy[ch]) / 64.0f;
    }

    if (activeCount < 3 && (millis() - lastJamDetectTime > 1000)) {
        wifiHist = btHist = bleHist = rcHist = anomalyHist = sweepHist = 0;
    }

    wifiCount = peakContig; btCount = nonRcActive; bleCount = evenHits; rcCount = rcHits;

    bool isDeauth = (wifiCount >= 10 && wifiHist >= 3 && activePct >= 25 && btCount < 20);
    bool isDrone  = (!isDeauth && hopCounter >= 5 && hopDistanceSum >= 80 && activePct < 40);
    bool isRC     = (!isDeauth && !isDrone && rcCount >= 3 && activePct > 30);
    bool isWiFi   = (!isDeauth && !isDrone && !isRC && wifiCount >= 10 &&
                     peakEnergy[bestWiFiCenter] >= ((int)noiseFloor[bestWiFiCenter] + DETECT_THRESHOLD * 2));
    bool isBLE    = (!isDeauth && !isDrone && !isRC && !isWiFi &&
                     bleCount >= 10 && oddHits <= (evenHits / 2 + 4));
    bool isBT     = (!isDeauth && !isDrone && !isRC && !isWiFi && !isBLE && btCount >= 15);

    if (isRC)    rcHist++;    else rcHist    = 0;
    if (isWiFi)  wifiHist++;  else wifiHist  = 0;
    if (isBLE)   bleHist++;   else bleHist   = 0;
    if (isBT)    btHist++;    else btHist    = 0;
    if (highEntropy) anomalyHist++; else anomalyHist = 0;
    if (isSweepAttack) sweepHist++; else sweepHist   = 0;

    JamType newType = JAM_NONE;
    if      (isInstantJam)   newType = JAM_BROADBAND;
    else if (isDeauth)       newType = JAM_WIFI_DEAUTH;
    else if (isDrone)        newType = JAM_DRONE_FHSS;
    else if (sweepHist >= 2) newType = JAM_SWEEP;
    else if (anomalyHist > 2)newType = JAM_ANOMALY;
    else if (rcHist >= 2)    newType = JAM_RC;
    else if (wifiHist >= 2)  newType = JAM_WIFI;
    else if (bleHist >= 2)   newType = JAM_BLE;
    else if (btHist >= 2)    newType = JAM_BT;

    isInstantJam = false;
    prevJamming  = jamming;

    if (newType != JAM_NONE) {
        lastJamDetectTime = millis();
        heldJamType = newType;
        jamming = true; jamType = newType;
    } else {
        if (millis() - lastJamDetectTime < 1000) { jamming = true; jamType = heldJamType; }
        else { jamming = false; jamType = JAM_NONE; }
    }

    if (jamming && !prevJamming) {
        // FIX: overflow protection on totalAlerts
        if (totalAlerts < 99999) totalAlerts++;
        addAlert(jamLabel(jamType), "RF Threat");
        buzzerStartAlarm(jamType);
    } else if (!jamming && prevJamming) {
        buzzerStopAlarm();
    } else if (jamming && jamType != alarmJamType) {
        alarmJamType = jamType;
    }

    static int lastThreatLevel = -1;
    int curThreatLevel = jamming ? 3 :
        (activePct >= 60 ? 3 : (activePct >= 30 ? 2 : (activePct >= 10 ? 1 : 0)));
    if (curThreatLevel != lastThreatLevel || jamming != prevJamming) {
        needRedraw = true; lastThreatLevel = curThreatLevel;
    }
}

void triggerBeep(int duration, int freq) {
    if (homeMode == 1) return;
    tone(BUZZER_PIN, freq); buzzerIsOn = true;
    buzzerOffTime = millis() + duration;
}

void buzzerUpdate() {
    if (!alarmActive || homeMode == 1) return;
    unsigned long now = millis(); unsigned long interval;
    if      (activePct >= 70) interval = 150;
    else if (activePct >= 45) interval = 300;
    else if (activePct >= 25) interval = 600;
    else                      interval = 1000;
    if (now - lastAlarmTick < interval) return;
    lastAlarmTick = now; alarmRepeat++;
    switch (alarmJamType) {
        case JAM_WIFI_DEAUTH: case JAM_DRONE_FHSS: case JAM_SWEEP:
            if (alarmPhase % 2 == 0) triggerBeep(interval - 20, 3800);
            else                     triggerBeep(interval - 20, 4200);
            break;
        default:
            if (alarmPhase % 2 == 0) triggerBeep(interval - 20, 2730);
            else                     triggerBeep(interval - 20, 4000);
            break;
    }
    alarmPhase++;
}

void buzzerStartAlarm(JamType j) {
    alarmActive = true; alarmJamType = j; alarmPhase = 0; alarmRepeat = 0; lastAlarmTick = 0;
}
void buzzerStopAlarm() {
    alarmActive = false; alarmPhase = 0; alarmRepeat = 0;
    noTone(BUZZER_PIN); buzzerIsOn = false;
}

// FIX: returns const char* instead of String — eliminates heap allocation on every call
const char* jamLabel(JamType j) {
    switch (j) {
        case JAM_WIFI_DEAUTH: return "WiFi_Deauth_Flood";
        case JAM_DRONE_FHSS:  return "Drone_FHSS_Link";
        case JAM_SWEEP:       return "RF_Sweep_Jammer";
        case JAM_ANOMALY:     return "High_Entropy_Noise";
        case JAM_BROADBAND:   return "Broadband_Jammer";
        case JAM_RC:          return "RC_Drones_1-125_CH";
        case JAM_BT:          return "Bluetooth_80_CH";
        case JAM_BLE:         return "BLE_40_CH";
        case JAM_BT_WIFI:     return "BT-WiFi_14-80_CH";
        case JAM_WIFI:        return "WiFi_14_CH";
        default:              return "None";
    }
}

void addAlert(const char* t, const char* d) {
    for (int i = 4; i > 0; i--) alerts[i] = alerts[i - 1];
    strncpy(alerts[0].type,   t, 19); alerts[0].type[19]   = '\0';
    strncpy(alerts[0].detail, d, 27); alerts[0].detail[27] = '\0';
    alerts[0].ts = millis() / 1000;
    if (alertCount < 5) alertCount++;
}

bool checkCameraOUI(const char* mac) {
    // FIX: expanded OUI table
    if (strncmp(mac, "EC:FA:BC", 8) == 0) return true; // Hikvision
    if (strncmp(mac, "AC:64:62", 8) == 0) return true; // Hikvision
    if (strncmp(mac, "44:65:0D", 8) == 0) return true; // Dahua
    if (strncmp(mac, "70:8A:09", 8) == 0) return true; // Reolink
    if (strncmp(mac, "9C:8E:CD", 8) == 0) return true; // Wyze
    if (strncmp(mac, "2C:AA:8E", 8) == 0) return true; // TP-Link Tapo
    if (strncmp(mac, "50:C7:BF", 8) == 0) return true; // Ezviz
    return false;
}

bool checkTrackerOUI(const char* mac, const char* name) {
    if (strncmp(mac, "00:25:96", 8) == 0) return true; // Apple AirTag OUI
    if (strncmp(mac, "7C:D1:C3", 8) == 0) return true; // Tile
    // FIX: replaced String heap allocation with char array + tolower loop
    char lower[32];
    int i;
    for (i = 0; i < 31 && name[i]; i++) lower[i] = (char)tolower((unsigned char)name[i]);
    lower[i] = '\0';
    if (strstr(lower, "smarttag")) return true;
    if (strstr(lower, "airtag"))   return true;
    if (strstr(lower, "findmy"))   return true;
    if (strstr(lower, "tile"))     return true;
    if (strstr(lower, "chipolo")) return true;
    return false;
}

// ============================================================
// UI RENDERING
// ============================================================
void redrawPage() {
    static Page lastDrawnPage = PG_COUNT;
    bool isNewPage = (curPage != lastDrawnPage);
    if (isNewPage || curPage != PG_RF) {
        tft.fillScreen(bgCol);
        drawNav(curPage);
        lastDrawnPage = curPage;
    }
    switch (curPage) {
        case PG_HOME: drawHome(); break;
        case PG_RF:   if (isNewPage) drawRF_Static(); break;
        case PG_WIFI: drawWifi(); break;
        case PG_BT:   drawBT();   break;
        case PG_IDS:  drawIDS();  break;
        case PG_SYS:  drawSys();  break;
        default: break;
    }
    // FIX: removed drawFeaturePrompt(0,0) dead call — total==0 caused immediate return
    if (showPopup) drawPopup();
}

void drawNav(Page p) {
    const char*  L[PG_COUNT] = {"HOME", "RF", "WiFi", "BT", "IDS", "SYS"};
    uint16_t     C[PG_COUNT] = {textCol, C_RED, C_CYAN, C_PURPLE, C_ORANGE, textDimCol};
    int bw = 320 / PG_COUNT;
    for (int i = 0; i < PG_COUNT; i++) {
        bool on = (i == (int)p);
        tft.fillRect(i * bw, 215, bw - 1, 25, on ? C[i] : panelCol);
        if (on) tft.drawRect(i * bw, 215, bw - 1, 25, textCol);
        int textX = i * bw + (bw - (strlen(L[i]) * 6)) / 2;
        tft.setTextColor(on ? bgCol : C[i]);
        tft.setTextSize(1);
        tft.setCursor(textX, 223);
        tft.print(L[i]);
    }
    tft.drawFastHLine(0, 214, 320, textDimCol);
}

void drawHome() {
    drawCenteredText("WATCHDOG 2.4", 16, 2, C_CYAN);
    drawCenteredText("Security Analyser v3.1 STABLE", 36, 1, textDimCol);
    tft.drawFastHLine(0, 47, 320, textDimCol);

    const char* lbl; uint16_t col; int pct = (int)activePct;
    if      (jamming)  { lbl = "CRITICAL"; col = C_RED;    }
    else if (pct < 10) { lbl = "LOW";      col = C_GREEN;  }
    else if (pct < 30) { lbl = "MEDIUM";   col = C_YELLOW; }
    else if (pct < 60) { lbl = "HIGH";     col = C_ORANGE; }
    else               { lbl = "CRITICAL"; col = C_RED;    }

    tft.setTextColor(textCol); tft.setTextSize(1);
    tft.setCursor(10, 52); tft.print("THREAT LEVEL:");
    tft.setTextColor(col); tft.setTextSize(3); tft.setCursor(10, 64); tft.print(lbl);
    tft.setTextSize(1); tft.setTextColor(textCol);
    tft.setCursor(10, 104); tft.printf("Active: %d/125 (%.0f%%)", activeCount, activePct);
    tft.drawRect(10, 116, 200, 10, textCol);
    int bw = map(pct, 0, 100, 0, 198); if (bw > 0) tft.fillRect(11, 117, bw, 8, col);
    if      (homeMode == 1) { tft.setTextColor(textDimCol); tft.setCursor(215, 116); tft.print("MUTED"); }
    else if (alarmActive)   { tft.setTextColor(C_RED);      tft.setCursor(215, 116); tft.print("ALARM ON"); }

    tft.drawFastHLine(0, 134, 320, textDimCol);
    auto stat = [&](int y, const char* l, int v, uint16_t vc) {
        tft.setTextColor(textCol); tft.setCursor(10, y); tft.print(l);
        tft.setTextColor(vc); tft.setCursor(130, y); tft.println(v);
    };
    stat(140, "RF Alerts:",       totalAlerts, totalAlerts > 0 ? C_RED : C_GREEN);
    stat(154, "WiFi Nets:",       wCount,      textCol);
    stat(168, "Suspicious Cams:", wCams,       wCams > 0 ? C_RED : C_GREEN);

    // FIX: read bCount2/bTrackers under mutex
    int localBCount = 0, localBTrackers = 0;
    if (xSemaphoreTake(bleMutex, pdMS_TO_TICKS(5)) == pdTRUE) {
        localBCount    = bCount2;
        localBTrackers = bTrackers;
        xSemaphoreGive(bleMutex);
    }
    stat(182, "BT Devices:", localBCount,    textCol);
    stat(196, "Trackers:",   localBTrackers, localBTrackers > 0 ? C_RED : C_GREEN);

    if (jamming) {
        tft.fillRect(175, 138, 140, 72, C_DRED);
        tft.drawRect(175, 138, 140, 72, C_RED);
        tft.setTextColor(C_WHITE); tft.setTextSize(1);
        tft.setCursor(183, 144); tft.print("!! JAMMING !!");
        tft.setCursor(183, 159); tft.print(jamLabel(jamType));
        tft.setCursor(183, 174); tft.printf("Active: %.0f%%", activePct);
    } else {
        tft.fillRect(175, 138, 140, 72, C_DGREEN);
        tft.drawRect(175, 138, 140, 72, C_GREEN);
        tft.setTextColor(C_WHITE); tft.setTextSize(1);
        tft.setCursor(200, 158); tft.print("ALL CLEAR");
        tft.setCursor(187, 173); tft.print("Monitoring...");
    }
    drawFeaturePrompt(homeMode, 3);
}

void updateHomeBar() {
    int pct = (int)activePct; uint16_t col = C_GREEN;
    if      (jamming)   col = C_RED;
    else if (pct >= 60) col = C_RED;
    else if (pct >= 30) col = C_ORANGE;
    else if (pct >= 10) col = C_YELLOW;
    tft.fillRect(11, 117, 198, 8, bgCol);
    int bw = map(pct, 0, 100, 0, 198);
    if (bw > 0) tft.fillRect(11, 117, bw, 8, col);
}

void drawRF_Static() {
    drawCenteredText("RF SPECTRUM  2.400-2.525 GHz", 16, 1, C_RED);
    tft.drawFastHLine(0, 26, 320, textDimCol);
    tft.setTextColor(textDimCol);
    tft.setCursor(302, 30);  tft.print("Hi");
    tft.setCursor(302, 94);  tft.print("Md");
    tft.setCursor(302, 163); tft.print("Lo");
    tft.drawFastHLine(0, 173, 320, textDimCol);

    int xBLE  = map(39, 0, TOTAL_CHANNELS, 0, 298);
    int xBT   = map(79, 0, TOTAL_CHANNELS, 0, 298);
    int xWifi = map(13, 0, TOTAL_CHANNELS, 0, 298);
    tft.drawFastVLine(xWifi, 173, 12, C_CYAN);
    tft.drawFastVLine(xBLE,  173, 12, C_PURPLE);
    tft.drawFastVLine(xBT,   173, 12, C_ORANGE);
    tft.setTextColor(C_CYAN);   tft.setCursor(2,          178); tft.print("2400");
    tft.setTextColor(C_PURPLE); tft.setCursor(xBLE - 14,  178); tft.print("2483");
    tft.setTextColor(C_ORANGE); tft.setCursor(xBT  - 14,  178); tft.print("2500");
    tft.setTextColor(textDimCol); tft.setCursor(292,       178); tft.print("MHz");

    tft.drawFastHLine(0, 188, 320, textDimCol);
    tft.fillRect(2,   190, 8, 6, C_PURPLE); tft.setTextColor(C_PURPLE); tft.setCursor(12,  190); tft.print("BLE");
    tft.fillRect(44,  190, 8, 6, C_ORANGE); tft.setTextColor(C_ORANGE); tft.setCursor(54,  190); tft.print("BT");
    tft.fillRect(78,  190, 8, 6, C_CYAN);   tft.setTextColor(C_CYAN);   tft.setCursor(88,  190); tft.print("WiFi");
    tft.fillRect(122, 190, 8, 6, C_RED);    tft.setTextColor(C_RED);    tft.setCursor(132, 190); tft.print("RC");
}

void drawRF_Dynamic() {
    if (rfMode != 2) updateRFBars();
    tft.fillRect(0, 200, 160, 14, bgCol);

    if      (rfMode == 1) { tft.setTextColor(C_RED);    tft.setCursor(5, 203); tft.print("[JAMMING FOCUS]"); }
    else if (rfMode == 2) { tft.setTextColor(C_YELLOW); tft.setCursor(5, 203); tft.print("[PAUSED]"); }
    else if (rfMode == 3) { tft.setTextColor(C_ORANGE); tft.setCursor(5, 203); tft.print("[MAX HOLD]"); }
    else if (rfMode == 4) { tft.setTextColor(C_RED);    tft.setCursor(5, 203); tft.print("[FOXHUNT GEIGER]"); }
    else if (rfMode == 5) {
        if (reflectionSpike > 4) { tft.setTextColor(C_RED);  tft.setCursor(5, 203); tft.print("[LENS FOUND!]"); }
        else                     { tft.setTextColor(C_CYAN); tft.setCursor(5, 203); tft.print("[LENS SCAN] Sweep..."); }
    }
    else {
        tft.setTextColor(jamming ? C_RED : C_GREEN);
        tft.setCursor(5, 203);
        if (jamming) {
            // FIX: replaced String concatenation with snprintf — no heap alloc
            char jbuf[32];
            snprintf(jbuf, 32, "!! %s", jamLabel(jamType));
            tft.print(jbuf);
        } else {
            tft.print("Clean spectrum");
        }
    }

    tft.fillRect(220, 200, 100, 14, bgCol);
    tft.setTextColor(textCol); tft.setCursor(220, 203);
    tft.printf("Act: %.0f%%", activePct);

    if (rfMode == 4) {
        tft.fillRect(180, 30, 135, 30, bgCol);
        tft.drawRect(180, 30, 135, 30, C_RED);
        tft.setTextColor(textCol); tft.setCursor(185, 34);
        if (jamming) tft.print("TGT: JAMMER"); else tft.print("TGT: PEAK CH");
        tft.setCursor(185, 48); tft.setTextColor(C_YELLOW);
        tft.printf("%s %ddB", foxDir, currentFoxSig);
    } else {
        tft.fillRect(160, 190, 160, 10, bgCol);
        if (stableSignal && rfMode == 0 && !jamming) {
            tft.setTextColor(C_ORANGE); tft.setCursor(160, 190); tft.print("Fixed Tx Detected");
        } else if (deviationScore > 5 && !jamming) {
            tft.setTextColor(C_YELLOW); tft.setCursor(160, 190); tft.print("Burst Tx!");
        }
    }
    drawFeaturePrompt(rfMode, 6);
}

void updateRFBars() {
    const int Y_TOP  = 28;
    const int Y_BASE = 172;
    const int BAR_AREA = Y_BASE - Y_TOP;
    for (int ch = 0; ch < TOTAL_CHANNELS; ch++) {
        if (rfMode == 1 && smoothEnergy[ch] < EARLY_JAM_THRESHOLD &&
            peakEnergy[ch] < EARLY_JAM_THRESHOLD) continue;
        if (smoothEnergy[ch] == prevEnergy[ch] && peakEnergy[ch] == prevPeak[ch]) continue;
        prevEnergy[ch] = smoothEnergy[ch]; prevPeak[ch] = peakEnergy[ch];
        int x = map(ch, 0, TOTAL_CHANNELS, 0, 298);
        tft.fillRect(x, Y_TOP, 2, BAR_AREA, bgCol);
        tft.drawFastHLine(x, Y_TOP + 48, 2, panelCol);
        tft.drawFastHLine(x, Y_TOP + 96, 2, panelCol);
        int pct = constrain((smoothEnergy[ch] * 100) / SCAN_PASSES, 0, 100);
        int h   = map(pct, 0, 100, 0, BAR_AREA);
        uint16_t barColour = (pct >= 90) ? C_RED :
                             (pct >= 76) ? C_ORANGE :
                             (pct >= 56) ? C_YELLOW :
                             (pct >= 31) ? C_LIME : C_DBLUE;
        if (h > 0) tft.fillRect(x, Y_BASE - h, 2, h, barColour);
        int peakH = map(constrain((peakEnergy[ch] * 100) / SCAN_PASSES, 0, 100), 0, 100, 0, BAR_AREA);
        if (peakH > h && peakH > 2) tft.fillRect(x, Y_BASE - peakH, 2, 2, textCol);
    }
}

void drawWifi() {
    if      (wifiMode == 0) drawCenteredText("WiFi SCANNER (ALL NETWORKS)",  16, 1, C_CYAN);
    else if (wifiMode == 1) drawCenteredText("WiFi (SUSPICIOUS CAMERAS)",    16, 1, C_CYAN);
    else if (wifiMode == 2) drawCenteredText("WiFi SPECTRUM CONGESTION",     16, 1, C_CYAN);
    else if (wifiMode == 3) drawCenteredText("WiFi FOXHUNT TRACKER",         16, 1, C_CYAN);

    tft.setCursor(5, 27); tft.setTextColor(textCol);
    tft.printf("Found:%d  Open:", wCount);
    tft.setTextColor(wOpen > 0 ? C_RED : C_GREEN); tft.printf("%d  ", wOpen);
    tft.setTextColor(textCol); tft.print("Cams:");
    tft.setTextColor(wCams > 0 ? C_RED : C_GREEN); tft.printf("%d", wCams);
    tft.drawFastHLine(0, 37, 320, textDimCol);

    if (batterySaver) {
        drawCenteredText("SCANNER PAUSED", 100, 2, C_YELLOW);
        drawCenteredText("ECO Mode Active. Hold 5s to unlock.", 125, 1, textDimCol);
        return;
    }

    if (wifiMode == 0 || wifiMode == 1) {
        tft.setTextColor(textDimCol); tft.setCursor(5,   40); tft.print("SSID");
        tft.setCursor(185, 40); tft.print("RSSI");
        tft.setCursor(225, 40); tft.print("CH");
        tft.setCursor(260, 40); tft.print("SEC");
        tft.drawFastHLine(0, 49, 320, panelCol);
        int drawn = 0;
        for (int i = 0; i < wCount && drawn < 9; i++) {
            if (wifiMode == 1 && !wNets[i].open && !wNets[i].twin && !wNets[i].isCam) continue;
            int y = 53 + drawn * 17;
            if (wNets[i].isCam) tft.fillRect(0, y - 1, 320, 16, C_HIGHLIGHT_ROW);
            uint16_t nc = wNets[i].isCam  ? C_RED    :
                          wNets[i].twin   ? C_ORANGE :
                          wNets[i].open   ? C_YELLOW : textCol;
            tft.setTextColor(nc); tft.setCursor(5, y + 3);
            char s[20]; strncpy(s, wNets[i].ssid, 16); s[16] = '\0';
            if (strlen(wNets[i].ssid) > 16) strcat(s, "..");
            tft.print(s);
            tft.setTextColor(wNets[i].rssi > -60 ? C_GREEN :
                             wNets[i].rssi > -75 ? C_YELLOW : C_RED);
            tft.setCursor(185, y + 3); tft.print(wNets[i].rssi);
            tft.setTextColor(textCol); tft.setCursor(225, y + 3); tft.print(wNets[i].ch);
            tft.setTextColor(wNets[i].open ? C_RED : C_GREEN);
            tft.setCursor(260, y + 3); tft.print(wNets[i].open ? "OPEN" : "ENC");
            drawn++;
        }
        if (drawn == 0) drawCenteredText("No targets found.", 110, 1, textDimCol);
    }
    else if (wifiMode == 2) {
        int chCounts[15] = {0}; int maxStack = 1;
        for (int i = 0; i < wCount; i++) {
            if (wNets[i].ch >= 1 && wNets[i].ch <= 14) {
                chCounts[wNets[i].ch]++;
                if (chCounts[wNets[i].ch] > maxStack) maxStack = chCounts[wNets[i].ch];
            }
        }
        for (int c = 1; c <= 14; c++) {
            int x = 8 + ((c - 1) * 22);
            int h = map(chCounts[c], 0, maxStack, 0, 140);
            if (h > 0) {
                uint16_t barCol = (chCounts[c] >= 5) ? C_RED :
                                  (chCounts[c] >= 3) ? C_YELLOW : C_CYAN;
                tft.fillRect(x, 195 - h, 14, h, barCol);
                tft.setTextColor(textCol); tft.setCursor(x + 2, 182 - h); tft.print(chCounts[c]);
            }
            tft.setTextColor(textDimCol);
            tft.setCursor(x + (c > 9 ? 0 : 3), 205); tft.print(c);
        }
    }
    else if (wifiMode == 3) {
        if (wCount == 0) {
            drawCenteredText("No targets in range.", 110, 1, textDimCol);
        } else {
            int bestIdx = 0, maxRssi = -100;
            for (int i = 0; i < wCount; i++) if (wNets[i].rssi > maxRssi) { maxRssi = wNets[i].rssi; bestIdx = i; }
            tft.setTextColor(C_CYAN); tft.setTextSize(2); tft.setCursor(10, 60); tft.print("TARGET:");
            tft.setTextColor(textCol); tft.setCursor(10, 85); tft.print(wNets[bestIdx].ssid);
            int w = constrain(map(maxRssi, -90, -45, 0, 300), 0, 300);
            uint16_t c = (maxRssi < -75) ? C_RED : (maxRssi < -60) ? C_YELLOW : C_GREEN;
            tft.drawRect(10, 130, 300, 30, textCol); tft.fillRect(10, 130, w, 30, c);
            tft.setTextColor(textCol); tft.setTextSize(1);
            tft.setCursor(10, 170); tft.printf("Distance (RSSI): %d dBm", maxRssi);
        }
    }
    drawFeaturePrompt(wifiMode, 5);
}

void drawBT() {
    if      (btMode == 0) drawCenteredText("BLUETOOTH MAPPER (ALL DEV)", 16, 1, C_PURPLE);
    else if (btMode == 1) drawCenteredText("BLUETOOTH (TRACKERS ONLY)", 16, 1, C_PURPLE);
    else if (btMode == 2) drawCenteredText("BLUETOOTH FOXHUNT",         16, 1, C_PURPLE);

    // FIX: snapshot under mutex before drawing
    int localCount = 0, localTrackers = 0;
    BDev localDevs[20];
    if (xSemaphoreTake(bleMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
        localCount    = bCount2;
        localTrackers = bTrackers;
        memcpy(localDevs, bDevs, sizeof(BDev) * min(localCount, 20));
        xSemaphoreGive(bleMutex);
    }

    tft.setCursor(5, 27); tft.setTextColor(textCol);
    tft.printf("Devices:%d  Trackers:", localCount);
    tft.setTextColor(localTrackers > 0 ? C_RED : C_GREEN); tft.printf("%d", localTrackers);
    tft.drawFastHLine(0, 37, 320, textDimCol);

    if (batterySaver) {
        drawCenteredText("SCANNER PAUSED", 100, 2, C_YELLOW);
        drawCenteredText("ECO Mode Active. Hold 5s to unlock.", 125, 1, textDimCol);
        return;
    }

    if (btMode == 0 || btMode == 1) {
        tft.setTextColor(textDimCol);
        tft.setCursor(5,   40); tft.print("NAME/MAC");
        tft.setCursor(148, 40); tft.print("RSSI");
        tft.setCursor(242, 40); tft.print("SIGNAL");
        tft.drawFastHLine(0, 49, 320, panelCol);
        int show = 0;
        for (int i = 0; i < localCount && show < 9; i++) {
            if (btMode == 1 && !localDevs[i].sus && !localDevs[i].isTracker) continue;
            int y = 53 + show * 17;
            if (localDevs[i].isTracker) tft.fillRect(0, y - 1, 320, 16, C_HIGHLIGHT_ROW);
            tft.setTextColor(localDevs[i].isTracker ? C_RED : textCol);
            char nm[18]; strncpy(nm, localDevs[i].name, 17); nm[17] = '\0';
            tft.setCursor(5, y + 3); tft.print(nm);
            tft.setTextColor(localDevs[i].rssi > -60 ? C_GREEN :
                             localDevs[i].rssi > -75 ? C_YELLOW : C_RED);
            tft.setCursor(148, y + 3); tft.print(localDevs[i].rssi);
            int bars = 1;
            if      (localDevs[i].rssi > -60) bars = 5;
            else if (localDevs[i].rssi > -70) bars = 4;
            else if (localDevs[i].rssi > -80) bars = 3;
            else if (localDevs[i].rssi > -90) bars = 2;
            uint16_t bColActive = (bars == 5) ? C_GREEN  : (bars == 4) ? C_LIME :
                                  (bars == 3) ? C_YELLOW : (bars == 2) ? C_ORANGE : C_RED;
            for (int b = 0; b < 5; b++) {
                uint16_t bCol = (b < bars) ? bColActive : panelCol;
                tft.fillRect(242 + (b * 6), (y + 11) - (4 + (b * 2)), 4, (4 + (b * 2)), bCol);
            }
            show++;
        }
        if (show == 0) drawCenteredText("No targets found.", 110, 1, textDimCol);
    }
    else if (btMode == 2) {
        if (localCount == 0) {
            drawCenteredText("No targets in range.", 110, 1, textDimCol);
        } else {
            int bestIdx = 0, maxRssi = -100;
            for (int i = 0; i < localCount; i++) if (localDevs[i].rssi > maxRssi) { maxRssi = localDevs[i].rssi; bestIdx = i; }
            tft.setTextColor(C_PURPLE); tft.setTextSize(2); tft.setCursor(10, 60); tft.print("TARGET:");
            tft.setTextColor(textCol); tft.setCursor(10, 85); tft.print(localDevs[bestIdx].name);
            int w = constrain(map(maxRssi, -90, -45, 0, 300), 0, 300);
            uint16_t c = (maxRssi < -75) ? C_RED : (maxRssi < -60) ? C_YELLOW : C_GREEN;
            tft.drawRect(10, 130, 300, 30, textCol); tft.fillRect(10, 130, w, 30, c);
            tft.setTextColor(textCol); tft.setTextSize(1);
            tft.setCursor(10, 170); tft.printf("Distance (RSSI): %d dBm", maxRssi);
        }
    }
    drawFeaturePrompt(btMode, 4);
}

void drawIDS() {
    drawCenteredText("WIRELESS IDS", 16, 1, C_ORANGE);
    tft.drawFastHLine(0, 26, 320, textDimCol);

    tft.setCursor(5, 30); tft.setTextColor(textCol); tft.print("WiFi ch:");
    tft.setTextColor(wifiCount > 6  ? C_RED : C_GREEN); tft.printf("%d  ", wifiCount);
    tft.setTextColor(textCol); tft.print("BT ch:");
    tft.setTextColor(btCount  > 35  ? C_RED : C_GREEN); tft.printf("%d  ", btCount);
    tft.setTextColor(textCol); tft.print("BLE ch:");
    tft.setTextColor(bleCount > 20  ? C_RED : C_GREEN); tft.printf("%d", bleCount);
    tft.drawFastHLine(0, 41, 320, textDimCol);

    tft.setTextColor(textCol); tft.setCursor(5, 45); tft.print("Persistence counters:");
    struct { const char* n; int v, th; } rows[5] = {
        {"WiFi hist",  wifiHist,    2},
        {"BT hist",    btHist,      2},
        {"Sweep hist", sweepHist,   2},
        {"RC hist",    rcHist,      2},
        {"RF Anomaly", anomalyHist, 2}
    };
    for (int b = 0; b < 5; b++) {
        int y = 57 + b * 17;
        tft.setTextColor(textCol); tft.setCursor(5, y); tft.printf("%-12s %d", rows[b].n, rows[b].v);
        tft.drawRect(115, y, 100, 12, textDimCol);
        int bw = min(rows[b].v * 50, 100);
        if (bw > 0) tft.fillRect(115, y, bw, 12, rows[b].v >= rows[b].th ? C_RED : C_YELLOW);
        if (rows[b].v >= rows[b].th) { tft.setTextColor(C_RED); tft.setCursor(222, y); tft.print("ALERT"); }
    }

    tft.drawFastHLine(0, 143, 320, textDimCol);
    tft.setTextColor(C_ORANGE); tft.setCursor(5, 147); tft.print("Alarm: ");
    if (alarmActive) {
        tft.setTextColor(C_RED); tft.printf("ACTIVE - %s", jamLabel(alarmJamType));
    } else {
        tft.setTextColor(C_GREEN); tft.print("Silent");
    }

    tft.drawFastHLine(0, 157, 320, textDimCol);
    tft.setTextColor(C_ORANGE); tft.setCursor(5, 161); tft.print("Recent Alerts:");
    if (!alertCount) {
        tft.setTextColor(C_GREEN); tft.setCursor(85, 178); tft.print("No alerts");
    } else {
        for (int i = 0; i < min(alertCount, 3); i++) {
            int y = 172 + i * 14;
            tft.setTextColor(C_RED);      tft.setCursor(5,   y); tft.print(alerts[i].type);
            tft.setTextColor(textDimCol); tft.setCursor(112, y); tft.print(alerts[i].detail);
            tft.setCursor(272, y); tft.printf("+%lus", millis() / 1000 - alerts[i].ts);
        }
    }
    drawFeaturePrompt(idsMode, 2);
}

void drawSys() {
    drawCenteredText("SYSTEM STATUS", 16, 1, C_GREY);
    tft.drawFastHLine(0, 26, 320, textDimCol);

    unsigned long up = millis() / 1000;
    auto row = [&](int y, const char* l, const char* v, uint16_t vc = (uint16_t)0xFFFF) {
        if (vc == 0xFFFF) vc = textCol;
        tft.setTextColor(textDimCol); tft.setCursor(5,   y); tft.print(l);
        tft.setTextColor(vc);         tft.setCursor(155, y); tft.print(v);
    };

    char b[32];
    snprintf(b, 32, "%luh%lum%lus", up / 3600, (up % 3600) / 60, up % 60);
    row(31, "Uptime:", b);
    snprintf(b, 32, "%.0f%%", activePct);
    row(45, "Active channels:", b, activePct > 30 ? C_RED : C_GREEN);
    row(59, "Jamming:", jamming ? "YES" : "NO", jamming ? C_RED : C_GREEN);
    row(73, "Attack type:", jamLabel(jamType));
    row(87, "Alarm:", alarmActive ? "ACTIVE" : "Silent", alarmActive ? C_RED : C_GREEN);
    snprintf(b, 32, "%d", totalAlerts);
    row(101, "Total Alerts:", b, totalAlerts > 0 ? C_ORANGE : C_GREEN);
    snprintf(b, 32, "%d", wCount);   row(115, "WiFi Nets:", b);

    int localBCount = 0;
    if (xSemaphoreTake(bleMutex, pdMS_TO_TICKS(5)) == pdTRUE) {
        localBCount = bCount2; xSemaphoreGive(bleMutex);
    }
    snprintf(b, 32, "%d", localBCount); row(129, "BT Devices:", b);
    snprintf(b, 32, "%lu ms", maxLoopDelay);
    row(157, "Max Loop Delay:", b, maxLoopDelay > 2000 ? C_RED : C_GREEN);
    snprintf(b, 32, "%d", stallWarnings);
    row(171, "Stall Recoveries:", b, stallWarnings > 0 ? C_ORANGE : C_GREEN);
    row(185, "Theme:",   isLightMode ? "Light Mode" : "Dark Mode", textDimCol);
    row(199, "Version:", "v3.1 HARDENED", textDimCol);
    drawFeaturePrompt(sysMode, 3);
}
