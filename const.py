"""
Constants used across package
"""

from enum import Enum

MINIMUM_BLINK_RATE = 20

UPB_MESSAGE_TYPE = 0
UPB_MESSAGE_PIMREPORT_TYPE = 1

PACKETHEADER_LINKBIT = 0x80

class UpbTransmission(Enum):
    UPB_MESSAGE = 0x55 # U
    UPB_PIM_ACCEPT = 0x41 # A
    UPB_PIM_BUSY = 0x42 # B
    UPB_PIM_ERROR = 0x45 # 'E'
    UPB_PIM_REGISTERS = 0x52 # R
    UPB_TRANSMISSION_ACK = 0x4b # K
    UPB_TRANSMISSION_NAK = 0x4e # N

class UpbMessage(Enum):
    UPB_MESSAGE_PIMREPORT = 0x50 # P
    UPB_MESSAGE_START = 0x58 # X
    UPB_MESSAGE_SYNC = 0x52 # R
    UPB_MESSAGE_DATA_0 = 0x30 # 0
    UPB_MESSAGE_DATA_1 = 0x31 # 1
    UPB_MESSAGE_DATA_2 = 0x32 # 2
    UPB_MESSAGE_DATA_3 = 0x33 # 3
    UPB_MESSAGE_ACK = 0x41 # A
    UPB_MESSAGE_NAK = 0x4e # N
    UPB_MESSAGE_DROP = 0x44 # D
    UPB_MESSAGE_IDLE = 0x2d # -
    UPB_MESSAGE_TRANSMITTED = 0x54 # T

    @classmethod
    def has_value(cls, value):
        return value in cls._value2member_map_

class PimCommand(Enum):
    UPB_NETWORK_TRANSMIT = 0x14
    UPB_PIM_READ = 0x12
    UPB_PIM_WRITE = 0x17

class UpbReg(Enum):
    UPB_REG_NETWORKID = 0x00
    UPB_REG_MODULEID = 0x01
    UPB_REG_PASSWORD = 0x02
    UPB_REG_UPBOPTIONS = 0x04
    UPB_REG_UPBVERSION = 0x05
    UPB_REG_MANUFACTURERID = 0x06
    UPB_REG_PRODUCTID = 0x08
    UPB_REG_FIRMWAREVERSION = 0x0a
    UPB_REG_SERIALNUMBER = 0x0c
    UPB_REG_NETWORKNAME = 0x10
    UPB_REG_ROOMNAME = 0x20
    UPB_REG_DEVICENAME = 0x30
    UPB_REG_RESERVED1 = 0x40
    UPB_REG_PIMOPTIONS = 0x70
    UPB_REG_RESERVED2 = 0x71
    UPB_REG_SIGNALSTRENGTH = 0xf9
    UPB_REG_NOISEFLOOR = 0xfa
    UPB_REG_NOISECOUNTS = 0xfb

class UpbDeviceId(Enum):
    BROADCAST_DEVICEID = 0x00
    RESERVED1_DEVICEID = 0xfb
    RESERVED2_DEVICEID = 0xfc
    WRITEENABLED_DEVICEID = 0xfd
    SETUPMODE_DEVICEID = 0xfe
    DEFAULT_DEVICEID = 0xff

    @classmethod
    def has_value(cls, value):
        return value in cls._value2member_map_

class UpbReqAck(Enum):
    REQ_ACKDEFAULT = 0x00
    REQ_ACKMESSAGE = 0x01
    REQ_NOACK = 0x02
    REQ_ACKNOREQUEUEONNAK = 0x04

class UpbReqRepeater(Enum):
    REP_NONREPEATER = 0x00
    REP_LOWREPEAT = 0x01
    REP_MEDIUMREPEAT = 0x02
    REP_HIGHREPEAT = 0x03

INITIAL_PIM_REG_QUERY_BASE = UpbReg.UPB_REG_UPBOPTIONS.value

MANUFACTURERS = {
    "1": "PCS Lighting",
    "2": "MD Manufacturing",
    "3": "Web Mountain",
    "4": "Simply Automated",
    "5": "Home Automation Inc.",
}

# UPB Product list from export document
# Note: some products may be missing, this is the only list around
PRODUCTS = {
    "1/1": ("(WS1) Wall Switch - 1 Channel", "Switch"),
    "1/2": ("(WS1R) Wall switch - Relay", "Switch"),
    "1/3": ("(WMC6) Wall Mount Controller - 6 Button", "Keypad"),
    "1/4": ("(WMC8) Wall Mount Controller - 8 Button", "Keypad"),
    "1/6": ("(OCM2) Output Control Module - 2 Channel", "Module"),
    "1/7": ("(LCM1) Load Control Module 1", "Module"),
    "1/9": ("(LM1) Lamp Module - 1 Channel", "Module"),
    "1/10": ("(LM2) Lamp Module - 2 Channel", "Module"),
    "1/11": ("(ICM2) Input Control Module - 2 Channel", "Input"),
    "1/13": ("(DTC6) Desktop Controller - 6 Button", "Keypad"),
    "1/14": ("(DTC8) Desktop Controller - 8 Button", "Keypad"),
    "1/15": ("(AM1) Appliance Module - 1 Channel", "Module"),
    "1/25": ("(LSM) Load Shedding Module", "Module"),
    "1/24": ("(WS1E) Wall Switch - Electronic Low Voltage", "Switch"),
    "1/36": ("(DCM) Doorbell Control Module", "Input"),
    "1/37": ("(TCM) Telephone Control Module", "Input"),
    "1/58": ("(RM1) Receptacle Module", "Module"),
    "1/60": ("(FMD2) Fixture Module - Dimmer", "Module"),
    "1/61": ("(FMR) Fixture Module - Relay", "Module"),
    "1/62": ("(WS2D) LED Wall Switch", "Switch"),
    "1/63": ("(KPLD6) Keypad Light Dimmer", "Keypad"),
    "1/65": ("(KPC6) Controller - 6 Button", "Keypad"),
    "1/66": ("(KPC8) Controller - 8 Button", "Keypad"),
    "1/69": ("(KPLD8) Keypad Load Dimmer - 8 Button", "Keypad"),
    "1/70": ("(KPLR6) Keypad Load Relay - 6 Button", "Keypad"),
    "1/71": ("(KPLR8) Keypad Load Relay - 8 Button", "Keypad"),
    "1/72": ("(WS1L) Wall Switch - LED", "CFL Dimmer"),
    "1/73": ("(KPC7) Controller - 7 Button", "Keypad"),
    "1/74": ("(KPLR7) Keypad Load Relay - 7 Button", "Keypad"),
    "1/75": ("(KPLD7) Keypad Load Dimmer - 7 Button", "Keypad"),
    "2/32": ("(VHC) Vacuum Handle Controller", "VHC"),
    "2/33": ("(VPM) Vacuum Power Module", "VPM"),
    "2/35": ("(VIM) Vacuum Input Module", "Input"),
    "2/36": ("(DSM) Doorbell Sense Module", "Input"),
    "2/37": ("(TSM) Telephone Sense Module", "Input"),
    "3/1": ("LM01 Lamp Module - Basic", "Switch"),
    "3/5": ("AM01 Appliance Module - Basic", "Switch"),
    "3/7": ("FXR01 Fixture, Relay", "Switch"),
    "3/8": ("OUT01 Switched Receptacle Outlet", "Switch"),
    "3/29": ("SW7 Dimmer switch", "Switch"),
    "3/30": ("SPIM01 Serial Powerline Interface Module", "Switch"),
    "4/1": ("UML Lamp Module", "Module"),
    "4/5": ("UMA Appliance Module", "Module"),
    "4/7": ("UFR Fixture Relay ", "URD Receptacle"),
    "4/9": ("UMA Appliance Module - Timer", "Module"),
    "4/10": ("UFD Fixture Dimmer", "Switch or Module *"),
    "4/12": ("UML Lamp Module - Timer", "Module"),
    "4/13": ("UFR Fixture ", "URD Receptacle - Timer"),
    "4/14": ("UFD Fixture Dimmer - Timer", "Switch or Module *"),
    "4/15": ("UCT Tabletop Controller", "Keypad"),
    "4/20": ("USM1 Switch Motorized", "Switch"),
    "4/22": ("US1 ", "US2 Series Dimming Switch"),
    "4/26": ("UCQ ", "UCQT Quad Output Module"),
    "4/27": ("US4 Series Quad Dimming Switch", "Switch"),
    "4/28": ("US1-40 Series Dimming Switch", "Switch"),
    "4/29": ("US2-40 Series Dimming Switch", "Switch"),
    "4/36": ("UCQTX Quad Output Module", "Module"),
    "4/62": ("US22-40T Series Dimming Switch", "Switch"),
    "4/34": ("US1-40 Series Dimming Switch - Timer", "Switch"),
    "4/44": ("USM1R", "Switch"),
    "4/45": ("USM2R", "Switch"),
    "4/40": ("UMI-32 3-Input ", "2-Output Module"),
    "4/201": ("Lamp Module (UML-E)", "Module"),
    "4/205": ("Appliance Module (UMA-E)", "Module"),
    "4/222": ("Retail Dimming Switch (RS101)", "Switch"),
    "4/240": ("Retail I", "O 32 Module"),
    "5/1": ("35A00-1 600W Dimming Switch", "Switch"),
    "5/2": ("35A00-2 1000W Dimming Switch", "Switch"),
    "5/16": ("35A00-3 600W Non-Dimming Switch", "Switch"),
    "5/17": ("35A00-4 1000W Non-Dimming Switch", "Switch"),
    "5/18": ("40A00-1 15A Relay Switch", "Switch"),
    "5/3": ("55A00-1 1000W Dimming Switch", "Switch"),
    "5/4": ("55A00-2 1500W Dimming Switch", "Switch"),
    "5/5": ("55A00-3 2400W Dimming Switch", "Switch"),
    "5/32": ("59A00-1 300W Lamp Module", "Module"),
    "5/48": ("60A00-1 15A Appliance Module", "Module"),
    "5/80": ("38A00-1 6-Button Room Controller", "Keypad"),
    "5/96": ('38A00-2 8-Button House Controller"', "Keypad"),
}
