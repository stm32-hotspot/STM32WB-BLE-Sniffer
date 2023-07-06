#!/usr/bin/env python3

# Copyright 2014 Roland Knall <rknall [AT] gmail.com>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

# ******************************************************************************
# *
# *          Portions COPYRIGHT 2023 STMicroelectronics
# *
# * @file    st_ble_sniffer.py
# * @author  MCD Application Team
# * @brief   Interface between the STM32 BLE Sniffer protocol and wireshark
# ******************************************************************************

from __future__ import print_function

import sys
import re
import argparse
import time
import struct
import array
import serial
from threading import Thread
import serial.tools.list_ports

# Global constants 

EXTCAP_VERSION       = "1.0.1"

ERROR_USAGE          = 0
ERROR_ARG            = 1
ERROR_INTERFACE      = 2
ERROR_FIFO           = 3
ERROR_DELAY          = 4

CTRL_CMD_INITIALIZED = 0
CTRL_CMD_SET         = 1
CTRL_CMD_ADD         = 2
CTRL_CMD_REMOVE      = 3
CTRL_CMD_ENABLE      = 4
CTRL_CMD_DISABLE     = 5
CTRL_CMD_STATUSBAR   = 6
CTRL_CMD_INFORMATION = 7
CTRL_CMD_WARNING     = 8
CTRL_CMD_ERROR       = 9

CTRL_ARG_CHANNEL     = 0
CTRL_ARG_TARGET      = 1
CTRL_ARG_LOGGER      = 2
CTRL_ARG_KEY_TYPE    = 3
CTRL_ARG_KEY         = 4
CTRL_ARG_NONE        = 255

ST_SNIFFER_REPORT_EVENT_TYPE    = b'\x01'
ST_SNIFFER_MSG_EVENT_TYPE       = b'\x02'
ST_SNIFFER_HEADER_BYTE_SIZE     = 10

ST_SNIFFER_ENABLE               = 1
ST_SNIFFER_DISABLE              = 0

ST_SNIFFER_LEGACY_PASSKEY          = 0x00
ST_SNIFFER_LEGACY_OOB_DATA         = 0x01
ST_SNIFFER_SECURE_LTK              = 0x03
ST_SNIFFER_ERASE_KEY               = 0xFF

# Global variables 

initialized             = False
baudrate                = 921600
channel                 = 39
ser                     = serial.Serial()
iterateCounter          = 0
cpt                     = 0
fn_out                  = None
moreData                = 0
pcap                    = bytearray()
pckt                    = bytearray()
keyType                 = ST_SNIFFER_LEGACY_PASSKEY

# Class definitions

"""
This code has been taken from http://stackoverflow.com/questions/5943249/python-argparse-and-controlling-overriding-the-exit-status-code - originally developed by Rob Cowie http://stackoverflow.com/users/46690/rob-cowie
"""
class ArgumentParser(argparse.ArgumentParser):
    def _get_action_from_name(self, name):
        """Given a name, get the Action instance registered with this parser.
        If only it were made available in the ArgumentError object. It is
        passed as it's first arg...
        """
        container = self._actions
        if name is None:
            return None
        for action in container:
            if '/'.join(action.option_strings) == name:
                return action
            elif action.metavar == name:
                return action
            elif action.dest == name:
                return action

    def error(self, message):
        exc = sys.exc_info()[1]
        if exc:
            exc.argument = self._get_action_from_name(exc.argument_name)
            raise exc
        super(ArgumentParser, self).error(message)

# Functions definitions 

#### EXTCAP FUNCTIONALITY SECTION

def extcap_config(interface, option):
    """
    @brief  This method prints the extcap configuration, which will be picked up by the interface in Wireshark
            to present a interface specific configuration for this extcap plugin
    """
    args = []

    args.append((1, '--channel', 'Channel index', "Channel index e.g '39'", 'integer', '{range=0,39}{default=39}'))

    if len(option) <= 0:
        for arg in args:
            print("arg {number=%d}{call=%s}{display=%s}{tooltip=%s}{type=%s}%s" % arg)


def extcap_version():
    """!
    @brief  Print the external capture version                    
    """
    print("extcap {version=" + EXTCAP_VERSION + "}{help=https://www.wireshark.org}{display=STM32WB interface}")

def extcap_interfaces():
    """!
    @brief  Print the external capture interface                    
    """
    extcap_version()

    find_sniffers()

    print("control {number=%d}{type=selector}{display=Channel}{tooltip=Channel to sniff}" % CTRL_ARG_CHANNEL)
    print("control {number=%d}{type=string}{display=Target BD address}"
          "{default=00:00:00:00:00:00}"
          "{tooltip=Target BD address to follow}"
          "{validation=^[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}$}"% CTRL_ARG_TARGET)
    print("control {number=%d}{type=selector}{display=Key}{tooltip=Key type}" % CTRL_ARG_KEY_TYPE)
    print("control {number=%d}{type=string}{display=Value}"
          "{default=0123456789ABCDEF0123456789ABCDEF}"
          "{tooltip=128 bits key to use for pairing (LSO on the right). Passkey shall be zero-padded on MSOs.}"
          "{validation=^[a-fA-F0-9]{32}$}"% CTRL_ARG_KEY)
    print("control {number=%d}{type=button}{role=logger}{display=Log}{tooltip=Log per interface}" % CTRL_ARG_LOGGER)

def extcap_dlts(interface):
    print("dlt {number=147}{name=ST_BLE_sniffer}{display=ST BLE Sniffer DLTS}")

#### UTILS SECTION

def log(message):
    """!
    @brief  Add message to logs 

    @param  message String to log                                  
    """
    global fn_out
    control_write(fn_out, CTRL_ARG_LOGGER, CTRL_CMD_ADD,message)

def logln(message):
    """!
    @brief  Add message to logs with an new line end

    @param  message String to log                                  
    """
    log(message+"\n")

def unsigned(n):
    """!
    @brief  Convert a number to an unsinged 32 bits integer 

    @param  n       A number                                  
    """
    return int(n) & 0xFFFFFFFF

def send_sniff_enable(enable,channel):
    """!
    @brief  Send HCI vendor specific sniffer set enable command

    @param  enable  Enable state can be : 0 -> Disable
                                          1 -> Enable
    @param  channel Channel index to start listening on (0 to 39)                                    
    """

    assert channel >= 0 and channel <= 39, "Channel index can only be in the [0-39] range"

    test_cmd = bytearray([0x01,0x01,0x1D,0x02,enable,channel])
    ser.write(test_cmd)

def send_sniff_target(target):
    """!
    @brief  Send HCI vendor specific sniffer set target command

    @param  target  6 bytes BD Address          
    """

    test_cmd = bytearray([0x01,0x02,0x1D,0x06,target[5],target[4],target[3],target[2],target[1],target[0]])
    ser.write(test_cmd)

def send_sniff_key(type,key):
    """!
    @brief  Send HCI vendor specific sniffer set key command

    @param  type    Key type as :   SNIFFER_LEGACY_PASSKEY          
                                    SNIFFER_LEGACY_OOB_DATA         
                                    SNIFFER_SECURE_LTK              
                                    SNIFFER_ERASE_KEY 
    @param  key     Key value, shall be 128bit long
    """

    assert len(key) == 16, "Key shall be 16 bytes long"

    cmd = bytearray([0x01,0x03,0x1D,0x11,type])
    cmd += key
    ser.write(cmd)

def log_bytearray(pckt):
    """!
    @brief  Print a bytearray in the logs
    """
    s=("[")
    for b in pckt:
        s+=("0x%0.2X "%b)
    s+=("]")
    logln(s)

def equal(a,b):
    """!
    @brief  Check strict equality of two byte arrays
    """
    if(len(a) != len(b)):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True

def find_sniffers():
    """!
    @brief  Discover the STM32WB Sniffers on com ports 
    """
    sniffer_enable_success = bytearray([0x04,0x0E,0x04, 0x01,0x01,0x01D,0x00]) # The HCI command success reponse 
    ports = serial.tools.list_ports.comports()
    for device in sorted(ports):
        if device.vid == 1155 and device.pid == 14155:
            try:
                ser.baudrate = baudrate
                ser.port = device.name
                ser.open()

                finded = False
                trial = 0
                # Check if the sniffer enable command respond correctly to detect if the device is a ST BLE sniffer
                # Give the device multiple chances to answer to increase detection reliability
                while(trial<5 and finded==False):
                    rcv = bytearray()
                    send_sniff_enable(ST_SNIFFER_DISABLE, 39)
                    ser.timeout = 0.1
                    for i in range(len(sniffer_enable_success)):
                        rcv += ser.read()
                    ser.timeout = 100

                    if equal(rcv,sniffer_enable_success) :
                        print("interface {value=%s}{display=STM32WB sniffer interface on %s}"%(device.name, device.name))
                        finded = True

                    trial += 1

                ser.close()
            except:
                e = sys.exc_info()[0]
    
#### PCAP SECTION

def pcap_header():
    """!
    @brief  Create a suitable PCAP header for the sniffer capture 
    """
    header = bytearray()
    header += struct.pack('<L', int('a1b2c3d4', 16)) # Magic number
    header += struct.pack('<H', unsigned(2))  # Pcap Major Version
    header += struct.pack('<H', unsigned(4))  # Pcap Minor Version
    header += struct.pack('<I', int(0))  # Timezone
    header += struct.pack('<I', int(0))  # Accuracy of timestamps
    header += struct.pack('<L', int('00000fff', 16))  # Max Length of capture frame
    header += struct.pack('<L', unsigned(148))  # DLT USER1 , own protocol

    return header

def pcap_from_serial():
    """!
    @brief  Read next packet from serial port

    @note   Basically here we are parsing  HCI vendor specific events.
            That data payload field is then encapsulated in pcap format with the frame header
            and sniffer header
    """
    global iterateCounter,cpt,moreData,pcap,pckt

    if moreData == 0:
        pcap = bytearray()
        pckt = bytearray()

    timestamp = time.time()
    timestamp_floor = int(timestamp)
    timestamp_offset_us = int((timestamp - timestamp_floor) * 1_000_000)
    
    ConnEvtCounter_bytearray = bytearray()
    Timestamp_bytearray = bytearray()
    event_type = 0
    flags = 0

    b = ser.read()

    #waiting for H4 frame start 
    while b != b'\x04':
        b = ser.read()

    b = ser.read()

    #verifying it's a vendor specific event
    if b == b'\xFF':

        #third byte is the length
        b = ser.read()
        length = int.from_bytes(b)
        counter = 0

        # now read the payload
        while length > 0 :
            b = ser.read()
            counter += 1
            # everything before counter <= 2 is the vendor specific ecode (0x0D01 for the sniffer report event, 0x0D02 for the sniffer message event)
            # we check the event type to know how to interpret the incoming next bytes
            if counter == 1:
                if b == ST_SNIFFER_REPORT_EVENT_TYPE:
                    event_type = ST_SNIFFER_REPORT_EVENT_TYPE
                elif b == ST_SNIFFER_MSG_EVENT_TYPE:
                    event_type = ST_SNIFFER_MSG_EVENT_TYPE
                else :
                    logln("Unknown event received")
            # read the report event
            if event_type == ST_SNIFFER_REPORT_EVENT_TYPE:
                if counter == 3:
                    rssi = int.from_bytes(b, signed = True)
                if counter == 4:
                    channel = int.from_bytes(b)
                if counter == 5:
                    ConnEvtCounter_bytearray = b
                if counter == 6:
                    ConnEvtCounter_bytearray += b
                    ConnEvtCounter = int.from_bytes(ConnEvtCounter_bytearray)
                if counter == 7:
                    flags = int.from_bytes(b)
                if counter >= 8 and counter <= 11:
                    Timestamp_bytearray += b
                if counter == 12:
                    BoardID = int.from_bytes(b) # useless for now as it is replaced by com port number after
                if counter > 13:
                        pckt += b
            # read the message event
            elif event_type==ST_SNIFFER_MSG_EVENT_TYPE:
                if counter >= 2 and counter <= 5:
                    Timestamp_bytearray += b
                if counter == 6:
                    message_type=int.from_bytes(b)
                if counter > 8:
                    pckt += b

            length -= 1

        Timestamp = int.from_bytes(Timestamp_bytearray, 'little')

        if event_type == ST_SNIFFER_REPORT_EVENT_TYPE:
            moreData = flags & 0x80

            if moreData == 0 :
                # add a dummy CRC
                pckt += b'\xAB'
                pckt += b'\xAB'
                pckt += b'\xAB'

                length = len(pckt)
                # frame header
                pcap += struct.pack('<L', unsigned(timestamp_floor))  # timestamp seconds
                pcap += struct.pack('<L', unsigned(timestamp_offset_us))  # timestamp nanoseconds
                pcap += struct.pack('<L', unsigned(length+ST_SNIFFER_HEADER_BYTE_SIZE))  # length captured
                pcap += struct.pack('<L', unsigned(length+ST_SNIFFER_HEADER_BYTE_SIZE))  # length in frame

                pcap += struct.pack('>B',abs(rssi)) # RSSI
                pcap += struct.pack('>B',unsigned(channel)) # Channel
                pcap += struct.pack('>H',unsigned(ConnEvtCounter)) # Connecton event counter
                pcap += struct.pack('>B',unsigned(flags)) # Flags
                pcap += struct.pack('>L',unsigned(Timestamp)) # Timestamp
                pcap += struct.pack('>B',unsigned(int(ser.port[3:5]))) # Board ID (actually it is the com port number)

                for byte in pckt :
                    pcap += struct.pack('>B',byte) # The payload

                return pcap
            else :
                # returning None while waiting for the continuation fragment
                return None
            
        elif event_type==ST_SNIFFER_MSG_EVENT_TYPE:
            if message_type==0:
                logln(time.strftime("%H:%M:%S") + " " + pckt.decode('ascii'))

    return None


#### CONTROLS SECTION

def control_read(fn):
    """!
    @brief  Read from Wireshark control in fifo 

    @param  fn  Fifo to read from
    """
    try:
        header = fn.read(6)
        sp, _, length, arg, typ = struct.unpack('>sBHBB', header)
        if length > 2:
            payload = fn.read(length - 2).decode('utf-8', 'replace')
        else:
            payload = ''
        return arg, typ, payload
    except Exception:
        return None, None, None

def control_read_thread(control_in, fn_out):
    """!
    @brief  Handle incoming controls 

    @param  control_in  Fifo to read from
    @param  fn_out      Fifo to write controls
    """

    global initialized,channel,keyType

    with open(control_in, 'rb', 0) as fn:
        arg = 0
        while arg is not None:
            arg, typ, payload = control_read(fn)
            if typ == CTRL_CMD_INITIALIZED:
                initialized = True
            elif arg == CTRL_ARG_CHANNEL:
                channel = int(payload)
                send_sniff_enable(ST_SNIFFER_DISABLE, channel)
                time.sleep(1)
                send_sniff_enable(ST_SNIFFER_ENABLE, channel)
                logln("Channel set to : " + payload)
            elif arg == CTRL_ARG_TARGET:
                address = bytearray()
                values = payload
                values = values.split(':')
                for value in values:
                    address += int(value,16).to_bytes(1)
                send_sniff_target(address)
                logln("Target set to : " + payload)
            elif arg == CTRL_ARG_KEY_TYPE:
                if(payload=="Erase stored key"):
                    dummyKey = bytearray()
                    for i in range(16):
                        dummyKey += b'\x00'
                    send_sniff_key(ST_SNIFFER_ERASE_KEY, dummyKey)
                    logln("Key erased")
                elif(payload =="Legacy PassKey"):
                    keyType = ST_SNIFFER_LEGACY_PASSKEY
                elif(payload=="Legacy OOB data"):
                    keyType = ST_SNIFFER_LEGACY_OOB_DATA
                elif(payload=="LTK"):
                    keyType = ST_SNIFFER_SECURE_LTK
            elif arg == CTRL_ARG_KEY:
                key = bytearray.fromhex(payload)
                key.reverse() # reverse it to have LSO first
                send_sniff_key(keyType,key)
                logln("Set key : 0x%s"%payload)

def control_write(fn, arg, typ, payload):
    """!
    @brief  Write to Wireshark control out fifo 

    @param  fn      Fifo to write in
    @param  arg     Control arg number
    @param  typ     Control command type
    @param  payload Payload
    """
    packet = bytearray()
    packet += struct.pack('>sBHBB', b'T', 0, len(payload) + 2, arg, typ)
    if sys.version_info[0] >= 3 and isinstance(payload, str):
        packet += payload.encode('utf-8')
    else:
        packet += payload
    fn.write(packet)

def control_write_defaults(fn_out):
    """!
    @brief  Initialize interface toolbar control values 

    @param  fn_out  Fifo to write in
    """
    global channel

    while not initialized:
        time.sleep(.1)  # Wait for initial control values

    # Write startup configuration to Toolbar controls
    for i in range(0, 40):
        item = '%d' % i
        control_write(fn_out, CTRL_ARG_CHANNEL, CTRL_CMD_ADD, item)

    control_write(fn_out, CTRL_ARG_KEY_TYPE, CTRL_CMD_ADD, "Legacy PassKey")
    control_write(fn_out, CTRL_ARG_KEY_TYPE, CTRL_CMD_ADD, "Legacy OOB data")
    control_write(fn_out, CTRL_ARG_KEY_TYPE, CTRL_CMD_ADD, "LTK")
    control_write(fn_out, CTRL_ARG_KEY_TYPE, CTRL_CMD_ADD, "Erase stored key")

    control_write(fn_out, CTRL_ARG_CHANNEL, CTRL_CMD_SET, str(channel))

### CAPTURE SECTION

def extcap_capture(interface, fifo, control_in, control_out):
    """!
    @brief  Start the capture 

    @param  interface   Interface com port number
    @param  fifo        Fifo to write in packets
    @param  control_in  File to receive controls
    @param  control_out File to send controls
    """
    global fn_out

    try:
        with open(fifo, 'wb', 0) as fh:
            fh.write(pcap_header())

            if ser.is_open == True :
                ser.close()

            if control_out is not None:
                fn_out = open(control_out, 'wb', 0)
                control_write(fn_out, CTRL_ARG_LOGGER, CTRL_CMD_SET, "Log started at " + time.strftime("%c") + "\n")

            if control_in is not None:
                # Start reading thread
                thread = Thread(target=control_read_thread, args=(control_in, fn_out))
                thread.start()

            if fn_out is not None:
                control_write_defaults(fn_out)

            ser.baudrate = baudrate
            ser.port = interface
            ser.open()

            send_sniff_enable(ST_SNIFFER_DISABLE,channel)
            time.sleep(1)
            send_sniff_enable(ST_SNIFFER_ENABLE,channel)
            logln("Sniffer started on "+ interface + " at " + str(ser.baudrate) +"baud\n")

            while True:
                pcap = pcap_from_serial()
                if pcap is not None:
                    fh.write(pcap)
                    fh.flush()

    except OSError:
        # Wireshark stopped 
        pass

    finally:
        send_sniff_enable(ST_SNIFFER_DISABLE,channel)
        ser.close()
        logln("Sniffer stopped")

        thread.join()
        if fh is not None and not fh.closed:
            fh.close()

        if fn_out is not None:
            fn_out.close()

        fh = None
        fn_out = None
    


def extcap_close_fifo(fifo):
    """!
    @brief  Close file 

    @param  fifo  Fifo to close
    """
    fh = open(fifo, 'wb', 0)
    fh.close()

#### MAIN SECTION

def usage():
    """!
    @brief  Print extcap usage 
    """
    print("Usage: %s <--extcap-interfaces | --extcap-dlts | --extcap-interface | --extcap-config | --capture | --extcap-capture-filter | --fifo>" % sys.argv[0] )

if __name__ == '__main__':

    interface = ""
    option = ""

    parser = ArgumentParser(
            prog="Extcap Example",
            description="Extcap example program for Python"
            )

    # Extcap Arguments
    parser.add_argument("--capture", help="Start the capture routine", action="store_true" )
    parser.add_argument("--extcap-interfaces", help="Provide a list of interfaces to capture from", action="store_true")
    parser.add_argument("--extcap-interface", help="Provide the interface to capture from")
    parser.add_argument("--extcap-dlts", help="Provide a list of dlts for the given interface", action="store_true")
    parser.add_argument("--extcap-config", help="Provide a list of configurations for the given interface", action="store_true")
    parser.add_argument("--extcap-capture-filter", help="Used together with capture to provide a capture filter")
    parser.add_argument("--fifo", help="Use together with capture to provide the fifo to dump data to")
    parser.add_argument("--extcap-control-in", help="Used to get control messages from toolbar")
    parser.add_argument("--extcap-control-out", help="Used to send control messages to toolbar")
    parser.add_argument("--extcap-version", help="Shows the version of this utility", nargs='?', default="")
    parser.add_argument("--extcap-reload-option", help="Reload elements for the given option")

    # Interface Arguments
    parser.add_argument("--channel", help="Channel index", type=int, default=39)

    try:
        args, unknown = parser.parse_known_args()
    except argparse.ArgumentError as exc:
        print("%s: %s" % (exc.argument.dest, exc.message), file=sys.stderr)
        fifo_found = 0
        fifo = ""
        for arg in sys.argv:
            if arg == "--fifo" or arg == "--extcap-fifo":
                fifo_found = 1
            elif fifo_found == 1:
                fifo = arg
                break
        extcap_close_fifo(fifo)
        sys.exit(ERROR_ARG)

    if len(sys.argv) <= 1:
        parser.exit("No arguments given!")

    if args.extcap_version and not args.extcap_interfaces:
        extcap_version()
        sys.exit(0)

    if not args.extcap_interfaces and args.extcap_interface is None:
        parser.exit("An interface must be provided or the selection must be displayed")

    if args.extcap_interfaces or args.extcap_interface is None:
        extcap_interfaces()
        sys.exit(0)

    if len(unknown) > 1:
        print("Extcap Example %d unknown arguments given" % len(unknown))

    interface = args.extcap_interface

    if args.channel >= 0 and args.channel <= 39:
        channel = args.channel

    if args.extcap_reload_option and len(args.extcap_reload_option) > 0:
        option = args.extcap_reload_option

    if args.extcap_config:
        extcap_config(interface, option)
    elif args.extcap_dlts:
        extcap_dlts(interface)
    elif args.capture:
        if args.fifo is None:
            sys.exit(ERROR_FIFO)

        try:
            extcap_capture(interface, args.fifo, args.extcap_control_in, args.extcap_control_out)
        except KeyboardInterrupt:
            pass
    else:
        usage()
        sys.exit(ERROR_USAGE)