#via https://github.com/cdealti/Adafruit_BLESniffer_Python

import logging
import os
import sys
import time

"""
PcapPipe.py: an Unix named pipe where PCAP packets are written.
This pipe represents the interface between the sniffer and Wireshark.
The original code has been posted on the Nordic Developer Zone [1][2] by
a Nordic employee and is not accompanied by a license.

[1] https://devzone.nordicsemi.com/blogs/750/ble-sniffer-in-linux-using-wireshark
[2] https://devzone.nordicsemi.com/attachment/74532982f9e4b627b4cddfec2cb585e7
"""

__author__    = "Stian"
__copyright__ = "Copyright (c) 2014, Nordic Semiconductor ASA"
__license__   = "MIT"
__version__   = "0.1.0"

class PcapPipe(object):
    def open_and_init(self, pipeFilePath):
        try:
            os.mkfifo(pipeFilePath)
        except OSError:
            logging.warn("fifo already exists?")
            raise SystemExit(1)
        self._pipe = open(pipeFilePath, 'w')
        self.write(self.makeGlobalHeader())

    def write(self, message):
        if not self._pipe: return
        try:
            self._pipe.write(''.join(map(chr, message)))
            self._pipe.flush()
        except IOError:
            exc_type, exc_value, exc_tb = sys.exc_info()
            logging.error('Got exception trying to write to pipe: %s', exc_value)
            self.close()

    def close(self):
        logging.debug("closing pipe")
        if not self._pipe: return
        self._pipe.close()
        self._pipe = None

    def isOpen(self):
        return self._pipe is not None and not self._pipe.closed 

    def newBlePacket(self, notification):
        packet      = notification.msg["packet"]
        packetList  = packet.getList()
        snifferList = self.makePacketHeader(len(packetList) + 1) + [packet.boardId] + packetList
        self.write(snifferList)

    def makeGlobalHeader(self):
        LINKTYPE_BLUETOOTH_LE_LL    = 251
        LINKTYPE_NORDIC_BLE         = 157

        MAGIC_NUMBER                = 0xa1b2c3d4
        VERSION_MAJOR               = 2
        VERSION_MINOR               = 4
        THISZONE                    = 0
        SIGFIGS                     = 0
        SNAPLEN                     = 0xFFFF
        NETWORK                     = LINKTYPE_NORDIC_BLE

        headerString = [
                            ((MAGIC_NUMBER  >>  0) & 0xFF),
                            ((MAGIC_NUMBER  >>  8) & 0xFF),
                            ((MAGIC_NUMBER  >> 16) & 0xFF),
                            ((MAGIC_NUMBER  >> 24) & 0xFF),
                            ((VERSION_MAJOR >>  0) & 0xFF),
                            ((VERSION_MAJOR >>  8) & 0xFF),
                            ((VERSION_MINOR >>  0) & 0xFF),
                            ((VERSION_MINOR >>  8) & 0xFF),
                            ((THISZONE      >>  0) & 0xFF),
                            ((THISZONE      >>  8) & 0xFF),
                            ((THISZONE      >> 16) & 0xFF),
                            ((THISZONE      >> 24) & 0xFF),
                            ((SIGFIGS       >>  0) & 0xFF),
                            ((SIGFIGS       >>  8) & 0xFF),
                            ((SIGFIGS       >> 16) & 0xFF),
                            ((SIGFIGS       >> 24) & 0xFF),
                            ((SNAPLEN       >>  0) & 0xFF),
                            ((SNAPLEN       >>  8) & 0xFF),
                            ((SNAPLEN       >> 16) & 0xFF),
                            ((SNAPLEN       >> 24) & 0xFF),
                            ((NETWORK       >>  0) & 0xFF),
                            ((NETWORK       >>  8) & 0xFF),
                            ((NETWORK       >> 16) & 0xFF),
                            ((NETWORK       >> 24) & 0xFF)
                        ]

        return headerString

    def makePacketHeader(self, length):

        if(os.name == 'posix'):
            timeNow = time.time()
        else:
            timeNow = time.clock()

        TS_SEC      = int(timeNow)
        TS_USEC     = int((timeNow-TS_SEC)*1000000)
        INCL_LENGTH = length
        ORIG_LENGTH = length

        headerString = [
                            ((TS_SEC        >>  0) & 0xFF),
                            ((TS_SEC        >>  8) & 0xFF),
                            ((TS_SEC        >> 16) & 0xFF),
                            ((TS_SEC        >> 24) & 0xFF),
                            ((TS_USEC       >>  0) & 0xFF),
                            ((TS_USEC       >>  8) & 0xFF),
                            ((TS_USEC       >> 16) & 0xFF),
                            ((TS_USEC       >> 24) & 0xFF),
                            ((INCL_LENGTH   >>  0) & 0xFF),
                            ((INCL_LENGTH   >>  8) & 0xFF),
                            ((INCL_LENGTH   >> 16) & 0xFF),
                            ((INCL_LENGTH   >> 24) & 0xFF),
                            ((ORIG_LENGTH   >>  0) & 0xFF),
                            ((ORIG_LENGTH   >>  8) & 0xFF),
                            ((ORIG_LENGTH   >> 16) & 0xFF),
                            ((ORIG_LENGTH   >> 24) & 0xFF)
                        ]
        return headerString
