import time, os, logging
import Logger

LINKTYPE_BLUETOOTH_LE_LL     = 251
LINKTYPE_NORDIC_BLE            = 157

MAGIC_NUMBER                 = 0xa1b2c3d4
VERSION_MAJOR                 = 2
VERSION_MINOR                 = 4
THISZONE                     = 0
SIGFIGS                     = 0
SNAPLEN                     = 0xFFFF
NETWORK                     = LINKTYPE_NORDIC_BLE


globalHeaderString = [    
                            ((MAGIC_NUMBER     >> 0) & 0xFF),
                            ((MAGIC_NUMBER     >> 8) & 0xFF),
                            ((MAGIC_NUMBER     >> 16) & 0xFF),
                            ((MAGIC_NUMBER     >> 24) & 0xFF),
                            ((VERSION_MAJOR >> 0) & 0xFF),
                            ((VERSION_MAJOR >> 8) & 0xFF),
                            ((VERSION_MINOR >> 0) & 0xFF),
                            ((VERSION_MINOR >> 8) & 0xFF),
                            ((THISZONE         >> 0) & 0xFF),
                            ((THISZONE          >> 8) & 0xFF),
                            ((THISZONE          >> 16) & 0xFF),
                            ((THISZONE          >> 24) & 0xFF),
                            ((SIGFIGS         >> 0) & 0xFF),
                            ((SIGFIGS          >> 8) & 0xFF),
                            ((SIGFIGS          >> 16) & 0xFF),
                            ((SIGFIGS          >> 24) & 0xFF),
                            ((SNAPLEN         >> 0) & 0xFF),
                            ((SNAPLEN          >> 8) & 0xFF),
                            ((SNAPLEN          >> 16) & 0xFF),
                            ((SNAPLEN          >> 24) & 0xFF),
                            ((NETWORK         >> 0) & 0xFF),
                            ((NETWORK          >> 8) & 0xFF),
                            ((NETWORK          >> 16) & 0xFF),
                            ((NETWORK          >> 24) & 0xFF)
                        ]

captureFilePath = os.path.join(Logger.logFilePath, "capture.pcap")

class CaptureFileHandler:
    def __init__(self, clear = False):
        self.filename = captureFilePath
        self.backupFilename = self.filename+".1"
        if not os.path.isfile(self.filename):
            self.startNewFile()
        elif os.path.getsize(self.filename) > 20000000:
            self.doRollover()
        if clear: 
            #clear file
            self.startNewFile()
    
    def startNewFile(self):
        with open(self.filename, "wb") as f:
            f.write(toString(globalHeaderString))
    
    def doRollover(self):
        try:
            os.remove(self.backupFilename)
        except:
            logging.exception("capture file rollover remove backup failed")
        try:
            os.rename(self.filename, self.backupFilename)
            self.startNewFile()
        except:
            logging.exception("capture file rollover failed")
    
    def readLine(self, lineNum):
        line = ""
        with open(self.filename, "r") as f:
            f.seek(lineNum)
            line = f.readline()
        return line
        
    def readAll(self):
        text = ""
        with open(self.filename, "r") as f:
            text = f.read()
        return text
        
    def writeString(self, msgString):
        with open(self.filename, "ab") as f:
            f.write(msgString)
            
    def writeList(self, msgList):
        self.writeString(toString(msgList))
        
    def writePacketList(self, packetList):
        self.writeList(self.makePacketHeader(len(packetList)) + packetList)
        
    def writePacket(self, packet):
        self.writePacketList([packet.boardId] + packet.getList())
                
    def makePacketHeader(self, length):
        
        timeNow = time.clock()
        
        TS_SEC         = int(timeNow)
        TS_USEC     = int((timeNow-TS_SEC)*1000000)
        INCL_LENGTH = length
        ORIG_LENGTH = length

        headerString = [
                            ((TS_SEC         >> 0) & 0xFF),
                            ((TS_SEC         >> 8) & 0xFF),
                            ((TS_SEC         >> 16) & 0xFF),
                            ((TS_SEC         >> 24) & 0xFF),
                            ((TS_USEC         >> 0) & 0xFF),
                            ((TS_USEC         >> 8) & 0xFF),
                            ((TS_USEC         >> 16) & 0xFF),
                            ((TS_USEC         >> 24) & 0xFF),
                            ((INCL_LENGTH     >> 0) & 0xFF),
                            ((INCL_LENGTH     >> 8) & 0xFF),
                            ((INCL_LENGTH     >> 16) & 0xFF),
                            ((INCL_LENGTH     >> 24) & 0xFF),
                            ((ORIG_LENGTH     >> 0) & 0xFF),
                            ((ORIG_LENGTH     >> 8) & 0xFF),
                            ((ORIG_LENGTH     >> 16) & 0xFF),
                            ((ORIG_LENGTH     >> 24) & 0xFF)
                        ]
        return headerString
        
        
def toString(myList):
    myString = ""
    for i in myList:
        try:
            myString += chr(i)
        except ValueError:
            logging.exception("byte: %d, list: %s" % (i, str(myList)))
        except:
            logging.exception("byte: %d, list: %s" % (i, str(myList)))
            raise
    return myString
        
def toList(myString):
    myList = []
    for c in myString:
        myList += [ord(c)]
    return myList