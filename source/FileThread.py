import io, sys, time, threading, os
import scapy.all as Scapy
from scapy.all import *
from PyQt5 import QtCore
from PyQt5.QtWidgets import *
from PyQt5 import QtGui
from PyQt5.QtGui import QIcon, QPalette, QPixmap, QFont
from PyQt5.QtCore import pyqtSlot, pyqtSignal, Qt
from GUIDesign import Result_Table, build_pkt_dict

class PDFthread(QtCore.QThread):

    finsh_write_signal = QtCore.pyqtSignal(bool)

    def __init__(self, pkt, parent = None, *args, **kwargs):
        
        super(PDFthread, self).__init__(parent)
        self.pkt = pkt

    def run(self):
        try:
            self.pkt.pdfdump('./tool/packet_analysis.pdf')
            state = os.system(r'.\tool\mutool.exe convert  -o .\tool\tmp.png .\tool\packet_analysis.pdf')
        except:
            state = True
        self.finsh_write_signal.emit(state)
        print('**Finsh write PDF')

class FileSaveThread(QtCore.QThread):

    finsh_write_signal = QtCore.pyqtSignal(bool)

    def __init__(self, save_path , packet_dict: dict, parent, *args, **kwargs):
        
        super(FileSaveThread, self).__init__(parent)
        self.packet_dict = packet_dict
        self.save_path = save_path

    def run(self):
        self.Plist = Scapy.PacketList()
        for key in self.packet_dict.keys():
            self.Plist.append(self.packet_dict[key])
        Scapy.wrpcap(self.save_path, self.Plist)
        print('**Finsh save file')

class PreSearchThread(QtCore.QThread):
    def __init__(self, packet_dict: dict, Horizontal_label, *args, **kwargs):
        
        super(PreSearchThread, self).__init__()
        self.packet_dict = packet_dict
        self.table_result = QTableWidget()
        
    def run(self):
        self.table_result.show()


