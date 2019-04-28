#coding:utf-8
import sys, io, os
from PyQt5.QtWidgets import *
from PyQt5 import QtGui
from PyQt5.QtGui import QIcon, QPalette, QPixmap, QFont
from PyQt5.QtCore import pyqtSlot, pyqtSignal, Qt
from scapy.all import Packet
import scapy.all as Scapy
from contextlib import redirect_stdout
from MyTabel import Result_Table
import SnifferThread

class MyTableWidget(QWidget):
 
    def __init__(self, parent = None):
        super(QWidget, self).__init__(parent)

        self.setWindowIcon(QIcon('img/SnifferLogo.png')) 
        self.layout = QVBoxLayout(self)
        
        self.font = QFont()
        self.font.setPointSize(12)
        self.font.setWeight(12)
        self.font.setBold(True)

        self.tabs_analysis = QTabWidget(self)

        self.packet_tab = QTextBrowser(self)
        self.packet_tab.setText("Choose Packe \n")
        self.packet_tab.setFont(self.font)

        self.reassemble_tab = Result_Table([ 
            'ID' , 'Time', 'Source', 'Destination', 'Protocal', 'Length', 'Info' 
        ])
        self.reassemble_tab.tablewidget.cellDoubleClicked.connect(self.reassem_tab_click)
        self.reassem_dict = {}

        self.scroll_analysis = QScrollArea()
        self.pdf_widget = QWidget()
        self.pdf_layout = QVBoxLayout()
        self.pdf_but = QPushButton('Generate Analysis Plot')
        self.analysis_tab = QLabel()
        self.pdf_layout.addWidget(self.pdf_but)
        self.pdf_layout.addWidget(self.analysis_tab)
        self.pdf_widget.setLayout(self.pdf_layout)
        self.analysis_tab.setMinimumSize(900, 800)

        self.pdf_pixmap = QPixmap('./img/OpenFile.png')
        self.analysis_tab.setText('The Tab Show Detail Information')
        self.analysis_tab.setScaledContents (True) 
        self.scroll_analysis.setWidget(self.pdf_widget)

        self.ethernet_tab = QTextBrowser(self)
        self.ethernet_tab.setFrameShape(QFrame.Box)
        self.ethernet_tab.setFont(self.font)
        
        self.ip_tab = QTextBrowser(self)
        self.ip_tab.setFrameShape(QFrame.Box)
        self.ip_tab.setFont(self.font)

        self.proto_tab = QTextBrowser(self)
        self.proto_tab.setFrameShape(QFrame.Box)
        self.proto_tab.setFont(self.font)

        self.data_tab = QTextBrowser(self)
        self.data_tab.setFrameShape(QFrame.Box)
        self.data_tab.setFont(self.font)

        # Add tabs_analysis
        self.tabs_analysis.addTab(self.packet_tab,"Hex Packet")
        self.tabs_analysis.addTab(self.scroll_analysis,"Detail Information")
        self.tabs_analysis.addTab(self.ethernet_tab,"Ethernet")
        self.tabs_analysis.addTab(self.ip_tab,"IP")
        self.tabs_analysis.addTab(self.proto_tab,"Protocol")
        # self.tabs_analysis.addTab(self.data_tab,"Data")
        self.tabs_analysis.addTab(self.reassemble_tab,"Reassemble table")

        # Add tabs_analysis to widget
        self.layout.addWidget(self.tabs_analysis)
        self.setLayout(self.layout)
        self.setGeometry(300, 100, 700, 500)

    def _renew_most(self, pkt: Packet):
        with io.StringIO() as buf, redirect_stdout(buf):
            Scapy.hexdump(pkt)
            hex_packet = buf.getvalue()
        self.packet_tab.setText(hex_packet)
        with io.StringIO() as buf, redirect_stdout(buf):
            pkt[0].show()
            eth_analysis = buf.getvalue()
        self.ethernet_tab.setText(eth_analysis)
        with io.StringIO() as buf, redirect_stdout(buf):
            pkt[1].show()
            IP_analysis = buf.getvalue()
        self.ip_tab.setText(IP_analysis)
        with io.StringIO() as buf, redirect_stdout(buf):
            pkt[2].show()
            proto_analysis = buf.getvalue()
        self.proto_tab.setText(proto_analysis)
        

    def _renew_pdf(self, state):
        if not state:
            self.pdf_pixmap = QPixmap(r'./tool/tmp1.png')
            self.analysis_tab.setPixmap(self.pdf_pixmap)
            self.analysis_tab.setScaledContents(True) 
        else:
            self.analysis_tab.setText('Some mistakes may orrur when converting to PNG.\nSee Result in ./tool/proto_analysis.pdf \n')
            self.analysis_tab.setFont(self.font)
            self.analysis_tab.setScaledContents (True) 
    
    def _set_pdf_tab_waiting(self, tip = 'Analysis packet... \nPlease Wait... \n' ):
        self.analysis_tab.setText(tip)
        self.analysis_tab.setFont(self.font)
        self.analysis_tab.setScaledContents(True) 

    def _clear_all_tabs(self):
        self.packet_tab.setText("")
        self.ethernet_tab.setText("")
        self.ip_tab.setText("")
        self.proto_tab.setText("")
        self.analysis_tab.setText("Choose Packet")
        self.reassemble_tab.clear()

    def build_pkt_dict(self, No, pkt:Packet):
        SingelRow = {
            'ID' : str(No),
            'Time' : 'N/A',
            'Protocal' : SnifferThread.get_packet_proto(pkt),
            'Length' : str(len(pkt)),
            'Info' : pkt.summary(),
        }
        SingelRow['Source'], SingelRow['Destination'] = SnifferThread.get_src_dst(pkt)
        return SingelRow

    def update_reassemble(self, Pdict):
        self.reassem_dict = {}
        self.reassemble_tab.clear()
        for key in Pdict.keys():
            SingelRow = self.build_pkt_dict(key, Pdict[key])
            rowPos = self.reassemble_tab.InsertOneRow(SingelRow)
            self.reassem_dict[str(rowPos)] = Pdict[key]
        self.reassemble_tab.adjust_RowHeader()

    def reassem_tab_click(self, row, coloum):
        if str(row) in self.reassem_dict.keys():
            pkt = self.reassem_dict[str(row)]
            self._renew_most(pkt)
            self._set_pdf_tab_waiting(tip = 'No Detail Analysis For Reassembe Packet')
        else:
            self._clear_all_tabs()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = MyTableWidget()
    ex.setGeometry(300, 100, 700, 500)
    ex.show()
    sys.exit(app.exec_())