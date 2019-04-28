import sys, time
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon,QPalette,QPixmap,QFont, QColor
from PyQt5.QtWidgets import *
import scapy.all as Scapy
from scapy.all import Packet

def build_pkt_dict(self, No, pkt:Packet):
    SingelRow = {
        'No.' : str(No),
        'Time' : str(time.time() - self.startTime)[0:6],
        'Protocal' : SnifferThread.get_packet_proto(pkt),
        'Length' : str(len(pkt)),
        'Info' : pkt.summary(),
    }
    SingelRow['Source'], SingelRow['Destination'] = SnifferThread.get_src_dst(pkt)
    return SingelRow

def set_row_color(proto: str):
    if 'TCP' in proto:
        color = QColor('#4dffff')
    elif 'UDP' in proto:
        color = QColor('#7afec6')
    elif 'ICMP' in proto:
        color = QColor('#ff79bc')
    elif 'ARP' in proto:
        color = QColor('#ea7500')
    elif 'DHCP' in proto:
        color = QColor('#c4c400')
    else:
        color = QColor('#9f4d95')
    return color

class Result_Table(QWidget):

    def __init__(self, Horizontal_label = None):
        super(Result_Table, self).__init__()
        self.initUI(Horizontal_label)


    def initUI(self,Horizontal_label):
        self.layout = QHBoxLayout()
        self.Horizontal_label = Horizontal_label
        self.row = 1
        self.coloum = len(self.Horizontal_label)
        self.is_auto_scorll = True

        self.tablewidget=QTableWidget()
        self.tablewidget.setColumnCount(self.coloum)
        self.tablewidget.setRowCount(self.coloum)

        self.tablewidget.setHorizontalHeaderLabels(self.Horizontal_label)
        self.tablewidget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tablewidget.setSelectionBehavior(QAbstractItemView.SelectRows)

        self.tablewidget.horizontalHeader().setStretchLastSection(True)
        self.tablewidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        stylesheet = "QHeaderView::section{font-family: arial; font-size:12pt; color: black; background-color:#BBBB00; text-align: center; }"
        self.tablewidget.horizontalHeader().setStyleSheet(stylesheet)

        self.tablewidget.verticalHeader().setVisible(False)

        self._initial_row()

        self.tablewidget.insertRow(self.tablewidget.rowCount())

        self.layout.addWidget(self.tablewidget)
        self.setLayout(self.layout)

    def _initial_row(self):
        for j in range(self.coloum):
            itemContent = self.Horizontal_label[j]
            self.tablewidget.setItem(0,j, QTableWidgetItem(itemContent))

    def clear(self):
        self.row = 1
        self.tablewidget.clear()
        self.tablewidget.setRowCount(self.row)
        self._initial_row()
        self.tablewidget.setHorizontalHeaderLabels(self.Horizontal_label)
        QTableWidget.resizeColumnsToContents(self.tablewidget)
        QTableWidget.resizeRowsToContents(self.tablewidget)

    def InsertOneRow(self, singelRow):
        rowPosition = self.tablewidget.rowCount()
        self.tablewidget.insertRow(rowPosition)
        for i in range(self.coloum):
            item = QTableWidgetItem(singelRow[self.Horizontal_label[i]])
            color = set_row_color(singelRow['Protocal'])
            item.setBackground(color)
            self.tablewidget.setItem(rowPosition, i, item)
        if self.is_auto_scorll:
            self.tablewidget.scrollToBottom()
        return rowPosition

    def insert_to_row_index(self, rowIndex, singelRow : dict):
        rowCount = self.tablewidget.rowCount()
        if rowIndex >= rowCount:
            self.tablewidget.setRowCount(rowIndex+1)
        for i in range(self.coloum):
            item = QTableWidgetItem(singelRow[self.Horizontal_label[i]])
            color = set_row_color(singelRow['Protocal'])
            item.setBackground(color)
            self.tablewidget.setItem(rowIndex, i, item)
        if self.is_auto_scorll:
            self.tablewidget.scrollToBottom()

    def set_auto_scoll(self, is_set):
        self.is_auto_scorll = is_set
        # self.tablewidget.scrollToBottom()

    def adjust_RowHeader(self):
        QTableWidget.resizeColumnsToContents(self.tablewidget)
        QTableWidget.resizeRowsToContents(self.tablewidget)
