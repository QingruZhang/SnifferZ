import sys, io, os
from PyQt5.QtWidgets import *
from PyQt5 import QtGui
from PyQt5.QtGui import QIcon, QPalette, QPixmap, QFont,QColor
from PyQt5.QtCore import pyqtSlot, pyqtSignal, Qt, QThread
from scapy.all import Packet
import scapy.all as Scapy
from contextlib import redirect_stdout

class AssembleTable(QWidget):

    def __init__(self, Sessions, Horizontal_label = ['Session', 'Packet list']):
        super(AssembleTable, self).__init__()
        
        self.session_data = Sessions
        self.table_data
        self.initUI(Horizontal_label)

        self._init_session_table()


    def initUI(self,Horizontal_label):
        self.layout = QHBoxLayout()
        self.Horizontal_label = Horizontal_label
        self.row = 10
        self.coloum = len(self.Horizontal_label)
        self.is_auto_scorll = True

        self.tablewidget=QTableWidget()
        self.tablewidget.setColumnCount(self.coloum)
        self.tablewidget.setRowCount(self.row)

        self.tablewidget.setHorizontalHeaderLabels(self.Horizontal_label)
        self.tablewidget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # self.tablewidget.setSelectionBehavior(QAbstractItemView.SelectRows)

        self.tablewidget.horizontalHeader().setStretchLastSection(True)
        self.tablewidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        stylesheet = "QHeaderView::section{font-family: arial; font-size:12pt; color: black; background-color:#BBBB00; text-align: center; }"
        self.tablewidget.horizontalHeader().setStyleSheet(stylesheet)

        self.tablewidget.verticalHeader().setVisible(False)

        for i in range(self.row):
            for j in range(self.coloum):
                itemContent='(%d,%d)'%(i,j)
                self.tablewidget.setItem(i,j,QTableWidgetItem(itemContent))

        self.textbrowser = QTextBrowser()

        self.layout.addWidget(self.tablewidget)
        self.layout.addWidget(self.textbrowser)
        self.setLayout(self.layout)

    def clear(self):
        self.row = 1
        self.tablewidget.clear()
        self.tablewidget.setRowCount(self.row)
        self.tablewidget.setHorizontalHeaderLabels(self.Horizontal_label)
        QTableWidget.resizeColumnsToContents(self.tablewidget)
        QTableWidget.resizeRowsToContents(self.tablewidget)

    def InsertOneRow(self, sessionRow):
        rowPosition = self.tablewidget.rowCount()
        self.tablewidget.insertRow(rowPosition)
        for i in range(self.coloum):
            item = QTableWidgetItem(singelRow[self.Horizontal_label[i]])
            # color = set_row_color(singelRow['Protocal'])
            item.setBackground(QColor('#AAFFEE'))
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

    def _init_session_table(self):
        for key in self.session_data.keys():
            singelRow = { self.Horizontal_label[0]:key, self.Horizontal_label[1]: self.session_data[key] }
            rowPos = self.InsertOneRow(singelRow)
            self.table_data[str(rowPos)] = singelRow

    def click_show_payload(self, row, coloum):
        


if __name__ == '__main__':
    app = QApplication(sys.argv)
    # dkpt = Scapy.sniff(count = 500)
    # for i in range(10):
    #     os.system('curl www.baidu.com')
    # print(dkpt.sessions())
    ex = AssembleTable()
    ex.setGeometry(300, 100, 700, 500)
    ex.show()
    sys.exit(app.exec_())


if __name__ == 'try':
    def recombine_ip_prepare(self):

        recombine_dict = {} # "src/dst/ip_id" : [(id,frag)()()]  ip_id is not id!!
        result = [] # [[id,id,id],[],..] one [] refers to one recombination

        for wpkt_id in self.w_pkts:
            w_pkt = self.w_pkts[wpkt_id]
            if w_pkt.IP == {}:
                continue

            index = str(w_pkt.src).strip() + '/' + str(w_pkt.dst).strip() + '/' + str(w_pkt.IP['id'])
            if index not in recombine_dict.keys():
                recombine_dict[index] = [(str(w_pkt.id), int(w_pkt.IP['frag']))]
            else:
                recombine_dict[index].append((str(w_pkt.id), int(w_pkt.IP['frag'])))

        for ip_id in recombine_dict:
            if len(recombine_dict[ip_id]) < 2:
                continue
            lst = recombine_dict[ip_id]
            lst.sort(cmp = self.sort_frag)
            result.append([a[0] for a in lst])

        recombine_dict.clear()
        return result

    def recombine_ip(self):
        result = self.recombine_ip_prepare()
        self.recombination = RecombinationIPGUI(result, self.w_pkts, self.raw_pkts)
        self.recombination.exec_()  # GUI has to be execuated!
