import sys, io, os
from PyQt5.QtWidgets import *
from PyQt5 import QtGui
from PyQt5.QtGui import QIcon, QPalette, QPixmap, QFont
from PyQt5.QtCore import pyqtSlot, pyqtSignal, Qt
from scapy.all import Packet
import scapy.all as Scapy
from contextlib import redirect_stdout

class FilterWidget(QWidget):
	
	emit_filter_signal = pyqtSignal(str)

	def __init__(self):
		super().__init__()
		self.primitives = {
			'host' : '[src|dst] host <host ip>',
			'ether host' : 'ether [src|dst] host <MAC>' , 
			'vlan' : 'vlan <ID>' , 
			'portrange' : '[src|dst] portrange <p1>-<p2> or [tcp|udp] [src|dst] portrange <p1>-<p2>' ,
			'proto' : '[ip|ip6][src|dst] proto <protocol>' ,
			'port' : '[ip|ip6][tcp|udp] [src|dst] port <port>' ,
			'net' : '[src|dst] net <network>' ,
			'tcpflags' : '[ip|ip6] tcp tcpflags & (tcp-[ack|fin|syn|rst|push|urg|)' ,
			'Fragmented' : 'Fragmented IPv4 packets (ip_offset != 0)' ,
		}
		self.filter_input = {
		   'host' : None,
			'ether host' : None , 
			'vlan' : None , 
			'portrange' : None ,
			'proto' : None ,
			'port' : None ,
			'net' : None ,
			'tcpflags' : None,
			'Fragmented' : None ,
		}        

		self.filter_rule = None
		self.initUI()

	def initUI(self):

		self.setWindowIcon(QIcon('img/SnifferLogo.png'))
		self.setWindowTitle('SnifferZ Filter')

		self.font = QFont()
		self.font.setPointSize(14)
		self.font.setWeight(14)
		self.font.setBold(True)

		self.layout = QVBoxLayout()
		self.grid_layout = QGridLayout()

		self.top_label = QLabel('Set the filter rule of Sniffer:')
		self.top_label.setFont(self.font)
		self.layout.addWidget(self.top_label)

		self.font.setPointSize(12)
		self.font.setWeight(12)

		self.checkBoxs = {}
		self.helpLabels = {}
		self.inputLines = {}

		for i,key in enumerate(self.primitives.keys()):
			self.checkBoxs[key] = QCheckBox(key)
			self.helpLabels[key] = QLabel(r'Help: ' + self.primitives[key])
			self.inputLines[key] = QLineEdit()


			self.checkBoxs[key].setObjectName(key)
			self.helpLabels[key].setObjectName(key)
			self.inputLines[key].setObjectName(key)
			# self.checkBoxs[key].setFont(self.font)
			# self.inputLines[key].setFont(self.font)
			# self.helpLabels[key].setFont(self.font)
			self.inputLines[key].setText(self.filter_input[key])
			self.inputLines[key].textEdited.connect(self.text_edited)

			self.layout.addWidget(self.checkBoxs[key])
			self.layout.addWidget(self.helpLabels[key])
			self.layout.addWidget(self.inputLines[key])
			self.layout.addStretch(1)

		#     self.grid_layout.addWidget(self.checkBoxs[key], i//2*3, i%2)
		#     self.grid_layout.addWidget(self.helpLabels[key], i//2*3+1, i%2)
		#     self.grid_layout.addWidget(self.inputLines[key], i//2*3+2, i%2)

		# self.grid_widget = QWidget()
		# self.grid_widget.setLayout(self.grid_layout)
		# self.layout.addWidget(self.grid_widget)

		self.confrim_but = QPushButton('OK')
		self.quit_but = QPushButton('Quit')

		self.but_widget = QWidget()
		self.but_hlayout = QHBoxLayout()
		self.but_hlayout.addStretch(1)
		self.but_hlayout.addWidget(self.confrim_but)
		self.but_hlayout.addWidget(self.quit_but)
		self.but_widget.setLayout(self.but_hlayout)

		self.layout.addWidget(self.but_widget)
		self.setLayout(self.layout)
		self.setGeometry(300, 50, 700, 500)

		self.confrim_but.clicked.connect(self.confrim_action)
		self.quit_but.clicked.connect(self.close)

	def text_edited(self, text):
		sender_name = self.sender().objectName()
		self.filter_input[sender_name] = text

	def confrim_action(self):
		self.filter_rule = ''
		for i,key in enumerate(self.filter_input.keys()):
			if self.checkBoxs[key].isChecked():
				self.filter_rule += ' and ' + self.filter_input[key]
		self.filter_rule = self.filter_rule[5:]
		self.emit_filter_signal.emit(self.filter_rule)
		print('Filter in FilterWidget:%s'%self.filter_rule)
		self.close()
		# print(self.filter_rule)
		# try:
		#     dkpt_try = Scapy.sniff(filter = self.filter_rule, count = 1)
		#     dkpt_try.show()
		#     self.emit_filter_signal.emit(self.filter_rule)
		#     self.close()
		# except:
		#     reply = QMessageBox.question(self, 'Warning',
		#         "Filter rule is incorrect!\n  Do you modify?", QMessageBox.Yes|
		#         QMessageBox.No, QMessageBox.No )
		#     if reply == QMessageBox.No:
		#         self.close()
			

	def get_filter_rule(self):
		return self.filter_rule





if __name__ == '__main__':
	app = QApplication(sys.argv)
	ex = FilterWidget()
	ex.setGeometry(300, 50, 700, 500)
	ex.show()
	sys.exit(app.exec_())






