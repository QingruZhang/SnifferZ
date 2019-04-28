import sys, time
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon,QPalette,QPixmap,QFont
from PyQt5.QtWidgets import *
import scapy.all as Scapy

class IfaceWidget(QWidget):
    
    def __init__(self):
        super().__init__()
        self.ifaces_list_all = Scapy.get_windows_if_list()
        self.ifaces_name_list = [ item['name'] for item in self.ifaces_list_all ]
        self.initUI()
        
        
    def initUI(self):   
        self.setWindowIcon(QIcon('img/SnifferLogo.png'))    
        self.v_layout = QVBoxLayout()
        self.h_layout_button = QHBoxLayout()

        self.logo = QLabel()
        self.logo.setPixmap(QPixmap('img/SnifferLogo.png'))
        self.logo_layout = QHBoxLayout()
        self.logo_layout.addStretch(1)
        self.logo_layout.addWidget(self.logo)
        self.logo_layout.addStretch(1)
        self.logo_widget = QWidget()
        self.logo_widget.setLayout(self.logo_layout)

        self.lbl = QLabel("Choose the IterFace:", self)
        self.lbl.setFixedHeight(80)
        self.lbl.setFont(QFont("Roman times",16,QFont.Bold))

        self.combo = QComboBox(self)
        self.combo.addItems(self.ifaces_name_list)
        self.combo.setFont(QFont("Ubuntu Mono", 12, QFont.Bold))
        self.combo.setCurrentText('Choose Iface')

        self.combo.activated[str].connect(self.onActivated)  

        self.confrim_but = QPushButton('OK')   
        self.quit_but = QPushButton('Quit')  
        self.h_layout_button.addStretch(1)
        self.h_layout_button.addWidget(self.confrim_but)
        self.h_layout_button.addWidget(self.quit_but)
        self.h_widget_button = QWidget()
        self.h_widget_button.setLayout(self.h_layout_button)

        self.quit_but.clicked.connect(self.close)
        self.confrim_but.clicked.connect(self.close)

        self.v_layout.addWidget(self.logo_widget)
        self.v_layout.addStretch(0.5)
        self.v_layout.addWidget(self.lbl)
        self.v_layout.addStretch(0.2)
        self.v_layout.addWidget(self.combo)
        self.v_layout.addStretch(1)
        self.v_layout.addWidget(self.h_widget_button)

        self.setLayout(self.v_layout)

        self.setWindowIcon(QIcon('img/SnifferLogo.png'))
        self.setGeometry(300, 100, 500, 200)
        self.setWindowTitle('QComboBox')

        
        
    def onActivated(self, text):
      
        self.lbl.setText('Choosed Iface: \n \t %s'%text)
        self.lbl.adjustSize()  
        
                
if __name__ == '__main__':
    
    app = QApplication(sys.argv)
    singal_chooseWidget = IfaceWidget()
    singal_chooseWidget.show()
    sys.exit(app.exec_())

