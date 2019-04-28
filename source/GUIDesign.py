import sys, time, copy
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon,QPalette,QPixmap,QFont, QColor
from PyQt5.QtWidgets import *
import scapy.all as Scapy
from scapy.all import Packet
from MyTabel import *
import SnifferThread
import InterFaceChoose
import MyTabWidget
import FileThread
import FilterWidget

class CentralWidget(QWidget):
    def __init__(self, Horizontal_label):
        super().__init__()
        self.init_UI(Horizontal_label)

    def init_UI(self, Horizontal_label):

        self.Hboxs = {
            'filter_hbox' : QHBoxLayout(),
            'result_hbox' : QHBoxLayout(),
            'analysis_hbox' : QHBoxLayout(),
            'iface_info' : QHBoxLayout(),
        }

        self.Vbox = QVBoxLayout()

        self.iface_label = QLabel('Choose Iface:')
        self.iface_label.setFont(QFont("Roman times",12,QFont.Bold))
        self.iface_comb = QComboBox(self)
        self.iface_comb.setFont(QFont("Ubuntu Mono", 10))

        self.lineEidt = QLineEdit(self)
        self.query_but = QPushButton("Query Info")
        self.Hboxs['filter_hbox'].addWidget(self.lineEidt)
        self.Hboxs['filter_hbox'].addWidget(self.query_but)
        self.Hboxs['filter_hbox'].addStretch(1)
        self.Hboxs['filter_hbox'].addWidget(self.iface_comb)
        self.Filter_Iface_widget = QWidget()
        self.Filter_Iface_widget.setLayout(self.Hboxs['filter_hbox'])

        self.table_result = Result_Table(Horizontal_label)
        self.table_result_cellClicked = self.table_result.tablewidget.cellDoubleClicked
        # self.Hboxs['result_hbox'].addWidget(self.table_result)
        
        self.tab_analysis = MyTabWidget.MyTableWidget()
        self.gene_pdf_but = self.tab_analysis.pdf_but
        # self.Hboxs['analysis_hbox'].addWidget(self.tab_analysis)

        self.tmp_widget = {}
        for key in ['filter_hbox']:
            self.tmp_widget[key] = QWidget()
            self.tmp_widget[key].setLayout(self.Hboxs[key])

        self.Vbox.addWidget(self.tmp_widget['filter_hbox'])
        self.Vbox.addWidget(self.table_result.tablewidget)
        self.Vbox.addWidget(self.tab_analysis.tabs_analysis)

        self.setLayout(self.Vbox)
 
    def clear_table_result(self):
        self.table_result.clear()

    def Insert_one_row_to_Result_Table(self, singalRow):
        rowPosition = self.table_result.InsertOneRow(singalRow)
        return rowPosition

    def Insert_row_given_index(self, rowIndex, singelRow):
        self.table_result.insert_to_row_index(rowIndex, singelRow)

    def Set_Iface_Comb(self, iface_names, text):
        self.iface_comb.addItems(iface_names)
        index = iface_names.index(text)
        self.iface_comb.setCurrentText(text)

    def set_comb_iface(self, text):
        self.iface_comb.setCurrentText(text)

    def set_auto_scoll(self, is_set):
        self.table_result.set_auto_scoll(is_set)

    def auto_adjust_result_header(self):
        self.table_result.adjust_RowHeader()

    def renew_tabs_most(self, pkt: Scapy.Packet):
        self.tab_analysis._renew_most(pkt)

    def renew_tabs_pdf(self, ready):
        self.tab_analysis._renew_pdf(ready)

    def set_pdf_tab_waiting(self):
        self.tab_analysis._set_pdf_tab_waiting()

    def clear_all_tabs(self):
        self.tab_analysis._clear_all_tabs()

    def get_search_word(self):
        return self.lineEidt.text()

    def build_tabel(self, Pdict:dict, keep_index = False):
        self.table_result.clear()
        for i,raw_index in enumerate(Pdict.keys()):
            if keep_index:
                self.table_result.insert_to_row_index(i,Pdict[raw_index])
            else:
                self.table_result.InsertOneRow(Pdict[raw_index])

    def update_reassemble_tab(self, pdict):
        self.tab_analysis.update_reassemble(pdict)



class GUI_Design(QMainWindow):

    stop_sniff_signal = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        self.Horizontal_label = [ 
            'No.' , 'Time', 'Source', 'Destination', 'Protocal', 'Length', 'Info' 
        ]

        self.pkt_num = 0
        self.packet_history = {}
        self.row_analysis = None
        self.startTime = 0

        self.filter_UI = None
        self.build_filter_win = FilterWidget.FilterWidget()
        self.build_filter_win.emit_filter_signal.connect(self.set_UI_filter)

        self.iface_choose = None
        self.iface_window = InterFaceChoose.IfaceWidget()

        self.iface_window.combo.activated[str].connect(self.set_Initial_Iface)
        self.iface_window.quit_but.clicked.connect(self.close)
        self.iface_window.confrim_but.clicked.connect(self.LaunchRun)

        self.initUI()

    def initUI(self):         
        self.setWindowIcon(QIcon('img/SnifferLogo.png'))    

        # self.menubar and toolbar
        self.statusbar = self.statusBar()
        self.statusbar.showMessage('Ready')

        # Menubar Action
        self.exitAct = QAction(QIcon('img/Exit.png'), '&Exit', self)        
        self.exitAct.setShortcut('Ctrl+Q')
        self.exitAct.setStatusTip('Exit application')
        self.exitAct.triggered.connect(self.close)

        self.openFile = QAction(QIcon('img/OpenFile.png'), '&Open File', self)
        self.openFile.setShortcut('Ctrl+O')
        self.openFile.setStatusTip('Open Saved File')
        self.openFile.triggered.connect(self.OpenFile)

        self.saveFile = QAction(QIcon('img/SaveFile.png'), '&Save File', self )
        self.saveFile.setShortcut('Ctrl+s')
        self.saveFile.setStatusTip('Save Selected Package')
        self.saveFile.triggered.connect(self.SaveFile)

        self.viewStatAct = QAction('View statusbar', self, checkable=True)
        self.viewStatAct.setStatusTip('View statusbar')
        self.viewStatAct.setChecked(True)
        self.viewStatAct.triggered.connect(self.toggleMenu)

        self.setScollAct = QAction('Auto Scoll', self, checkable = True)
        self.setScollAct.setStatusTip('Set Auto Scoll or Not')
        self.setScollAct.setChecked(True)
        self.setScollAct.triggered.connect(self.SetScoll)

        self.adjustHeader = QAction(QIcon('img/AdjustHeader.png'), 'Adjust Header', self)
        self.adjustHeader.setStatusTip('Auto Adjust Result Tbale Header')

        self.showHistory = QAction(QIcon('img/ShowHistory.png'),'Show History', self)
        self.showHistory.setStatusTip('Show Packet History')


        # tool bar
        self.toolbar = self.addToolBar('Tools')

        self.startAct = QAction(QIcon('img/StartAct.png'), '&Start Capture', self)
        self.startAct.setShortcut('Ctrl+B')
        self.startAct.setStatusTip('Start Capturing Package')
        self.startAct.triggered.connect(self.StartSniff)

        self.stopAct = QAction(QIcon('img/StopAct.png'), '&Stop Capture', self)
        self.stopAct.setShortcut('Ctrl+W')
        self.stopAct.setStatusTip('Stop Capturing Package')
        self.stopAct.triggered.connect(self.StopSniff)

        self.restartAct = QAction(QIcon('img/RestartAct.png'), '&Restart Capture', self)
        self.restartAct.setShortcut('Ctrl+Shift+B')
        self.restartAct.setStatusTip('Restart Capturing Package')
        self.restartAct.triggered.connect(self.RestartAct)


        self.chooseInterf = QAction(QIcon('img/ChooseInterf.png'), '&Choose interface', self)
        self.chooseInterf.setShortcut('Ctrl+T')
        self.chooseInterf.setStatusTip('Choose the interface to be captured')
        self.chooseInterf.triggered.connect(self.ChooseInterf)

        self.clearAct = QAction(QIcon('img/ClearAct.png'), '&Clear History', self)
        self.clearAct.setShortcut('Ctrl+Shift+C')
        self.clearAct.setStatusTip('Clear All History')
        self.clearAct.triggered.connect(self.clear_all)

        self.filterAct = QAction(QIcon('img/FilterAct.png'), '&Set Filter', self)
        self.filterAct.setShortcut('Ctrl+Shift+F')
        self.filterAct.setStatusTip('Set Filter Rule')
        self.filterAct.triggered.connect(self.build_filter_win.show)

        self.reassemAct = QAction(QIcon('img/ReassemAct.png'), '&Reassemble Packet', self)
        self.reassemAct.setShortcut('Ctrl+Shift+R')
        self.reassemAct.setStatusTip('Reassemble Packet Selected')
        self.reassemAct.triggered.connect(self.reassemble_pkt)

        self.toolbar.addAction(self.startAct)
        self.toolbar.addAction(self.stopAct)
        self.toolbar.addAction(self.restartAct)
        self.toolbar.addAction(self.openFile)
        self.toolbar.addAction(self.saveFile)
        self.toolbar.addAction(self.showHistory)
        self.toolbar.addAction(self.clearAct)
        self.toolbar.addAction(self.chooseInterf)
        self.toolbar.addAction(self.filterAct)
        self.toolbar.addAction(self.reassemAct)
        self.toolbar.addAction(self.adjustHeader)
        self.toolbar.addAction(self.exitAct)


        # meunbar
        self.menubar = self.menuBar()

        self.fileMenu = self.menubar.addMenu('File(&F)')
        self.fileMenu.addAction(self.openFile)
        self.fileMenu.addAction(self.saveFile)
        self.fileMenu.addAction(self.exitAct)

        self.sniffMenu = self.menubar.addMenu('Sniff(&S)')
        self.sniffMenu.addAction(self.startAct)
        self.sniffMenu.addAction(self.stopAct)
        self.sniffMenu.addAction(self.restartAct)

        self.toolMenu = self.menubar.addMenu('Tool(&T)')
        self.toolMenu.addAction(self.chooseInterf)
        self.toolMenu.addAction(self.filterAct)
        self.toolMenu.addAction(self.reassemAct)


        self.viewMenu = self.menubar.addMenu('View(&V)')
        self.viewMenu.addAction(self.showHistory)
        self.viewMenu.addAction(self.adjustHeader)
        self.viewMenu.addAction(self.viewStatAct)
        self.viewMenu.addAction(self.setScollAct)

        self.quitMenu = self.menubar.addMenu('Quit(&Q)')
        self.quitMenu.addAction(self.exitAct)

        # Central Widget
        self.central_Widget = CentralWidget(self.Horizontal_label)
        self.central_Widget.iface_comb.activated[str].connect(self.Change_Iface_from_combo)
        # connect the adjust header action of view menu to the auto adjust result header
        self.adjustHeader.triggered.connect(self.central_Widget.auto_adjust_result_header)
        self.showHistory.triggered.connect(self.show_packet_history)
        # connect the result table click signal to the tabs for analysis
        self.central_Widget.table_result_cellClicked.connect(self.update_tabs)
        # connect the query info button to the preSearch thread
        self.central_Widget.query_but.clicked.connect(self.search_info)
        # connect the pdf generate button to the analysis thread
        self.central_Widget.tab_analysis.pdf_but.clicked.connect(self.update_pdf_tab)

        self.setCentralWidget(self.central_Widget)

        self.setGeometry(300, 100, 1000, 950)
        self.setWindowTitle('SnifferZ')  

    def Initial_Begining(self):
        self.iface_window.show()

    def set_Initial_Iface(self, text):
        self.iface_choose = text
        self.iface_list_all = Scapy.get_windows_if_list()
        iface_names = [ item['name'] for item in self.iface_list_all ]
        self.central_Widget.Set_Iface_Comb(iface_names, text)

    def LaunchRun(self):
        self.show()
        self.StopSniff()

    def SetScoll(self, state):
        self.central_Widget.set_auto_scoll(state)

    def OpenFile(self):
        fileName, filetype = QFileDialog.getOpenFileName(self, "选取文件", "./",  "WireShark Tcpdump (*.cap);;All Files (*);;") 
        if fileName:
            try:
                pkt_from_file = Scapy.rdpcap(fileName)
                self.clear_all()
                for i,pkt in enumerate(pkt_from_file):
                    self.packet_history[str(i)] = pkt
                    SingelRow = self.build_pkt_dict(i+1,pkt)
                    self.central_Widget.Insert_row_given_index(i, SingelRow)
                self.pkt_num = i+1
            except:
                QMessageBox.question(self, 'Warning',
                        "Cannot Open the Selected File!", QMessageBox.Yes)

    def SaveFile(self):
        indexs = self.central_Widget.table_result.tablewidget.selectedIndexes()
        row_indexs = set(index.row() for index in indexs )
        print(row_indexs)
        if row_indexs:
            Pdict = {}
            for index in row_indexs:
                Pdict[str(index)] = self.packet_history[str(index)]
        else:
            Pdict = self.packet_history
        save_path, ok2 = QFileDialog.getSaveFileName(self, "文件保存", "./", "WireShark Tcpdump (*.cap);;All Files (*)")
        save_thread = FileThread.FileSaveThread(save_path, Pdict, parent = self)
        save_thread.start()

    def reassemble_pkt(self):
        indexs = self.central_Widget.table_result.tablewidget.selectedIndexes()
        row_indexs = set(index.row() for index in indexs )
        print(row_indexs)
        if row_indexs:
            Plist = Scapy.PacketList()
            for index in row_indexs:
                pkt = copy.deepcopy(self.packet_history[str(index)])
                Plist.append(pkt)
            print('Reassemble:', Plist,len(Plist))
            Scapy.wrpcap('test.cap', Plist)
            Plist.show()
            self.reassem_dict = SnifferThread.Reassemble_packet(Plist)
            if self.reassem_dict:
                self.central_Widget.update_reassemble_tab(self.reassem_dict)
            else:
                QMessageBox.question(self, 'Warning',
                        "Please Select the Entire Packet Group!", QMessageBox.Yes|
                        QMessageBox.No, QMessageBox.No )
        else:
            QMessageBox.question(self, 'Warning',
                        "Please Select the packet to Reassemble!", QMessageBox.Yes|
                        QMessageBox.No, QMessageBox.No )



    def StartSniff(self):
        if self.pkt_num == 0:
            self.stop_sniff_signal.emit(True)
            self.clear_all()
            self.startTime = time.time()
            self.sniff_thread = SnifferThread.SnifferThread(UI_stop_signal = self.stop_sniff_signal, iface = self.iface_choose,
                            filter_UI = self.filter_UI )
            self.sniff_thread.start()
            self.sniff_thread.update_ResultTable_signal.connect(self.Update_ResultTable)
            self.startAct.setEnabled(False)
            self.stopAct.setEnabled(True)
            self.saveFile.setEnabled(False)
            self.openFile.setEnabled(False)
            self.filterAct.setEnabled(False)
            self.chooseInterf.setEnabled(False)
            self.exitAct.setEnabled(False)
        else:
            self.stop_sniff_signal.emit(True)
            self.sniff_thread = SnifferThread.SnifferThread(UI_stop_signal = self.stop_sniff_signal, iface = self.iface_choose,
                             pkt_num = self.pkt_num, filter_UI = self.filter_UI )
            self.sniff_thread.update_ResultTable_signal.connect(self.Update_ResultTable)
            self.sniff_thread.start()
            self.startAct.setEnabled(False)
            self.stopAct.setEnabled(True)
            self.saveFile.setEnabled(False)
            self.openFile.setEnabled(False)
            self.filterAct.setEnabled(False)
            self.chooseInterf.setEnabled(False)
            self.exitAct.setEnabled(False)

    def StopSniff(self):
        self.stop_sniff_signal.emit(True)
        self.stopAct.setEnabled(False)
        self.startAct.setEnabled(True)
        self.saveFile.setEnabled(True)
        self.openFile.setEnabled(True)
        self.filterAct.setEnabled(True)
        self.chooseInterf.setEnabled(True)
        self.filterAct.setEnabled(True)
        self.exitAct.setEnabled(True)

    def RestartAct(self):
        self.stop_sniff_signal.emit(True)
        self.clear_all()
        self.startTime = time.time()
        self.sniff_thread = SnifferThread.SnifferThread(UI_stop_signal = self.stop_sniff_signal, iface = self.iface_choose,
                             pkt_num = self.pkt_num, filter_UI = self.filter_UI )
        self.sniff_thread.update_ResultTable_signal.connect(self.Update_ResultTable)
        self.sniff_thread.start()
        self.startAct.setEnabled(False)
        self.stopAct.setEnabled(True)
        self.saveFile.setEnabled(False)
        self.openFile.setEnabled(False)
        self.filterAct.setEnabled(False)
        self.chooseInterf.setEnabled(False)
        self.exitAct.setEnabled(False)


    def ChooseInterf(self):
        reply = QMessageBox.question(self, 'Warning',
            "Change IterFace will Quit Current Window?", QMessageBox.Yes|
            QMessageBox.No, QMessageBox.No )
        if reply == QMessageBox.Yes:
            self.StopSniff()
            self.close()
            self.Initial_Begining()
        else:
            self.central_Widget.set_comb_iface(self.iface_choose)


    def Change_Iface_from_combo(self, text):
        reply = QMessageBox.question(self, 'Warning',
            "Change Iterface will clear all result?", QMessageBox.Yes|
            QMessageBox.No, QMessageBox.No )
        if reply == QMessageBox.Yes:
            self.StopSniff()
            self.clear_all()
            self.iface_choose = text
        else:
            self.central_Widget.set_comb_iface(self.iface_choose)


    def clear_all(self):
        self.StopSniff()
        self.central_Widget.clear_table_result()
        self.central_Widget.clear_all_tabs()
        self.pkt_num = 0
        del self.packet_history
        self.packet_history = {}
        # clear analysis
    
    
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


    def Update_ResultTable(self, No, pkt: Packet):
        SingelRow = self.build_pkt_dict(No,pkt)
        nowRowpos = self.central_Widget.Insert_one_row_to_Result_Table(SingelRow)
        self.packet_history[str(nowRowpos)] = pkt
        self.pkt_num = len(self.packet_history)



    def update_tabs(self, row, coloum):
        if row != self.row_analysis:
            self.row_analysis = row
            pkt = self.packet_history[str(row)]
            self.central_Widget.clear_all_tabs()
            self.central_Widget.renew_tabs_most(pkt)

            # pdf_write_thread = FileThread.PDFthread(pkt, parent = self)
            # pdf_write_thread.finsh_write_signal.connect(self.central_Widget.renew_tabs_pdf)
            # self.central_Widget.set_pdf_tab_waiting()
            # pdf_write_thread.start()

    def update_pdf_tab(self):
        if self.row_analysis is not None:
            pkt = self.packet_history[str(self.row_analysis)]
            pdf_write_thread = FileThread.PDFthread(pkt, parent = self)
            pdf_write_thread.finsh_write_signal.connect(self.central_Widget.renew_tabs_pdf)
            self.central_Widget.set_pdf_tab_waiting()
            pdf_write_thread.start()


    def set_UI_filter(self, text:str):
        self.clear_all()
        self.filter_UI = text
        print('--->Set Filter  Rule: %s'%self.filter_UI)


    def search_info(self):
        self.search_word = self.central_Widget.get_search_word()
        print('Search Word:',self.search_word)
        if self.search_word:
            self.StopSniff()
            self.central_Widget.clear_table_result()
            for index_key in self.packet_history.keys():
                if self.search_word in repr(self.packet_history[index_key]):
                    dict_tmp =  self.build_pkt_dict(index_key ,self.packet_history[index_key])
                    self.central_Widget.Insert_one_row_to_Result_Table(dict_tmp)


    def show_packet_history(self):
        self.StopSniff()
        self.central_Widget.clear_table_result()
        for index_key in self.packet_history.keys():
            dict_tmp = self.build_pkt_dict(index_key ,self.packet_history[index_key])
            self.central_Widget.Insert_row_given_index(int(index_key), dict_tmp)


    def toggleMenu(self, state):
        if state:
            self.statusbar.show()
        else:
            self.statusbar.hide()

    def contextMenuEvent(self, event): #function about right mouse
       cmenu = QMenu(self)
       cmenu.addAction(self.openFile)
       cmenu.addAction(self.saveFile)
       cmenu.addAction(self.clearAct)
       cmenu.addAction(self.reassemAct)
       cmenu.addAction(self.showHistory)
       cmenu.addAction(self.exitAct)
       action = cmenu.exec_(self.mapToGlobal(event.pos()))

    # def closeEvent(self, event):
    #     reply = QMessageBox.question(self, 'Message',
    #         "Are you sure to quit?", QMessageBox.Yes|
    #         QMessageBox.No, QMessageBox.No )

    #     if reply == QMessageBox.Yes:
    #         event.accept()
    #     else:
    #         event.ignore()       


if __name__ == '__main__':
    app = QApplication(sys.argv)
    GUI_Window = GUI_Design()
    GUI_Window.Initial_Begining()
    sys.exit(app.exec_())