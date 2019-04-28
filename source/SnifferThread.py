from PyQt5 import QtCore
import scapy.all as Scapy
from scapy.all import *
import sys
import time, threading
import io
from contextlib import redirect_stdout
 

def get_packet_proto(pkt: Packet):
    summary_pkt = pkt.summary()
    sum_list = summary_pkt.split('/')
    if 'ARP' in sum_list[1]:
        return 'ARP'
    elif 'DARP' in sum_list[1]:
        return 'DARP'
    elif 'DHCP' in sum_list[1]:
        return 'DHCP'
    elif 'IPv6' in sum_list[1]:
        return 'IPv6' + '/' +sum_list[2].strip().split(' ')[0]
    elif 'IP' in sum_list[1]:
        if 'Raw' in sum_list[-1] or 'Padding' in sum_list[-1]:
            layer3 = sum_list[-2].strip()
        else:
            layer3 = sum_list[-1].strip()
        proto = layer3.split(' ')[0]
        return proto
    else:
        proto = sum_list[1].split(' ')[0]
        proto = proto.strip() + '/' + sum_list[2].split(' ')[1]
        return proto

def get_src_dst(pkt):
    try:
        src = pkt[IP].src
        dst = pkt[IP].dst
    except:
        src = pkt[0].src
        dst = pkt[0].dst
    return src, dst

def Reassemble_packet(plist):
    id_dict = {}
    for pkt in plist:
        if str(pkt[IP].id) not in id_dict.keys():
            id_dict[str(pkt[IP].id)] = PacketList()
            id_dict[str(pkt[IP].id)].append(pkt)
        else:
            id_dict[str(pkt[IP].id)].append(pkt) 
    
    result_dict = {}
    for id_key in id_dict.keys():
        tmp_dict = {}
        for pkt in id_dict[id_key]:
            tmp_dict[str(pkt[IP].frag)] = pkt
        try:
            result_dict[id_key] = tmp_dict['0']
        except:
            return None
        loads = b''
        for frag in sorted(tmp_dict.keys()):
            loads = loads + tmp_dict[frag].getlayer(Raw).load

        result_dict[id_key].len += len(loads) -  len(result_dict[id_key][Raw].load)
        result_dict[id_key][Raw].load = loads
        result_dict[id_key].flags = 2 
        result_dict[id_key].frag = 0 
    return result_dict


class SnifferThread(QtCore.QThread):

    update_ResultTable_signal = QtCore.pyqtSignal(int, Packet)

    def __init__(self, UI_stop_signal = None, iface = conf.iface, parent = None, pkt_num = 0, filter_UI = None, *args, **kwargs):
        
        super(SnifferThread, self).__init__(parent)

        self.dkpt = None
        self.filter = filter_UI
        self.pkt_num = pkt_num
        self.iface = iface
        self._stop_event = threading.Event()
        self.stop_sniff_signal = UI_stop_signal

        self.stop_sniff_signal.connect(self.join)

    def run(self):
        print('**Start Sniff')
        self.dkpt = sniff(iface = self.iface, filter = self.filter, prn = self._sniff_callback,
                            stop_filter = lambda p: self._stop_event.is_set())
        print('**End Sniff')

    def _sniff_callback(self, pkt: Packet):
        self.pkt_num += 1
        self.update_ResultTable_signal.emit(self.pkt_num, pkt)

    def join(self, isStop):
        if isStop:
            self._stop_event.set()
            print('*** Set Join Event On: %d'%self.currentThreadId())






