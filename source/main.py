import sys
sys.path.append(r"./dependency/")
sys.path.append(r"./dependency/PyQt5_Pack/")
from GUIDesign import *


if __name__ == '__main__':
    app = QApplication(sys.argv)
    GUI_Window = GUI_Design()
    GUI_Window.Initial_Begining()
    sys.exit(app.exec_())