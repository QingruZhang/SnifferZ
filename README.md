# SnifferZ
## Author
+ Qingru Zhang
+ Shanghai Jiao Tong University


## Requirements

* Python >= 3.4.0 
* PyQt5 5.9
* scapy 2.4.0
* Pyx 0.14.1

### Installation ###
    pip install PyQt5
    pip install scapy
    pip install Pyx

_Ps_: For windows platform, directory "source/dependency" includes all required packages, you don not need to install them and follow the below steps to finsh testing. But for Linux platform, PyQt5 installation is needed.

## Getting started

### Brief Introduction
It is a course design about web packet sniffer. PyQt5 is used to design GUI.
scapy is used to sniffe and analyze packets.

### Run Code Directly
For windows paltform, you can run `main.py` without installation.
In the ``.\source\`` directory, run command:
```
    python3 main.py
```

For Linux paltform, PyQt5 installation is needed. And then, run:

```
    python3 main.py
```


### Some Points
For Linux platform, detail information tab is unabled.


### About File

| Dir   |      Comment      |
|----------|:-------------:|
|soruce/                   |    源代码文件夹  |
|source/dependency/        |    依赖库文件夹  |
|VirtualEnv/               |    虚拟环境文件夹 |
|source/img/               |    UI内使用的icon图标和项目Logo |
|source/tool/              |    包解析依赖的外部工具  |
|source/main.py            |    程序执行入口，执行命令：python main.py  |
|source/GUIDesign.py       |    定义UI主控件的文件  |
|source/InterFaceChoose.py |    UI初始执行时，网卡选择控件的定义文件 |
|source/FilterWidget.py    |    设置包嗅探过滤规则的Filter控件  |
|source/SnifferThread.py   |    定义包嗅探的多线程继承类    |
|source/MyTabel.py         |    主控件中表格展示控件的定义文件 |
|source/MyTabWidget.py     |    包解析选项卡控件的定义文件   |
|source/FileThread.py      |    文件处理线程  |
|README.md                 |    说明文档    |

