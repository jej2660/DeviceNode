import sys
import json
from utils import *
from androguard import *
from androguard import misc
from androguard import session
from androguard.core.bytecode import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
from androguard.decompiler.decompiler import DecompilerJADX
from androguard.misc import AnalyzeAPK
from androguard.core.androconf import show_logging
import logging
from collections import OrderedDict



class TraceFlow:
    def __init__(self):
        self.find_list = ["startActivity", "startService"]
        self.Log_list = []

    def getLogger(self):
        __log = logging.getLogger("TraceFlow")
        __log.setLevel(logging.INFO)
        #stream_hander = logging.StreamHandler()
        #__log.addHandler(stream_hander)
        #file_handler = logging.FileHandler('my.log')
        #__log.addHandler(file_handler)
        self.logger = __log
        return __log

    def search(self, path, method):
        #종결 조건
        if(method.name in self.find_list):
            self.logger.critical("Find!"+ toString(path))
            self.Log_list.append(path)
        if(method.name == "<init>"):
            return
            
        for meth in method.get_xref_to():
            tmp_path = path
            tmp_path.append(meth[0].name + "::" + meth[1].name)
            self.logger.info("Current path: " + meth[0].name + "::" + meth[1].name)
            self.logger.info("Full path" + toString(tmp_path))

            self.search(tmp_path, meth[1])

    def traceMethod(self, dx, startPoint, table):
        if table == None:
            clslist = dx.find_classes(startPoint)
            for cls in clslist:
                self.logger.info(cls.name)
                for meth in cls.get_methods():
                    self.logger.info(meth.name)
                    tmp_path = [cls.name + "::" + meth.name]
                    self.search(tmp_path, meth)
                    
#내일 할일 startActivity를 찾았을 때 어떤 class로 던지는지를 찾아야함 ㅇㅇ이거 가능하나 ? ㅋㅋㅋ
            
            