import sys
import logging
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
from apkanalyzer import Apkanlyzer

# entrypoint class를 전달받고 이를 통해 언오더드맵을 사용하여 테이블을 제작

class TableMaker:
    def __init__(self):
        self.flow_tbl={}

    def getLogger(self):
        __log = logging.getLogger("TraceFlow")
        __log.setLevel(logging.DEBUG)
        stream_hander = logging.StreamHandler()
        stream_hander.setLevel(logging.DEBUG)
        __log.addHandler(stream_hander)
        file_handler = logging.FileHandler('my.log')
        file_handler.setLevel(logging.CRITICAL)
        __log.addHandler(file_handler)
        self.logger = __log
        return __log

    def xref_tbl(self, dx):
        self.flow_tbl["xref"]={}
        for p_method in dx.get_methods():
            key=self.extract_class_name(str(p_method.get_class_name()))+"::"+str(p_method.name)
            if p_method.is_android_api():
                continue
            if (len(p_method.get_xref_to())>0):
                self.flow_tbl["xref"][key]=[]
                for c_method in p_method.get_xref_to():
                    value=self.extract_class_name(str(c_method[0].name))+"::"+str(c_method[1].name)
                    self.flow_tbl["xref"][key].append(value)
        with open('flow_tbl.json', 'w') as f:
            json.dump(self.flow_tbl,f)   
        f.close()
        self.logger.critical("Make XREF tbl Finished")

    def class_methods_tbl(self, dx):
        self.flow_tbl["class-methods"]={}
        for c in dx.get_classes():
            if c.is_external() or c.is_android_api():
                continue
            key_class=self.extract_class_name(str(c.name))
            for method in c.get_methods():
                value_method=[]
                value_method.append(str(method.name))
                self.flow_tbl["class-methods"][key_class]=value_method

    def extract_class_name(self, dir_class):
        tmp=dir_class.split('/')
        class_name = tmp.pop()
        return class_name

    def string_xref_from(self, dx, string):
        for string in dx.find_strings(string):
            for meth in string.get_xref_from():
                self.logger.critical(self.extract_class_name(str(meth[0].name))+"::"+str(meth[1].name))