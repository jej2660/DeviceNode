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
        self.getLogger()

    def getLogger(self):
        __log = logging.getLogger("TableMaker")
        __log.setLevel(logging.DEBUG)
        stream_hander = logging.StreamHandler()
        stream_hander.setLevel(logging.DEBUG)
        __log.addHandler(stream_hander)
        #file_handler = logging.FileHandler('my.log')
        #file_handler.setLevel(logging.CRITICAL)
        #__log.addHandler(file_handler)
        self.logger = __log
        return __log

    def method_xref(self, dx):
        self.flow_tbl["xref"]={}
        self.logger.critical("-----XREF TBL START-----")
        for p_method in dx.get_methods():
            key=self.extract_class_name(str(p_method.get_class_name()))+"::"+str(p_method.name)
            if p_method.is_android_api():
                continue
            if (len(p_method.get_xref_to())>0):
                self.flow_tbl["xref"][key]=[]
                for c_method in p_method.get_xref_to():
                    value=self.extract_class_name(str(c_method[0].name))+"::"+str(c_method[1].name)
                    self.flow_tbl["xref"][key].append(value)
        self.logger.critical("-----XREF TBL FINISH-----")


    def class_methods_tbl(self, dx):
        self.flow_tbl["class-methods"]={}
        self.logger.critical("-----CLASS_METHODS TBL START-----")
        for c in dx.get_classes():
            if c.is_external() or c.is_android_api():
                continue
            key_class=self.extract_class_name(str(c.name))
            value_method=[]
            for method in c.get_methods():
                value_method.append(str(method.name))
                self.flow_tbl["class-methods"][key_class]=value_method
        self.logger.critical("-----CLASS_METHODS TBL FINISH-----")

    """
    def make_xref_root(self, dx,mainactivity):
        root=self.extract_class_name(mainactivity)
        main_activity="^"+FormatClassToJava(mainactivity)+"$"
        for cls in dx.find_classes(main_activity):
            self.xref_tbl[root]=[]
            tmp=[]
            for meth in cls.get_methods():
                self.xref_tbl[root].append(str(meth.name))
                tmp.append(meth)
                #self.make_xref_node(dx,meth)
            for m in tmp:
                self.make_xref_node(dx,m)

    def make_xref_node(self, dx, method):
        key=self.extract_class_name(str(method.get_class_name()))+"::"+str(method.name)
        tmp=[]
        if self.check_method(method):
            self.xref_tbl[key]=[]
            for meth in method.get_xref_to():
                value=self.extract_class_name(str(meth[0].name))+"::"+str(meth[1].name)
                self.xref_tbl[key].append(value)
                tmp.append(meth[1])
                #self.make_xref_node(dx,meth[1])
            for m in tmp:
                self.make_xref_node(dx,m)
        
    def check_method(self, method):
        if method.name in self.xref_tbl.keys():
            #self.logger.critical("already exist in xref_tbl keys")
            return False
        if method.is_external():
            #self.logger.critical("External")
            return False
        if method.is_android_api():
            #self.logger.critical("Android API")
            return False
        if(str(method.name) == "<init>"):
            #self.logger.critical("method name == <init>")
            return False
        else: 
            return True
    """

    def extract_class_name(self, dir_class):
        tmp=dir_class.split('/')
        class_name = tmp.pop()
        return class_name

    def string_xref_from(self, dx, string):
        for string in dx.find_strings(string):
            for meth in string.get_xref_from():
                self.logger.critical(self.extract_class_name(str(meth[0].name))+"::"+str(meth[1].name))