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
    def __init__(self, apk_hash):
        self.flow_tbl={}
        self.domain_tbl={}
        self.getLogger()
        self.apk_hash = apk_hash

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

    def extract_class_name(self, dir_class):
        tmp=dir_class.split('/')
        class_name = tmp.pop()
        return class_name

    def domain_xref_from(self,dx):
        for domain in dx.find_strings(r"([a-zA-Z0-9-_]+[$\.]){1,}(com$|net$|org$|biz$|into$|asia$|jobs$|mobi$|tel$|travel$|xxx$)"):
            key_domain=str(domain.get_value())
            print(str(domain.get_value())+" => xref from")
            tmp_ls=[]
            for meth in domain.get_xref_from():
                tmp_ls.append(self.extract_class_name(str(meth[0].name))+"::"+str(meth[1].name))
                print(self.extract_class_name(str(meth[0].name))+"::"+str(meth[1].name))
            self.domain_tbl[key_domain]=tmp_ls
            print("=====end====")

        for domain in dx.find_strings(r"([a-zA-Z0-9-_]+[$\.]){1,}((co$)?|(go)?|(ac)?|(ne)?|(nm)?|(or)?|(re)?)(kr$|jp$|cn$|in$|mx$|us$|de$|tv$|me$)"):
            key_domain=str(domain.get_value())
            print(str(domain.get_value())+" => xref from")
            tmp_ls=[]
            for meth in domain.get_xref_from():
                tmp_ls.append(self.extract_class_name(str(meth[0].name))+"::"+str(meth[1].name))
                print(self.extract_class_name(str(meth[0].name))+"::"+str(meth[1].name))
            self.domain_tbl[key_domain]=tmp_ls
            print("=====end====")

    def is_obfuscated(self, dx, mainactivity):
        mainactivity="^"+FormatClassToJava(mainactivity)+"$"
        findClass =dx.find_classes(mainactivity)
        listfindClass = list(findClass)
        if len(listfindClass):
            return True
        else:
            self.logger.critical("APK IS OBFUSCATED")
            return False