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
import re
from collections import OrderedDict



class TraceFlow:
    def __init__(self,dx,apk_hash):
        self.apk_hash = apk_hash
        self.search_list = []
        self.find_list = ["startActivity","startService","startActivityForResult","bindService","stopService","run"]
        self.act_change = []
        self.Log_list = []
        self.getLogger()
        self.dx = dx
        self.activitychangelist =[]
        self.bindList = []
        self.servicelist = []
        self.threadlist = []
        self.log_debug = self.getLogger_debug()

    def getLogger(self):
        __log = logging.getLogger("TraceFlow")
        __log.setLevel(logging.DEBUG)
        stream_hander = logging.StreamHandler()
        stream_hander.setLevel(logging.DEBUG)
        __log.addHandler(stream_hander)
        file_handler = logging.FileHandler(self.apk_hash+'/my.log')
        file_handler.setLevel(logging.CRITICAL)
        __log.addHandler(file_handler)
        self.logger = __log
        return __log

    def getLogger_debug(self):
        __log = logging.getLogger("TraceFlow")
        __log.setLevel(logging.DEBUG)
        stream_hander = logging.StreamHandler()
        stream_hander.setLevel(logging.DEBUG)
        __log.addHandler(stream_hander)
        file_handler = logging.FileHandler(self.apk_hash+'/debug.log')
        file_handler.setLevel(logging.CRITICAL)
        __log.addHandler(file_handler)
        self.logger = __log
        return __log

    def searching(self, method, path, depth):
        if(method.is_external() or method.is_android_api()):
            #self.logger.critical("["+str(depth)+"]"+"EXTERNAL OR API")
            return

        if(method.name == "<init>"):
            #self.logger.critical("["+str(depth)+"]"+"INIT_END")
            return
        if str(method.class_name)+str(method.name) in self.search_list:
            return
        self.search_list.append(str(method.class_name)+str(method.name))
        for meth in method.get_xref_to():
            if (meth[1].name in self.find_list):
                tmp_path = path.copy()
                tmp_path.append(self.extract_class_name(str(meth[0].name) + "::" + str(meth[1].name)))

                self.logger.critical("Find transition ---> " + (self.extract_class_name(str(meth[0].name) + "::" + str(meth[1].name))))
                self.nextProcessing(method, meth[1], tmp_path)
    
        for meth in method.get_xref_to():
            tmp_path = path.copy()
            if meth[1].name in self.find_list:
                continue
            if str(method.name) == str(meth[1].name):
                self.logger.critical("Loop!")
                continue
            tmp_path.append(self.extract_class_name(str(meth[0].name) + "::" + str(meth[1].name)))
            #self.logger.critical("["+ str(depth) + "]" +" Current Pos:" + toString(tmp_path))
            self.logger.critical("["+ str(depth) + "]" + "Next_Search: " + str(meth[0].name) + "::" + str(meth[1].name))
            self.searching(meth[1],tmp_path,depth+1)
            
    
    def nextProcessing(self, caller, method, path):
        methodname = str(method.name)
        if (methodname in ["startActivity", "startActivityForResult"]):
            self.logger.critical("\n----Activity Transition Occur!!----\n")
            nextclasslist = self.activityAnalysis(caller)
            if (nextclasslist == None):
                self.logger.critical("error occur At nextProcessing()")
            #class_name = self.extract_class_name(str(nextclass)) + "::" + "onCreate"
            for nextclass in nextclasslist:
                tmp_path = path.copy()
                class_name = self.extract_class_name(str(FormatClassToJava(nextclass.lstrip()))) + "::" + "onCreate"
                #tmp_path.append(class_name)
                self.activitychangelist.append(tmp_path)
                self.traceChange(nextclass.lstrip(), tmp_path)
        elif (methodname in ["bindService"]):
            self.logger.critical("\n----Binding Occur!!----\n")
            nextclasslist = self.activityAnalysis(caller)
            if (nextclasslist == None):
                self.logger.critical("error occur At nextProcessing()")
            for nextclass in nextclasslist:
                tmp_path = path.copy() 
                class_name = self.extract_class_name(str(FormatClassToJava(nextclass.lstrip()))) + "::" + "onBind"
                #tmp_path.append(class_name)
                self.bindList.append(tmp_path)
                self.traceChange(nextclass.lstrip(), tmp_path)
        elif (methodname in ["startService", "stopService"]):
            self.logger.critical("\n----Binding Occur!!----\n")
            nextclasslist = self.activityAnalysis(caller)
            if (nextclasslist == None):
                self.logger.critical("error occur At nextProcessing()")
            for nextclass in nextclasslist:
                tmp_path = path.copy()
                if(methodname == "startService"):
                    class_name = self.extract_class_name(str(FormatClassToJava(nextclass.lstrip()))) + "::" + "onCreate"
                    #tmp_path.append(class_name)
                    class_name = self.extract_class_name(str(FormatClassToJava(nextclass.lstrip()))) + "::" + "onStartCommand"
                    #tmp_path.append(class_name)
                if(methodname == "stopService"):
                    class_name = self.extract_class_name(str(FormatClassToJava(nextclass.lstrip()))) + "::" + "onDestroy"
                    #tmp_path.append(class_name)
                self.servicelist.append(tmp_path)
                self.traceChange(nextclass.lstrip(), tmp_path)
        elif (methodname in ["run"]):
            self.logger.critical("\n--------Thread Occur!!------\n")
            #path.append(self.extract_class_name(str(method.get_class_name())) + "::" + "run")
            self.threadlist.append(path)


    def traceChange(self, startPoint, path):
        try:
            classlist = self.dx.find_classes("^"+FormatClassToJava(startPoint)+"$")
            for cls in classlist:
                for me in cls.get_methods():
                    tmp_act_path = path.copy()
                    #self.logger.critical("--------Root---------------")
                    #self.logger.critical(self.extract_class_name(str(cls.name))+"::"+str(me.name))
                    tmp_act_path.append(self.extract_class_name(str(cls.name))+"::"+str(me.name))
                    self.searching(me,tmp_act_path,0)
        except:
            return
                

    def extract_class_name(self, dir_class):
        tmp=dir_class.split('/')
        class_name = tmp.pop()
        class_name = class_name.replace(";","")
        return class_name

    def activityAnalysis(self, meth):
        self.log_debug.critical("----------parsing activity Find-------------")
        self.log_debug.critical(str(meth.class_name) + str(meth.name))
        #self.log_debug.critical(str(meth.get_method().get_source()) + "\n")
        if meth.is_external() or meth.is_android_api():
            return
        meth = meth.get_method()
        searchdata = meth.get_source()
        regex = re.compile('Intent\(.*?\,(.*[a-z])\)')
        test_str = searchdata

        match=regex.findall(test_str)
        self.log_debug.critical("Input:" + str(match))
        return match
        #return FormatClassToJava(match.group(1).lstrip())

    def getChangeList(self):
        print(self.activitychangelist)
        print(self.servicelist)
        print(self.bindList)
    
    def get_json(self):
        output = {}
        output["activitychangelist"] = self.activitychangelist
        output["bindList"] = self.bindList
        output["servicelist"] = self.servicelist
        output["threadlist"] = self.threadlist

        with open(self.apk_hash+'/trainstion.json', 'w') as f:
            json.dump(output,f, indent=4) 

            