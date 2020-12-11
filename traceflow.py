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
        self.find_list = ["startActivity","startService","startActivityForResult","bindService"]
        self.act_change = []
        self.Log_list = []
        self.getLogger()
        self.dx = dx
        self.activitychangelist =[]
        self.bindList = []
        self.servicelist = []

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


#path = [main::oncreat, Strat:start, Start::startActivity, Deviceser::onCreate, ]
    def searching(self, method, path, depth):
        #####
        if(method.is_external() or method.is_android_api()):
            self.logger.critical("["+str(depth)+"]"+"EXTERNAL OR API")
            return

        if(method.name == "<init>"):
            self.logger.critical("["+str(depth)+"]"+"INIT_END")
            return
        ###########
#deviceser::oncreate -> servec()
        for meth in method.get_xref_to():
            if (meth[1].name in self.find_list):
                path.append(self.extract_class_name(str(meth[0].name) + "::" + str(meth[1].name)))
                #path = [main::oncreat, Strat:start, Start::startActivity]
                self.logger.critical("Find transition ---> " + (self.extract_class_name(str(meth[0].name) + "::" + str(meth[1].name))))
                self.nextProcessing(method, meth[1], path)
#Close::close()
#Start::start() -> startActivity()
#path = [main::oncreat, Strat:start, Start::startActivity, Deviceser]
        
        for meth in method.get_xref_to():
            tmp_path = path.copy()
            if meth[1].name in self.find_list:
                continue
            if str(method.name) == str(meth[1].name):
                self.logger.critical("Loop!")
                continue
            tmp_path.append(self.extract_class_name(str(meth[0].name) + "::" + str(meth[1].name)))
            #tmp_path = [main::oncreat, Strat:start]
            self.logger.critical("["+ str(depth) + "]" +" Current Pos:" + toString(tmp_path))
            self.searching(meth[1],tmp_path,depth+1)
            
    
    def nextProcessing(self, caller, method, path):
        methodname = str(method.name)
        if (methodname in ["startActivity", "startActivityForResult"]):
            self.logger.critical("\n----Activity Transition Occur!!----\n")
            nextclass = self.activityAnalysis(caller)
            if (nextclass == None):
                self.logger.critical("error occur At nextProcessing()")
            class_name = self.extract_class_name(str(nextclass)) + "::" + "onCreate"
            path.append(class_name)
            #self.activitychangelist.append(self.extract_class_name(str(caller.get_class_name())) + "::" + str(caller.name) + "->" + self.extract_class_name(str(method.get_class_name())) + "::" + str(method.name) + "->" + nextclass + "::onCreate")
            self.activitychangelist.append(path)
            self.traceChange(nextclass, path)
        elif (methodname in ["bindService"]):
            self.logger.critical("\n----Binding Occur!!----\n")
            nextclass = self.activityAnalysis(caller)
            if (nextclass == None):
                self.logger.critical("error occur At nextProcessing()")
            class_name = self.extract_class_name(str(nextclass)) + "::" + "onBind"
            path.append(class_name)
            #self.bindList.append(self.extract_class_name(str(caller.get_class_name())) + "::" + str(caller.name) + "->" + self.extract_class_name(str(method.get_class_name())) + "::" + str(method.name) + "->" + nextclass + "::onCreate")
            self.bindList.append(path)
            self.traceChange(nextclass, path)
        elif (methodname in ["startService", "stopService"]):
            self.logger.critical("\n----Binding Occur!!----\n")
            nextclass = self.activityAnalysis(caller)
            if (nextclass == None):
                self.logger.critical("error occur At nextProcessing()")
            class_name = self.extract_class_name(str(nextclass)) + "::" + "onCreate"
            path.append(class_name)
            class_name = self.extract_class_name(str(nextclass)) + "::" + "onStartCommand"
            path.append(class_name)
            #self.servicelist.append(self.extract_class_name(str(caller.get_class_name())) + "::" + str(caller.name) + "->" + self.extract_class_name(str(method.get_class_name())) + "::" + str(method.name) + "->" + nextclass + "::onCreate")
            self.servicelist.append(path)
            self.traceChange(nextclass, path)
#path = [main::oncreat, Strat:start, Start::startActivity, Deviceser::onCreate, ]
    def traceChange(self, startPoint, path):
        classlist = self.dx.find_classes("^"+FormatClassToJava(startPoint)+"$")
        for cls in classlist:
            #fmethod = dx.find_methods(cls.name,"^onCreate$")#oncreate만 생각하지 말자
            for me in cls.get_methods():
                tmp_act_path = path.copy()
                self.logger.critical("--------Root---------------")
                self.logger.critical(self.extract_class_name(str(cls.name))+"::"+str(me.name))
                #if(me.name == "onCreate"):
                tmp_act_path.append(self.extract_class_name(str(cls.name))+"::"+str(me.name))#mainactivi::oncreate
                self.searching(me,tmp_act_path,0)
                

    def extract_class_name(self, dir_class):
        tmp=dir_class.split('/')
        class_name = tmp.pop()
        class_name = class_name[:-1]
        return class_name

    def activityAnalysis(self, meth):
        
        if meth.is_external() or meth.is_android_api():
            return
        meth = meth.get_method()
        searchdata = meth.get_source()
        regex = re.compile('Intent\(.*?\,(.*[a-z])\)')

        test_str = searchdata

        match=regex.search(test_str)
        return FormatClassToJava(match.group(1).lstrip())

    def getChangeList(self):
        print(self.activitychangelist)
        print(self.servicelist)
        print(self.bindList)
    
    def get_json(self):
        output = {}
        output["activitychangelist"] = self.activitychangelist
        output["bindList"] = self.bindList
        output["servicelist"] = self.servicelist

        with open(self.apk_hash+'/trainstion.json', 'w') as f:
            json.dump(output,f, indent=4) 

            