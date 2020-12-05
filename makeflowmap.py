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
        apkanalyzer=Apkanlyzer()
        self.a=apkanalyzer.a
        self.dx=apkanalyzer.dx
        self.dvm=DalvikVMFormat(self.a.get_dex())
        self.mainActivity=apkanalyzer.getMainActivity()
        self.flow_tbl={}
        self.get_mainactivity_method()

    # get_xref_to 한 결과를 '클래스네임::메소드네임' 형식으로 flow_tbl의 key와 value에 저장
    # <init>이 아니면 add_flow 
    def add_flow(self, key_class, key_method):
        key = key_class + "::" + key_method
        self.flow_tbl[key]=[]
        for meth in self.method_to_methodAnalysis(key_class, key_method).get_xref_to():
            value = meth[0].name + "::" + meth[1].name
            self.flow_tbl[key].append(value)
            if(meth[1].name != "<init>"):
                self.add_flow(meth[0].name, meth[1].name)
                
    # EncodedMethod를 MethodClassAnalysis로 attribute 변환
    def method_to_methodAnalysis(self, class_name, method_name):
        methods=[]
        for method in self.dx.find_methods(classname=class_name, methodname=method_name):
            methods.append(method)
        return methods[0]

    """
    메인 액티비티 클래스 이름 자바 형식으로 변환
    find classes로 메인 액티비티 str에서 ClassAnalysis 타입으로 변환 
    i.get_methods로 메인액티비티 내의 메소드 MethodClassAnalysis 타입으로 return
    i = ClassAnalysis
    j = MethodClassAnalysis
    """
    def get_mainactivity_method(self):
        self.main=FormatClassToJava(self.mainActivity)
        for i in self.dx.find_classes(self.main):
            for j in i.get_methods():
                self.add_flow(self.main, j.name)
