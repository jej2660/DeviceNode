from androguard import misc
from androguard.core.bytecodes.apk import APK
from androguard import session
import logging
import json

class Apkanlyzer:
    '''def __get_logger(self):
        __logger = logging.getLogger("Apkanlyzer")
        # 로그 포멧 정의
        formatter = logging.Formatter('%(message)s')
        #formatter = logging.Formatter(
         #   'BATCH##AWSBATCH##%(levelname)s##%(asctime)s##%(message)s >> @@file::%(filename)s@@line::%(lineno)s')
        #스트림 핸들러 정의
        stream_handler = logging.StreamHandler()
        # 각 핸들러에 포멧 지정
        stream_handler.setFormatter(formatter)
        # 로거 인스턴스에 핸들러 삽입
        __logger.addHandler(stream_handler)
        # 로그 레벨 정의
        __logger.setLevel(logging.DEBUG)
        return __logger
     '''
    def __init__(self, apk_path):                #경로 초기화
        self.apk_path = apk_path
        self.manifest = {}

    def loadAPK(self, flag):                 #apk 파일 분석 초기화
        sess = misc.get_default_session()
        if flag == True:
            sess = session.Load("androguard_session.ag")
            a, d, dx= misc.AnalyzeAPK(self.apk_path, session=sess)
            self.a=a
            self.d=d
            self.dx=dx
            return
        a, d, dx= misc.AnalyzeAPK(self.apk_path, session=sess)
        self.a=a
        self.d=d
        self.dx=dx
        #self.logger = self.__get_logger()
        #self.logger.info("load apkfile")

    def getManifest(self):
    
        self.permission = self.a.get_permissions()
        self.manifest["permission"]=self.permission  # permissions
        #self.logger.logging("get permissions")
        
        self.receiv_list = self.a.get_receivers()  
        self.manifest["receiver"]={}  
        for receiver in self.receiv_list:
            receiver_intent = self.a.get_intent_filters("receiver", receiver)
            self.manifest["receiver"][receiver]=receiver_intent
        #self.logger.logging("get receiver")
        
        self.serv_list = self.a.get_services()
        self.manifest["service"]={}
        for service in self.serv_list:      # service, intent-filter
            service_intent = self.a.get_intent_filters("service", service)
            self.manifest["service"][service]=service_intent
        #self.logger.logging("get service")
        
        self.activ_list = self.a.get_activities()
        manifest["activity"]={}
        for activity in self.activ_list:          # activity, intent-filter
            activity_intent = self.a.get_intent_filters("activity", activity)
            self.manifest["activity"][activity]=activity_intent
        #self.logger.logging("get activity")
        
        self.asign = self.a.get_signatures()
        signatures = self.asign  # list of the data of the signature files(v1 Signature / JAR Signature)
        self.manifest["apk sign"]=[signature.decode('unicode_escape') for signature in signatures]
        #self.logger.logging("get apk sign")
        return self.manifest

    def getMainActivity(self):
        self.main_activ = self.a.get_main_activity()
        return self.main_activ

    def get_json(self):
        with open('manifest.json', 'w') as f:
            json.dump(self.manifest,f)