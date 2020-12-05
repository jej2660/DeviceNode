from androguard import misc
from androguard.core.bytecodes.apk import APK
import logging

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

    def loadAPK(self):                 #apk 파일 분석 초기화
        a, d, dx= misc.AnalyzeAPK(self.apk_path)
        self.a=a
        self.d=d
        self.dx=dx
        #self.logger = self.__get_logger()
        #self.logger.info("load apkfile")

    def getManifest(self):
        manifest={}
    
        self.permission = self.a.get_permissions()
        manifest["permission"]=self.permission  # permissions
        #self.logger.logging("get permissions")
        
        receive_mani=[]
        self.receiv_list = self.a.get_receivers()    
        for receiver in self.receiv_list:
            receiver_intent = self.a.get_intent_filters("receiver", receiver)
            receive_mani.append({receiver:receiver_intent})
        manifest["receiver"]=receive_mani
        #self.logger.logging("get receiver")
        
        service_mani=[]
        self.serv_list = self.a.get_services()
        for service in self.serv_list:      # service, intent-filter
            service_intent = self.a.get_intent_filters("service", service)
            service_mani.append({service:service_intent})
        manifest["service"]=service_mani
        #self.logger.logging("get service")
        
        active_mani=[]
        self.activ_list = self.a.get_activities()
        for activity in self.activ_list:          # activity, intent-filter
            activity_intent = self.a.get_intent_filters("activity", activity)
            active_mani.append({activity:activity_intent})
        manifest["activity"]=active_mani
        #self.logger.logging("get activity")
        
        self.asign = self.a.get_signatures()
        signatures = self.asign  # list of the data of the signature files(v1 Signature / JAR Signature)
        manifest["apk sign"]=[signature.decode('unicode_escape') for signature in signatures]
        #self.logger.logging("get apk sign")
        
        return manifest

    def getMainActivity(self, activ_list):
        for activity in activ_list:
            if(len(self.a.get_intent_filters("activity", activity)) > 0):
                intent_filter = self.a.get_intent_filters("activity", activity)
                if "android.intent.action.MAIN" in intent_filter["action"]:
                    mainActivity = activity
                    break
        return mainActivity

pingju=Apkanlyzer("./Downloads/DeviceNode.apk")    

pingju.loadAPK()
pingju.getMainActivity()
pingju.getManifest()


        #apk 파일 경로그런거
        #a d dx 분석파일 저장하는거 선언

    #위에 a d dx 를 초기화 해줌 ㅇㅇ
    #fi = a.get_android_manifest_axml().get_xml() 
    #manifest 파싱 --> 엑티비티나 서비스 그런거 가져와!!

"""

# find MainActivity
for activity in activity_list:
    if(len(a.get_intent_filters("activity", activity)) > 0):
        intent_filter = a.get_intent_filters("activity", activity)
        if "android.intent.action.MAIN" in intent_filter["action"]:
            mainActivity = activity
            break
"""