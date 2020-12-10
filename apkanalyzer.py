from androguard import misc
from androguard.core.bytecodes.apk import APK
from androguard import session
import logging
import json

class Apkanlyzer:
    def __init__(self, apk_path, apk_hashpath):
        self.apk_path = apk_path
        self.apk_hashpath = apk_hashpath
        self.manifest = {}

    def loadAPK(self, flag):
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

    def getManifest(self):
    
        self.permission = self.a.get_permissions()
        self.manifest["permission"]=self.permission  # permissions
        
        self.receiv_list = self.a.get_receivers()  
        self.manifest["receiver"]={}  
        for receiver in self.receiv_list:
            receiver_intent = self.a.get_intent_filters("receiver", receiver)
            self.manifest["receiver"][receiver]=receiver_intent
        
        self.serv_list = self.a.get_services()
        self.manifest["service"]={}
        for service in self.serv_list:      # service, intent-filter
            service_intent = self.a.get_intent_filters("service", service)
            self.manifest["service"][service]=service_intent
        
        self.activ_list = self.a.get_activities()
        self.manifest["activity"]={}
        for activity in self.activ_list:          # activity, intent-filter
            activity_intent = self.a.get_intent_filters("activity", activity)
            self.manifest["activity"][activity]=activity_intent
        
        self.asign = self.a.get_signatures()
        signatures = self.asign  # list of the data of the signature files(v1 Signature / JAR Signature)
        self.manifest["apk sign"]=[signature.decode('unicode_escape') for signature in signatures]
        return self.manifest

    def getMainActivity(self):
        self.main_activ = self.a.get_main_activity()
        return self.main_activ

    def get_json(self):
        with open(self.apk_hashpath+"/manifest.json", 'w') as f:
            json.dump(self.manifest,f, indent=4)
