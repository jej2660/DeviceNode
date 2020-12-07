import hashlib
import sys
from apkanalyzer import *
from traceflow import *
import utils



if __name__ == '__main__':    # 프로그램의 시작점일 때만 아래 코드 실행
    apk_file=sys.argv[1]
    a,_,__=AnalyzeAPK(apk_file)
    apk_hash = hashlib.sha256(a.get_raw())

    with open("hash.txt", "a+") as f:
        lines=f.readlines()
        for line in lines:
            if(line==apk_hash):
                print("already exist")
                sys.exit()
        f.write(apk_hash.hexdigest()+"\n") 

    
    sess = misc.get_default_session()
    pingju=Apkanlyzer("./DeviceNode.apk")

    pingju.loadAPK(False)

    pingju.getMainActivity()

    pingju.getManifest()
    tf = TraceFlow()
    tf.getLogger()
    tf.traceMethod(pingju.dx,"L"+pingju.getMainActivity(),None) 
    tf.logger.critical("Final:"+toString(tf.Log_list))