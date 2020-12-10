import hashlib
import sys
from apkanalyzer import *
from traceflow import *
from makeflowmap import *
import utils



if __name__ == '__debug__':    # 프로그램의 시작점일 때만 아래 코드 실행
    apk_file=sys.argv[1]
    a,_,__=AnalyzeAPK(apk_file)
    apk_hash = hashlib.sha256(a.get_raw())

    with open("hash.txt", "a+") as f:
        f.seek(0)
        lines=f.readlines()
        if(apk_hash.hexdigest()+"\n" in lines):
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


if __name__ == '__main__':
    apk_name = sys.argv[1]
    apk_hashpath = sys.argv[2]
    apk = Apkanlyzer(apk_name, apk_hashpath)
    apk.loadAPK(False)
    apk.getManifest()
    apk.get_json()

    flow=TableMaker(apk_hashpath)
    flow.class_methods_tbl(apk.dx)
    flow.method_xref(apk.dx) 

    main = apk.getMainActivity()
    tf = TraceFlow(apk.dx, apk_hashpath)
    tf.traceChange(main, [])
    tf.getChangeList()

