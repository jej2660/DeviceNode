from apkanalyzer import *
from traceflow import *




if __name__ == '__main__':    # 프로그램의 시작점일 때만 아래 코드 실행
    sess = misc.get_default_session()
    pingju=Apkanlyzer("./DeviceNode.apk")

    pingju.loadAPK(False)

    pingju.getMainActivity()

    pingju.getManifest()
    tf = TraceFlow()
    tf.getLogger()
    tf.traceMethod(pingju.dx,"L"+pingju.getMainActivity(),None) 