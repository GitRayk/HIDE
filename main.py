import os
import fcntl
import ctypes

# 确定与内核交互命令的 C 语言格式
class SET_AID_MES(ctypes.Structure):
    _fields_ = [("sn", ctypes.c_uint),
                ("aid", ctypes.c_char * 8)]
    
class SET_KEY_MES(ctypes.Structure):
    _fields_ = [("sn", ctypes.c_uint),
                ("mac", ctypes.c_char * 6),
                ("aes_key", ctypes.c_char * 16),
                ("ip6", ctypes.c_char * 16),
                ("aid", ctypes.c_char * 8)]
    
class IOCTL_CMD(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint),
                ("buff", ctypes.c_void_p)]

# 获取 DID(AID) 的方法放在此处
def getAID() -> bytes:
    pass

if __name__ == "__main__":
    f = os.open("/dev/labelCmd", os.O_WRONLY)
    cmd = IOCTL_CMD()
    aid_mes = SET_AID_MES()

    # 获取 AID 和 sn 然后构造消息体
    aid_mes.sn = 1
    aid_mes.aid = getAID()

    cmd.type = 2
    cmd.buff = ctypes.addressof(aid_mes)

    # 将其与 sn 一起发送给内核，其中 ioctl 的第二参数可以为任意值，在内核中不使用
    fcntl.ioctl(f, 1, cmd)
    os.close(f)