from os import spawnlpe
import time
from ctypes import *

wbcrypto = cdll.LoadLibrary("../build/out/libwbcrypto.so")

performance_test_sm4_lut = wbcrypto.performance_test_sm4_lut
performance_test_sm4_lut.argtypes = None
performance_test_sm4_lut.restype = None

if __name__ == "__main__":
    performance_test_sm4_lut()
