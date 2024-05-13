from os import spawnlpe
import time
from ctypes import *
import multiprocessing

wbcrypto = cdll.LoadLibrary("../build/libwbcrypto.so")

# sm4 bitslicing 256 ECB mode
# sm4_bs256_ecb(cipher,plain,key)
sm4_bs256_ecb = wbcrypto.sm4_bs256_ecb
sm4_bs256_ecb.argtypes = [POINTER(c_ubyte),POINTER(c_ubyte),c_int,POINTER(c_ubyte)]
sm4_bs256_ecb.restype = None

# sm4 bitslicing 256 CTR mode
# sm4_bs256_ctr(cipher,plain,key,iv)
sm4_bs256_ctr = wbcrypto.sm4_bs256_ctr
sm4_bs256_ctr.argtypes = [POINTER(c_ubyte),POINTER(c_ubyte),c_int,POINTER(c_ubyte),POINTER(c_ubyte)]
sm4_bs256_ctr.restype = None

# sm4 bitslicing 256 GCM mode
# sm4_bs256_gcm
# void sm4_bs256_gcm(uint8_t *output, uint8_t *input,int size, uint8_t *key_vector, uint8_t *iv,uint8_t *tag,uint8_t *Associated_Data);
# void sm4_bs256_gcm(uint8_t *output, uint8_t *input, int size, uint8_t *key_vector, int key_len, uint8_t *iv, int iv_len, uint8_t *tag, int tag_len, uint8_t *Associated_Data, int add_len)
sm4_bs256_gcm = wbcrypto.sm4_bs256_gcm
sm4_bs256_gcm.argtypes = [POINTER(c_ubyte),POINTER(c_ubyte),c_int,POINTER(c_ubyte),c_int,POINTER(c_ubyte),c_int,POINTER(c_ubyte),c_int,POINTER(c_ubyte),c_int]
sm4_bs256_gcm.restype = None

def run_sm4_bs256_ecb(start: int, end: int):
    key_vector = (c_ubyte*16)(
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    )
    len = 16*(1<<15)
    plainn = (c_ubyte*len)()
    c = (c_ubyte*len)()
    size = 16
    for i in range(start, end+1):
        sm4_bs256_ecb(c,plainn,size,key_vector)

def run_sm4_bs256_ctr(start: int, end: int):
    key_vector = (c_ubyte*16)(
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    )
    iv_vector = (c_ubyte*16)(
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    )
    len = 16*(1<<15)
    plainn = (c_ubyte*len)()
    c = (c_ubyte*len)()
    size = 16
    for i in range(start,end+1):
        sm4_bs256_ctr(c,plainn,size,key_vector,iv_vector)

def run_sm4_bs256_gcm(start: int, end: int):
    key_vector = (c_ubyte*16)(
        0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,
        0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08
    )
    iv_vector = (c_ubyte*16)(
        0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x00, 0x00, 0x00, 0x00
    )
    Associated_Data = (c_ubyte*23)(
        0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x03,0x7f,0xff,0xff,0xfe,0x89,0x2c,0x38,0x00,
        0x00,0x5c,0x36,0x5c,0x36,0x5c,0x36
    )
    tag = (c_ubyte*16)(
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    )
    len = 16*(1<<15)
    plainn = (c_ubyte*len)()
    c = (c_ubyte*len)()
    size = 16
    for i in range(start, end+1):
        sm4_bs256_gcm(c,plainn,size,key_vector,16,iv_vector,16,tag,16,Associated_Data,23)


def test_multiprocesses(run, process_num):
    # 加密的block个数，对应的区间为 [0, count-1]
    count = 1000000
    # 每个进程加密的block个数
    jobs_num = count//process_num + 1
    # 创建进程池
    pool = multiprocessing.Pool(processes=process_num)
    start_time = time.time()  # 记录开始时间
    for i in range(process_num):
        left = jobs_num*i
        right = left + jobs_num
        if right >= count:
            right = count-1  # 如果超出最大区间，则令最后一块的右区间为count-1
        arg = tuple([left, right])
        pool.apply_async(run, args=arg)
    pool.close()
    # 等待所有子进程执行结束
    pool.join()
    end_time = time.time()  # 记录结束时间
    total_time = (end_time-start_time)
    print(f"SM4_encrypt - {process_num} processes >>>, run {count} times, total time {total_time} s, per second run {count/(total_time)} times")

if __name__ == "__main__":
    print("ECB mode:")
    test_multiprocesses(run_sm4_bs256_ecb, 1)
    test_multiprocesses(run_sm4_bs256_ecb, 2)
    test_multiprocesses(run_sm4_bs256_ecb, 4)
    test_multiprocesses(run_sm4_bs256_ecb, 8)
    test_multiprocesses(run_sm4_bs256_ecb, 12)

    print("CTR mode:")
    test_multiprocesses(run_sm4_bs256_ctr, 1)
    test_multiprocesses(run_sm4_bs256_ctr, 2)
    test_multiprocesses(run_sm4_bs256_ctr, 4)
    test_multiprocesses(run_sm4_bs256_ctr, 8)
    test_multiprocesses(run_sm4_bs256_ctr, 12)

    print("GCM mode:")
    test_multiprocesses(run_sm4_bs256_gcm, 1)
    test_multiprocesses(run_sm4_bs256_gcm, 2)
    test_multiprocesses(run_sm4_bs256_gcm, 4)
    test_multiprocesses(run_sm4_bs256_gcm, 8)
    test_multiprocesses(run_sm4_bs256_gcm, 12)
