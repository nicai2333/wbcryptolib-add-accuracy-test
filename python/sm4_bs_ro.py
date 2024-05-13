from os import spawnlpe
import time
from ctypes import *

wbcrypto = cdll.LoadLibrary("../build/out/libwbcrypto.so")

# sm4 bitslicing 256 ECB mode
# sm4_bs256_ecb(cipher,plain,key)
sm4_bsro256_ecb = wbcrypto.sm4_bsro256_ecb
sm4_bsro256_ecb.argtypes = [POINTER(c_ubyte),POINTER(c_ubyte),c_int,POINTER(c_ubyte)]
sm4_bsro256_ecb.restype = None

# sm4 bitslicing 256 CTR mode
# sm4_bs256_ctr(cipher,plain,key,iv)
sm4_bsro256_ctr = wbcrypto.sm4_bsro256_ctr
sm4_bsro256_ctr.argtypes = [POINTER(c_ubyte),POINTER(c_ubyte),c_int,POINTER(c_ubyte),POINTER(c_ubyte)]
sm4_bsro256_ctr.restype = None

# sm4 bitslicing 256 GCM mode
# sm4_bs256_gcm 
# void sm4_bs256_gcm(uint8_t *output, uint8_t *input,int size, uint8_t *key_vector, uint8_t *iv,uint8_t *tag,uint8_t *Associated_Data);
# void sm4_bs256_gcm(uint8_t *output, uint8_t *input, int size, uint8_t *key_vector, int key_len, uint8_t *iv, int iv_len, uint8_t *tag, int tag_len, uint8_t *Associated_Data, int add_len)
sm4_bsro256_gcm = wbcrypto.sm4_bsro256_gcm
sm4_bsro256_gcm.argtypes = [POINTER(c_ubyte),POINTER(c_ubyte),c_int,POINTER(c_ubyte),c_int,POINTER(c_ubyte),c_int,POINTER(c_ubyte),c_int,POINTER(c_ubyte),c_int]
sm4_bsro256_gcm.restype = None

performance_test_sm4_bsro256 = wbcrypto.performance_test_sm4_bsro256
performance_test_sm4_bsro256.argtypes = None
performance_test_sm4_bsro256.restype = None

def sm4_bsro256_ecb_test():
    print("SM4_BSRO256 ECB 1 block:\n")
    key_vector = (c_ubyte*16)(
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    )
    pt_vector = (c_ubyte*32)(
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    )
    ct_vector = (c_ubyte*16)(
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
    )
    output = (c_ubyte*16)()
    sm4_bsro256_ecb(output,pt_vector,16,key_vector)
    wbcrypto.dump_hex(output,32)

    print("SM4-AVX2-bitslice RO ECB Speed Test.\n")
    len = 16*(1<<15)
    # print(len)
    plainn = (c_ubyte*len)()
    # print(plainn)
    c = (c_ubyte*len)()
    # wbcrypto.dump_hex(c,len)

    sizes =[16,64,256,1024,8192,16384]
    for size in sizes:
        t1 = time.perf_counter()
        for i in range(1,10001):
            sm4_bsro256_ecb(c,plainn,size,key_vector)
            # print(i)
        t2 = time.perf_counter()
        tt = (t2-t1)/10000
        speed = size / (16 * 10000 * tt)
        # wbcrypto.dump_hex(c,len)
        print("BSROSM4_encrypt>>> blocks:",size/16,", time:",tt,"s, speed:",speed," 万次/s")

    print("SM4-AVX2-bitslice ECB Speed Test end!\n\n")


def sm4_bsro256_ctr_test():
    print("SM4_BSRO256 CTR 4 block:\n")
    key_vector = (c_ubyte*16)(
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    )
    iv_vector = (c_ubyte*16)(
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    )
    pt_vector = (c_ubyte*64)(
        0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,
        0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,
        0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB
    )
    ct_vector = (c_ubyte*64)(
        0xAC, 0x32, 0x36, 0xCB, 0x97, 0x0C, 0xC2, 0x07, 0x91, 0x36, 0x4C, 0x39, 0x5A, 0x13, 0x42, 0xD1,
        0xA3, 0xCB, 0xC1, 0x87, 0x8C, 0x6F, 0x30, 0xCD, 0x07, 0x4C, 0xCE, 0x38, 0x5C, 0xDD, 0x70, 0xC7,
        0xF2, 0x34, 0xBC, 0x0E, 0x24, 0xC1, 0x19, 0x80, 0xFD, 0x12, 0x86, 0x31, 0x0C, 0xE3, 0x7B, 0x92,
        0x6E, 0x02, 0xFC, 0xD0, 0xFA, 0xA0, 0xBA, 0xF3, 0x8B, 0x29, 0x33, 0x85, 0x1D, 0x82, 0x45, 0x14
    )
    print("plaintext:")
    wbcrypto.dump_hex(pt_vector,64)
    
    output = (c_ubyte*64)()
    sm4_bsro256_ctr(output,pt_vector,64,key_vector,iv_vector)

    print("ciphertext:")
    wbcrypto.dump_hex(output,64)

    t = (c_ubyte*64)()
    sm4_bsro256_ctr(t,output,64,key_vector,iv_vector)

    print("plaintext:")
    wbcrypto.dump_hex(t,64)

    print("SM4-AVX2-bitslice CTR Speed Test.\n")
    len = 16*(1<<15)
    # print(len)
    plainn = (c_ubyte*len)()
    c = (c_ubyte*len)()

    sizes =[16,64,256,1024,8192,16384]
    for size in sizes:
        t1 = time.perf_counter()
        for i in range(1,10001):
            sm4_bsro256_ctr(c,plainn,size,key_vector,iv_vector)
        t2 = time.perf_counter()
        tt = (t2-t1)/10000
        speed = size / (16 * 10000 * tt)
        # wbcrypto.dump_hex(c,size)
        print("BSROSM4_encrypt>>> blocks:",size/16,", time:",tt,"s, speed:",speed," 万次/s")

    print("SM4-AVX2-bitslice CTR Speed Test end!\n\n")

def sm4_bsro256_gcm_test():
    print("SM4_BSRO256 GCM 4 block:\n")
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
    pt_vector = (c_ubyte*48)(
        0x08,0x06,0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01,0x00,0x03,0x7f,0xff,0xff,0xfe,
        0xc0,0xa8,0x14,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0xa8,0x14,0x0d,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    )
    ct_vector = (c_ubyte*48)(
        0x0a,0x59,0x91,0xa6,0x70,0xdc,0x0e,0xa2,0x6f,0x84,0xe4,0x55,0xa1,0xc0,0x61,0x47,
        0x8a,0xa0,0x9f,0x2f,0xbe,0x90,0x49,0x46,0x29,0xbc,0x58,0xe7,0x5b,0xe5,0xe9,0x1d,
        0xbc,0x6d,0x21,0x49,0xbc,0x1f,0xba,0xca,0xca,0xa9,0x72,0x2d,0x61,0x0f,0xde,0x1d
    )
    tag = (c_ubyte*16)(
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    )
    print("plaintext:")
    wbcrypto.dump_hex(pt_vector,48)

    print("tag:")
    wbcrypto.dump_hex(tag,16)
    
    output = (c_ubyte*48)()
    sm4_bsro256_gcm(output,pt_vector,48,key_vector,16,iv_vector,16,tag,16,Associated_Data,23)

    print("ciphertext:")
    wbcrypto.dump_hex(output,48)

    # t = (c_ubyte*48)()
    # sm4_bs256_gcm(t,output,48,key_vector,iv_vector,tag,Associated_Data)

    # print("plaintext:")
    # wbcrypto.dump_hex(t,48)

    print("SM4-AVX2-bitslice RO GCM Speed Test.\n")
    len = 16*(1<<15)
    # print(len)
    plainn = (c_ubyte*len)()
    c = (c_ubyte*len)()

    sizes =[16,64,256,1024,8192,16384]
    for size in sizes:
        t1 = time.perf_counter()
        for i in range(1,10001):
            sm4_bsro256_gcm(c,plainn,size,key_vector,16,iv_vector,16,tag,16,Associated_Data,23)
        t2 = time.perf_counter()
        tt = (t2-t1)/10000
        speed = size / (16 * 10000 * tt)
        print("BSROSM4_encrypt>>> blocks:",size/16,", time:",tt,"s, speed:",speed," 万次/s")

    print("SM4-AVX2-bitslice GCM Speed Test end!\n\n")


if __name__ == "__main__":
    # sm4_bsro256_ecb_test()
    # sm4_bsro256_ctr_test()
    # sm4_bsro256_gcm_test()
    performance_test_sm4_bsro256()
