package ayssl;

import com.sun.jna.*;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

import java.util.Arrays;
import java.util.List;

// Crypto里面包含：
// 1. 需要使用动态库的接口：例如，int WBCRYPTO_gcm_setiv(Crypto.WBCRYPTO_gcm_context ctx, byte[] iv, int len)
// 2. 结构体的定义：例如，public static class WBCRYPTO_gcm_context extends Structure
// 3. 函数指针的定义：例如，public static interface Block extends Callback
public interface Crypto extends Library {
    // 创建实例，用来调用动态库中的函数
    Crypto INSTANCE = System.getProperty("os.name").toLowerCase().contains("linux")?
            (Crypto) Native.loadLibrary("wbcrypto", Crypto.class):
            System.getProperty("os.name").toLowerCase().contains("windows")?
                    (Crypto) Native.loadLibrary("libwbcrypto", Crypto.class):null ;
    
    // 使用java调用wbcrypto库的函数接口
    void dump_hex(byte []h, int len);
    void sm4_bsro256_ecb(byte []output, byte []input, int size, byte []key_vector);
    void sm4_bsro256_ctr(byte []output, byte []input, int size, byte []key_vector, byte []iv);
    void sm4_bsro256_gcm(byte []output, byte []input, int size, byte []key_vector, int key_len, byte []iv, int iv_len, byte []tag, int tag_len, byte []Associated_Data, int add_len);

    void performance_test_sm4_lut();
    void performance_test_sm4_bsro256();

}

