package ayssl;

import com.sun.jna.*;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

import java.util.Arrays;
import java.util.List;

// WBCrypto里面包含：
// 1. 需要使用动态库的接口：例如，int wbcrypto_wbaes_gcm_setiv(WBCrypto.WBCRYPTO_gcm_context ctx, byte[] iv, int len)
// 2. 结构体的定义：例如，public static class WBCRYPTO_gcm_context extends Structure
// 3. 函数指针的定义：例如，public static interface Block extends Callback
public interface WBCrypto extends Library {
    // 创建实例，用来调用动态库中的函数
    WBCrypto INSTANCE = System.getProperty("os.name").toLowerCase().contains("linux")?
            (WBCrypto) Native.loadLibrary("wbcrypto", WBCrypto.class):
            System.getProperty("os.name").toLowerCase().contains("windows")?
                    (WBCrypto) Native.loadLibrary("libwbcrypto", WBCrypto.class):null ;
}
