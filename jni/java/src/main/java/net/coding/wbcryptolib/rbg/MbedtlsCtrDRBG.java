package net.coding.wbcryptolib.rbg;


import net.coding.wbcryptolib.nativelib.DLLLoader;
import net.coding.wbcryptolib.nativelib.RBGJNI;

/**
 * a implementation of DRBG using mbedtls's ctr_drbg with platform entropy source
 *     please implement your own if you want to change the native config
 */
public class MbedtlsCtrDRBG implements RBG {

    private long handle;

    public static MbedtlsCtrDRBG withNullEntropy(byte[] seed) {
        return new MbedtlsCtrDRBG(RBGJNI.MbedtlsCtrDRBG.withNullEntropy(seed));
    }

    public static MbedtlsCtrDRBG withPlatformDefaultEntropy(byte[] seed) {
        return new MbedtlsCtrDRBG(RBGJNI.MbedtlsCtrDRBG.withPlatformEntropy(seed));
    }

    public MbedtlsCtrDRBG(long handle) { this.handle = handle; }

    @Override
    public long getNativeHandle() {
        return handle;
    }

    @Override
    public void close() {
        RBGJNI.MbedtlsCtrDRBG.free(handle);
        handle = 0;
    }

}
