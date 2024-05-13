package net.coding.wbcryptolib.nativelib;

public class RBGJNI {

    public static class MbedtlsCtrDRBG {

        static { DLLLoader.loadWBcryptoDLL(); }

        public static native long withPlatformEntropy(byte[] seed);

        public static native long withNullEntropy(byte[] seed);

        public static native void free(long handle);

    }

}
