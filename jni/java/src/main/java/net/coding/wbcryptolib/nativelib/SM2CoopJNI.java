package net.coding.wbcryptolib.nativelib;

import net.coding.wbcryptolib.rbg.RBG;
import net.coding.wbcryptolib.sm2coop.algorithm.SM2CoopDecryptClient;
import org.apache.commons.lang3.tuple.Pair;

public class SM2CoopJNI {

    public static class Context {

        static { DLLLoader.loadWBcryptoDLL(); }

        public static native long init();

        public static native void free(long handle);

        public static native void setPublicKey(long handle, byte[] pkX, byte[] pkY);

        public static native void setPrivateKey(long handle, byte[] hd);

        public static native void setW(long handle, byte[] WX, byte[] WY);

        public static native Pair<byte[], byte[]> getPublicKey(long handle);

        public static native byte[] getPrivateKey(long handle);

        public static native Pair<byte[], byte[]> getW(long handle);

    }


    //handle is a Context with PublicKey loaded
    public static native byte[] encrypt(long handle, byte[] plaintext, long rbgHandle);


    public static class DecryptSessionState {

        static { DLLLoader.loadWBcryptoDLL(); }

        public static native long init();

        public static native void free(long handle);

        //we need group info from the context handle to determine the size
        //just make sure the context has the same group, which is trivially true
        public static native long deserialize(long handle, byte[] data);

        public static native byte[] serialize(long handle, long sk_handle);

    }

    //handle is a Context with hd loaded
    //return Pair<request, handle of SessionState>
    public static native Pair<byte[], Long> decryptClientBegin(long handle, byte[] ciphertext);

    //handle is a Context with hd and W loaded
    public static native byte[] decryptServerRespond(long handle, byte[] request, long rbgHandle);

    //handle is a Context with hd loaded
    public static native byte[] decryptClientComplete(
            long handle,
            long sessionStateHandle,
            byte[] response,
            byte[] ciphertext
    );


    public static class SignSessionState {

        static { DLLLoader.loadWBcryptoDLL(); }

        public static native long init();

        public static native void free(long handle);

        public static native long deserialize(byte[] data);

        public static native byte[] serialize(long handle);

    }

    //handle is a Context with hd and P loaded
    //Pair<client ctx handle, Pair<dgst, request>>
    public static native Pair<Long, Pair<byte[], byte[]>> signClientBegin(long handle, byte[] msg, long rbgHandle);

    //handle is a Context with hd and P loaded
    //Pair<client ctx handle, Pair<dgst, request>>
    public static native Pair<Long, Pair<byte[], byte[]>> signClientBeginWithID(long handle, byte[] id, byte[] msg, long rbgHandle);

    //handle is a Context with W and hd loaded
    public static native byte[] signServerRespond(long handle, byte[] dgst, byte[] request, long rbgHandle);

    //handle is a Context with hd and P loaded
    public static native byte[] signClientComplete(long handle, long clientCtxHandle, byte[] response);

    //handle is a Context with hd loaded
    public static native boolean verify(long handle, byte[] msg, byte[] signature);

    //handle is a Context with hd loaded
    public static native boolean verifyWithID(long handle, byte[] id, byte[] msg, byte[] sig);

}
