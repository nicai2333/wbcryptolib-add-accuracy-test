package net.coding.wbcryptolib.sm2coop.algorithm;

import net.coding.wbcryptolib.nativelib.SM2CoopJNI;
import net.coding.wbcryptolib.rbg.RBG;
import net.coding.wbcryptolib.sm2coop.key.SM2CoopServerPrivateKey;

import static net.coding.wbcryptolib.nativelib.SM2CoopJNI.*;

public class SM2CoopDecryptServer implements AutoCloseable {

    private long handle;

    private RBG rbg;

    public SM2CoopDecryptServer(long handle) { this.handle = handle; }

    /**
     * construct an instance
     * @param sk the private key to use
     */
    public SM2CoopDecryptServer(SM2CoopServerPrivateKey sk, RBG rbg) {
        handle = Context.init();
        Context.setPrivateKey(handle , sk.getS().toByteArray());
        Context.setW(handle, sk.getW().getAffineX().toByteArray(), sk.getW().getAffineY().toByteArray());
        this.rbg = rbg;
    }

    public byte[] respond(byte[] request) {
        return decryptServerRespond(handle, request, rbg.getNativeHandle());
    }

    public long getNativeHandle() {
        return handle;
    }

    @Override
    public void close() {
        Context.free(handle);
        handle = 0;
    }

}
