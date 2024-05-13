package net.coding.wbcryptolib.sm2coop.algorithm;

import net.coding.wbcryptolib.nativelib.SM2CoopJNI;
import net.coding.wbcryptolib.rbg.RBG;
import net.coding.wbcryptolib.sm2coop.key.SM2CoopPublicKey;
import net.coding.wbcryptolib.util.NativeOperationException;

import static net.coding.wbcryptolib.nativelib.SM2CoopJNI.Context;

public class SM2CoopEncrypter implements AutoCloseable {

    private long handle;

    private RBG rbg;

    public SM2CoopEncrypter(long handle){
        this.handle = handle;
    }

    /**
     * construct an instance
     * @param pk the public key to use
     * @param rbg the RBG to use, MUST LIVE LONGER AFTER THIS OBJECT!
     */
    public SM2CoopEncrypter(SM2CoopPublicKey pk, RBG rbg) {
        handle = Context.init();
        Context.setPublicKey(
                handle,
                pk.getW().getAffineX().toByteArray(),
                pk.getW().getAffineY().toByteArray()
        );
        this.rbg = rbg;
    }

    /**
     * run the encrypt algorithm
     * @param plaintext the plaintext to encrypt
     * @throws NativeOperationException on failure
     * @return the ciphertext
     */
    public byte[] encrypt(byte[] plaintext) {
        return SM2CoopJNI.encrypt(handle, plaintext, rbg.getNativeHandle());
    }

    @Override
    public void close() {
        Context.free(handle);
        handle = 0;
    }

}
