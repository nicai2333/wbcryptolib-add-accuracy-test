package net.coding.wbcryptolib.sm2coop.algorithm;

import net.coding.wbcryptolib.nativelib.SM2CoopJNI;
import net.coding.wbcryptolib.sm2coop.key.SM2CoopPublicKey;
import net.coding.wbcryptolib.util.NativeOperationException;

public class SM2CoopVerifier implements AutoCloseable {

    private long handle;

    public SM2CoopVerifier(long handle){
        this.handle = handle;
    }

    /**
     * construct an instance
     * @param pk the public key to use
     */
    public SM2CoopVerifier(SM2CoopPublicKey pk) {
        handle = SM2CoopJNI.Context.init();
        SM2CoopJNI.Context.setPublicKey(
                handle,
                pk.getW().getAffineX().toByteArray(),
                pk.getW().getAffineY().toByteArray()
        );
    }

    /**
     * verify the sm2coop signature, with default user ID
     * @param message the message
     * @param signature the signature to verify
     * @return does the signature match the message?
     */
    public boolean verify(byte[] message, byte[] signature) {
        return SM2CoopJNI.verify(handle, message, signature);
    }

    /**
     * verify the sm2coop signature, with default user ID
     * @param id the user ID
     * @param message the message
     * @param signature the signature to verify
     * @return does the signature match the message?
     */
    public boolean verifyWithID(byte[] id, byte[] message, byte[] signature) {
        return SM2CoopJNI.verifyWithID(handle, id, message, signature);
    }

    @Override
    public void close() {
        SM2CoopJNI.Context.free(handle);
        handle = 0;
    }

}
