package net.coding.wbcryptolib.sm2coop.algorithm;

import net.coding.wbcryptolib.nativelib.SM2CoopJNI;
import net.coding.wbcryptolib.nativelib.SM2CoopJNI.Context;
import net.coding.wbcryptolib.rbg.RBG;
import net.coding.wbcryptolib.sm2coop.key.SM2CoopClientPrivateKey;
import net.coding.wbcryptolib.sm2coop.key.SM2CoopPublicKey;
import net.coding.wbcryptolib.sm2coop.key.SM2CoopServerPrivateKey;
import org.apache.commons.lang3.tuple.Pair;

import static net.coding.wbcryptolib.nativelib.SM2CoopJNI.*;

public class SM2CoopSignServer implements AutoCloseable {

    private RBG rbg;

    private long handle;

    public SM2CoopSignServer(long handle, RBG rbg) {
        this.handle = handle;
        this.rbg = rbg;
    }

    public SM2CoopSignServer(SM2CoopServerPrivateKey sk, RBG rbg) {
        this.rbg = rbg;
        handle = Context.init();
        Context.setPrivateKey(handle, sk.getS().toByteArray());
        Context.setW(handle, sk.getW().getAffineX().toByteArray(), sk.getW().getAffineY().toByteArray());
    }

    public byte[] respond(byte[] digest, byte[] request) {
       return signServerRespond(handle, digest, request, rbg.getNativeHandle());
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
