package net.coding.wbcryptolib.sm2coop.algorithm;

import net.coding.wbcryptolib.nativelib.SM2CoopJNI;
import net.coding.wbcryptolib.nativelib.SM2CoopJNI.Context;
import net.coding.wbcryptolib.nativelib.SM2CoopJNI.SignSessionState;
import net.coding.wbcryptolib.rbg.RBG;
import net.coding.wbcryptolib.sm2coop.key.SM2CoopClientPrivateKey;
import net.coding.wbcryptolib.sm2coop.key.SM2CoopPublicKey;
import org.apache.commons.lang3.tuple.Pair;

import static net.coding.wbcryptolib.nativelib.SM2CoopJNI.*;

public class SM2CoopSignClient implements AutoCloseable {

    public static class SignSession implements AutoCloseable {

        public static SignSession deserialize(byte[] data) {
            return new SignSession(SignSessionState.deserialize(data));
        }

        private long handle;

        public SignSession(long handle) {
            this.handle = handle;
        }

        public SignSession() {
            handle = SignSessionState.init();
        }

        public byte[] serialize() { return SignSessionState.serialize(handle); }

        public long getNativeHandle() {
            return handle;
        }

        @Override
        public void close() {
            SignSessionState.free(handle);
            handle = 0;
        }

    }

    private RBG rbg;

    private long handle;

    public SM2CoopSignClient(long handle, RBG rbg) {
        this.handle = handle;
        this.rbg = rbg;
    }

    /**
     * construct an instance
     * @param sk the private key to use
     */
    public SM2CoopSignClient(SM2CoopPublicKey pk, SM2CoopClientPrivateKey sk, RBG rbg) {
        handle = Context.init();
        this.rbg = rbg;
        Context.setPublicKey(handle, pk.getW().getAffineX().toByteArray(), pk.getW().getAffineY().toByteArray());
        Context.setPrivateKey(handle, sk.getS().toByteArray());
    }

    //returns Pair<SignSession, Pair<dgst, request>>, send both to server
    public Pair<SignSession, Pair<byte[], byte[]>> begin(byte[] message) {
        final Pair<Long, Pair<byte[], byte[]>> pair = signClientBegin(handle, message, rbg.getNativeHandle());
        return Pair.of(
                new SignSession(pair.getLeft()),
                pair.getRight()
        );
    }

    public byte[] complete(SignSession session, byte[] response) {
        return signClientComplete(handle, session.getNativeHandle(), response);
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
