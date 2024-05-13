package net.coding.wbcryptolib.sm2coop.algorithm;

import net.coding.wbcryptolib.rbg.RBG;
import net.coding.wbcryptolib.sm2coop.key.SM2CoopClientPrivateKey;
import org.apache.commons.lang3.tuple.Pair;

import static net.coding.wbcryptolib.nativelib.SM2CoopJNI.*;

public class SM2CoopDecryptClient implements AutoCloseable {

    public static class DecryptSession implements AutoCloseable {

        public static DecryptSession deserialize(SM2CoopDecryptClient client, byte[] data) {
            return new DecryptSession(DecryptSessionState.deserialize(client.getNativeHandle(), data));
        }

        private long handle;

        public DecryptSession(long handle) {
            this.handle = handle;
        }

        public DecryptSession() {
            handle = DecryptSessionState.init();
        }

        public byte[] serialize(SM2CoopDecryptClient client) { return DecryptSessionState.serialize(handle, client.getNativeHandle()); }

        public long getNativeHandle() {
            return handle;
        }

        @Override
        public void close() {
            DecryptSessionState.free(handle);
            handle = 0;
        }

    }

    private long handle;

    public SM2CoopDecryptClient(long handle) { this.handle = handle; }

    /**
     * construct an instance
     * @param sk the private key to use
     */
    public SM2CoopDecryptClient(SM2CoopClientPrivateKey sk) {
        handle = Context.init();
        Context.setPrivateKey(handle, sk.getS().toByteArray());
    }

    public Pair<byte[], DecryptSession> begin(byte[] ciphertext) {
        final Pair<byte[], Long> pair = decryptClientBegin(handle, ciphertext);
        return Pair.of(
                pair.getLeft(),
                new DecryptSession(pair.getRight())
        );
    }

    public byte[] complete(DecryptSession session, byte[] response, byte[] ciphertext) {
        return decryptClientComplete(handle, session.getNativeHandle(), response, ciphertext);
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
