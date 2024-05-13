package net.coding.wbcryptolib.sm2coop.algorithm.cipher;

import net.coding.wbcryptolib.rbg.MbedtlsCtrDRBG;
import net.coding.wbcryptolib.rbg.RBG;
import net.coding.wbcryptolib.sm2coop.TestSM2CoopKey;
import net.coding.wbcryptolib.sm2coop.algorithm.SM2CoopDecryptClient;
import net.coding.wbcryptolib.sm2coop.algorithm.SM2CoopDecryptClient.DecryptSession;
import net.coding.wbcryptolib.sm2coop.algorithm.SM2CoopDecryptServer;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Base64;

public class SM2CoopClientDecryptSessionTest {

    @Test
    void initFreeWorks() {
        try(DecryptSession session = new DecryptSession()) {
            //testing init & free only
        }
    }

    @Test
    void serializationInSameDcryptClientWorks() {
        byte[] plaintext = "encryption standard".getBytes();
        byte[] ciphertext = Base64.getDecoder().decode("MHwCICkVD4AlmM6EDoQV+lTV4Ilwa4f8K4aeNzcg7l1s6JJwAiEAr8MRcX1ayYhRH5te9rEMIWlaYXa9sQV6IxUgz0asVkAEIMKIDrpC11A8SwVuS5Qv4QMvq1ZPz1nHTWXuK6H0heNIBBOdBbI1LgPg9tMxgeF7w82UJigN");

        try (
                RBG rbg = MbedtlsCtrDRBG.withNullEntropy("ABCD".getBytes());
                SM2CoopDecryptClient client = new SM2CoopDecryptClient(TestSM2CoopKey.CLIENT_PRIVATE_KEY);
                SM2CoopDecryptServer server = new SM2CoopDecryptServer(TestSM2CoopKey.SERVER_PRIVATE_KEY, rbg);
        ) {
            Pair<byte[], DecryptSession> pair = client.begin(ciphertext);
            byte[] request = pair.getLeft();

            byte[] serialized = pair.getRight().serialize(client);
            DecryptSession session = DecryptSession.deserialize(client, serialized);

            byte[] response = server.respond(request);

            byte[] decrypted = client.complete(session, response, ciphertext);

            // remember this is AutoClosable!
            session.close();

            Assertions.assertArrayEquals(plaintext, decrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void serializationInDifferentDcryptClientWorks() {
        byte[] plaintext = "encryption standard".getBytes();
        byte[] ciphertext = Base64.getDecoder().decode("MHwCICkVD4AlmM6EDoQV+lTV4Ilwa4f8K4aeNzcg7l1s6JJwAiEAr8MRcX1ayYhRH5te9rEMIWlaYXa9sQV6IxUgz0asVkAEIMKIDrpC11A8SwVuS5Qv4QMvq1ZPz1nHTWXuK6H0heNIBBOdBbI1LgPg9tMxgeF7w82UJigN");

        byte[] request;
        byte[] serialized;
        try (SM2CoopDecryptClient client = new SM2CoopDecryptClient(TestSM2CoopKey.CLIENT_PRIVATE_KEY)) {
            Pair<byte[], DecryptSession> pair = client.begin(ciphertext);
            request = pair.getLeft();
            serialized = pair.getRight().serialize(client);
        }

        byte[] response;
        try (
                RBG rbg = MbedtlsCtrDRBG.withNullEntropy("ABCD".getBytes());
                SM2CoopDecryptServer server = new SM2CoopDecryptServer(TestSM2CoopKey.SERVER_PRIVATE_KEY, rbg);
        ) {
            response = server.respond(request);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        byte[] decrypted;
        try (SM2CoopDecryptClient client = new SM2CoopDecryptClient(TestSM2CoopKey.CLIENT_PRIVATE_KEY)) {
            DecryptSession recovered = DecryptSession.deserialize(client, serialized);
            decrypted = client.complete(recovered, response, ciphertext);
        }

        Assertions.assertArrayEquals(plaintext, decrypted);
    }

}
