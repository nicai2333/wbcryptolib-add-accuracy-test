package net.coding.wbcryptolib.sm2coop.algorithm.cipher;

import net.coding.wbcryptolib.rbg.MbedtlsCtrDRBG;
import net.coding.wbcryptolib.rbg.RBG;
import net.coding.wbcryptolib.sm2coop.TestSM2CoopKey;
import net.coding.wbcryptolib.sm2coop.algorithm.SM2CoopDecryptClient;
import net.coding.wbcryptolib.sm2coop.algorithm.SM2CoopDecryptClient.DecryptSession;
import net.coding.wbcryptolib.sm2coop.algorithm.SM2CoopDecryptServer;
import net.coding.wbcryptolib.sm2coop.algorithm.SM2CoopEncrypter;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Base64;

public class SM2CoopEncryptDecryptIntegrationTest {

    @Test
    public void run() throws Exception {

        String plaintext = "encryption standard";

        RBG rbg = MbedtlsCtrDRBG.withNullEntropy("ABCD".getBytes());

        byte[] ciphertext;
        try(SM2CoopEncrypter encrypter = new SM2CoopEncrypter(TestSM2CoopKey.PUBLIC_KEY, rbg)){
            ciphertext = encrypter.encrypt(plaintext.getBytes());
        }

        try(
                SM2CoopDecryptClient client = new SM2CoopDecryptClient(TestSM2CoopKey.CLIENT_PRIVATE_KEY);
                SM2CoopDecryptServer server = new SM2CoopDecryptServer(TestSM2CoopKey.SERVER_PRIVATE_KEY, rbg);
        ) {
            Pair<byte[], DecryptSession> pair = client.begin(ciphertext);
            byte[] request = pair.getLeft();
            DecryptSession session = pair.getRight();

            byte[] response = server.respond(request);

            System.out.println(Base64.getEncoder().encodeToString(ciphertext));
            byte[] decrypted = client.complete(session, response, ciphertext);

            // remember this is AutoClosable!
            session.close();

            Assertions.assertEquals(plaintext, new String(decrypted));
        }

        rbg.close();
    }

}
