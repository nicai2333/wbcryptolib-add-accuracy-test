package net.coding.wbcryptolib.sm2coop.algorithm.sign;

import net.coding.wbcryptolib.rbg.MbedtlsCtrDRBG;
import net.coding.wbcryptolib.rbg.RBG;
import net.coding.wbcryptolib.sm2coop.TestSM2CoopKey;
import net.coding.wbcryptolib.sm2coop.algorithm.*;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static net.coding.wbcryptolib.sm2coop.TestSM2CoopKey.*;

public class SM2CoopSignVerifyIntegrationTest {

    @Test
    public void run() throws Exception {

        String plaintext = "encryption standard";

        RBG rbg = MbedtlsCtrDRBG.withNullEntropy("ABCD".getBytes());

        byte[] signature;
        try(
                SM2CoopSignClient client = new SM2CoopSignClient(PUBLIC_KEY, CLIENT_PRIVATE_KEY, rbg);
                SM2CoopSignServer server = new SM2CoopSignServer(SERVER_PRIVATE_KEY, rbg);
        ){
            final Pair<SM2CoopSignClient.SignSession, Pair<byte[], byte[]>> pair = client.begin(plaintext.getBytes());
            final SM2CoopSignClient.SignSession session = pair.getLeft();
            final Pair<byte[], byte[]> reqPair = pair.getRight();
            System.out.println("dgst:"+Base64.getEncoder().encodeToString(reqPair.getLeft()));
            System.out.println("req:"+Base64.getEncoder().encodeToString(reqPair.getRight()));

            final byte[] respond = server.respond(reqPair.getLeft(), reqPair.getRight());

            signature = client.complete(session, respond);
            session.close();
        }

        try(SM2CoopVerifier verifier = new SM2CoopVerifier(PUBLIC_KEY)) {
            Assertions.assertTrue(verifier.verify(plaintext.getBytes(), signature));
        }

        rbg.close();

    }

}
