package net.coding.wbcryptolib.sm2coop.algorithm.cipher;

import net.coding.wbcryptolib.rbg.MbedtlsCtrDRBG;
import net.coding.wbcryptolib.rbg.RBG;
import net.coding.wbcryptolib.sm2coop.TestSM2CoopKey;
import net.coding.wbcryptolib.sm2coop.algorithm.SM2CoopDecryptServer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Base64;

public class SM2CoopDecryptServerTest {

    @Test
    void initFreeWorks() {
        try (
                RBG rbg = MbedtlsCtrDRBG.withNullEntropy("ABCD".getBytes());
                SM2CoopDecryptServer server = new SM2CoopDecryptServer(TestSM2CoopKey.SERVER_PRIVATE_KEY, rbg);
        ) {} catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void respondWorks() {
        byte[] request = Base64.getDecoder().decode("MEQCIGnRmY5ySrpFgk4ahnpsLPwr00CM+lqSt7XNU8kufUllAiBnMdMA3WA+etAHw1JFEELWNXUWASKg3FrqjwjTW+cRIg==");
        String expected = "MEUCIF3gETaXAcKYG9NJvBRSFTQ5Vw14HX8B1GvUjlWkkTF+AiEA+vktt95WHsC5zfY4kppyKtMI2v6j/aKblvmO4wqOH78=";
        try (
                RBG rbg = MbedtlsCtrDRBG.withNullEntropy("ABCD".getBytes());
                SM2CoopDecryptServer server = new SM2CoopDecryptServer(TestSM2CoopKey.SERVER_PRIVATE_KEY, rbg);
        ) {
            byte[] response = server.respond(request);
            Assertions.assertEquals(expected, Base64.getEncoder().encodeToString(response));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
