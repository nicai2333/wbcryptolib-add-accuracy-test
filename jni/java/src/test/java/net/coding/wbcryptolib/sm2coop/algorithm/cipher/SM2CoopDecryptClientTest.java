package net.coding.wbcryptolib.sm2coop.algorithm.cipher;

import net.coding.wbcryptolib.sm2coop.TestSM2CoopKey;
import net.coding.wbcryptolib.sm2coop.algorithm.SM2CoopDecryptClient;
import org.junit.jupiter.api.Test;

class SM2CoopDecryptClientTest {

    @Test
    void initFreeWorks(){
        try (SM2CoopDecryptClient client = new SM2CoopDecryptClient(TestSM2CoopKey.CLIENT_PRIVATE_KEY))
        {} catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // functionality test deferred to integration

}
