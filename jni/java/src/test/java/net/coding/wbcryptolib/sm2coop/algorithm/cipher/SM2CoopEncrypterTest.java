package net.coding.wbcryptolib.sm2coop.algorithm.cipher;

import net.coding.wbcryptolib.rbg.MbedtlsCtrDRBG;
import net.coding.wbcryptolib.rbg.RBG;
import net.coding.wbcryptolib.sm2coop.TestSM2CoopKey;
import net.coding.wbcryptolib.sm2coop.algorithm.SM2CoopEncrypter;
import org.junit.jupiter.api.Test;

public class SM2CoopEncrypterTest {

    @Test
    void initFreeWorks() {
        try(
                final RBG rbg = MbedtlsCtrDRBG.withNullEntropy(null);
                final SM2CoopEncrypter encrypter = new SM2CoopEncrypter(TestSM2CoopKey.PUBLIC_KEY, rbg);
        ) {} catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // functionality test deferred to integration

}
