package net.coding.wbcryptolib.rbg;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MbedtlsCtrDRBGTest {

    @Test
    void withNullEntropyWorks() {
        //works with seed
        try(final MbedtlsCtrDRBG abcd = MbedtlsCtrDRBG.withNullEntropy("ABCD".getBytes())) {}
        //works without seed
        try(final MbedtlsCtrDRBG abcd = MbedtlsCtrDRBG.withNullEntropy(null)) {}
    }

    @Test
    void withPlatformDefaultEntropyWorks() {
        //works with seed
        try(final MbedtlsCtrDRBG abcd = MbedtlsCtrDRBG.withPlatformDefaultEntropy("ABCD".getBytes())) {}
        //works without seed
        try(final MbedtlsCtrDRBG abcd = MbedtlsCtrDRBG.withPlatformDefaultEntropy(null)) {}
    }

}
