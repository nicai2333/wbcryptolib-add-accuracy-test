package net.coding.wbcryptolib.sm2coop.key;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.spec.ECParameterSpec;

/**
 * the client private part of the key
 */
public final class SM2CoopClientPrivateKey implements Serializable {

    private BigInteger s;

    private ECParameterSpec params;


    public SM2CoopClientPrivateKey(BigInteger s, ECParameterSpec params) {
        this.s = s;
        this.params = params;
    }

    public String getAlgorithm() {
        return "SM2Coop";
    }

    public BigInteger getS() {
        return s;
    }

    public ECParameterSpec getParams() {
        return params;
    }

}
