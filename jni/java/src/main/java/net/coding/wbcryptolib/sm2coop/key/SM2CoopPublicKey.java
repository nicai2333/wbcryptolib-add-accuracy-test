package net.coding.wbcryptolib.sm2coop.key;

import java.io.Serializable;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

/**
 * the public part of SM2Coop key, which is essentially a SM2 Public Key
 */
public final class SM2CoopPublicKey implements Serializable {

    private ECPoint w;

    private ECParameterSpec params;


    public SM2CoopPublicKey(ECPoint w, ECParameterSpec params) {
        this.w = w;
        this.params = params;
    }

    public String getAlgorithm() {
        return "SM2";
    }

    public ECPoint getW() {
        return w;
    }

    public ECParameterSpec getParams() {
        return params;
    }

}

