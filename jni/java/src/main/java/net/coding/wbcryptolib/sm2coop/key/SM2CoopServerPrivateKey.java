package net.coding.wbcryptolib.sm2coop.key;

import javax.sql.rowset.serial.SerialArray;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

/**
 * the client private part of the key
 */
public final class SM2CoopServerPrivateKey implements Serializable {

    private BigInteger s;

    private ECPoint w;

    private ECParameterSpec params;


    public SM2CoopServerPrivateKey(BigInteger s, ECPoint w, ECParameterSpec params) {
        this.s = s;
        this.w = w;
        this.params = params;
    }

    public String getAlgorithm() {
        return "SM2Coop";
    }

    public BigInteger getS() {
        return s;
    }

    public ECPoint getW() { return w; }

    public ECParameterSpec getParams() {
        return params;
    }

}
