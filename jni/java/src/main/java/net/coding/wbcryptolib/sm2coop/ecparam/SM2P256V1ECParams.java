package net.coding.wbcryptolib.sm2coop.ecparam;

import java.math.BigInteger;
import java.security.spec.*;

public class SM2P256V1ECParams {

    public static final ECField FIELD = new ECFieldFp(
            new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
    );

    public static final EllipticCurve CURVE = new EllipticCurve(
            FIELD,
            new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",16),
            new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",16)
    );

    public static final ECParameterSpec PARAMETER_SPEC = new ECParameterSpec(
            CURVE,
            new ECPoint(
                    new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",16),
                    new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",16)
            ),
            new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",16),
            1
    );

}
