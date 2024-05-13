package net.coding.wbcryptolib.sm2coop;

import net.coding.wbcryptolib.sm2coop.key.SM2CoopClientPrivateKey;
import net.coding.wbcryptolib.sm2coop.key.SM2CoopPublicKey;
import net.coding.wbcryptolib.sm2coop.key.SM2CoopServerPrivateKey;
import net.coding.wbcryptolib.sm2coop.ecparam.SM2P256V1ECParams;

import java.math.BigInteger;
import java.security.spec.ECPoint;

public class TestSM2CoopKey {

    public static final SM2CoopPublicKey PUBLIC_KEY = new SM2CoopPublicKey(
            new ECPoint(
                    new BigInteger("28DE0B78FC5BD6ACDA482DE3230F76CBAED998AA734806F9BFC30A3E47E37417", 16),
                    new BigInteger("F564670DE6203275AA27B7B3D38361855056C6E338F313BCAFAEF4BEB0C122F3", 16)
            ),
            SM2P256V1ECParams.PARAMETER_SPEC
    );

    public static final SM2CoopClientPrivateKey CLIENT_PRIVATE_KEY = new SM2CoopClientPrivateKey(
            new BigInteger("5CE3CAF090A7FCC6F191DAB7C4589B2911F22DCC3378B54F6892040E259AE6F5", 16),
            SM2P256V1ECParams.PARAMETER_SPEC
    );

    public static final SM2CoopServerPrivateKey SERVER_PRIVATE_KEY = new SM2CoopServerPrivateKey(
            new BigInteger("8480A2D752F54C0DFD388D538C71B06F864FCF150F852967689C8DD4DCAF18FD", 16),
            new ECPoint(
                    new BigInteger("53D08B211376B4660A9D8F8AE3546E8E60D335790FB45AFDD73731C601E0694F", 16),
                    new BigInteger("D539885C616C0C87CC0931291D3C35AA1E51D527B398F544A0BC880D68EF7B21", 16)
            ),
            SM2P256V1ECParams.PARAMETER_SPEC
    );

}
