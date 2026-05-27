package crypto.ecc;

import java.security.*;
import java.security.spec.*;

/**
 * ECC key pair utilities using Java built-in SunEC provider (secp256r1 / NIST P-256).
 * No external dependencies required.
 */
public class ECCKeyPair {

    public static final String CURVE = "secp256r1";
    public static final int KEY_SIZE = 256;

    public final PrivateKey privateKey;
    public final PublicKey publicKey;

    public ECCKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec(CURVE), new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            privateKey = kp.getPrivate();
            publicKey = kp.getPublic();
        } catch (Exception e) {
            throw new RuntimeException("ECC key generation failed", e);
        }
    }

    private ECCKeyPair(PrivateKey pk, PublicKey pub) {
        this.privateKey = pk;
        this.publicKey = pub;
    }

    public byte[] getPublicKeyEncoded() {
        return publicKey.getEncoded();
    }

    public byte[] getPrivateKeyEncoded() {
        return privateKey.getEncoded();
    }

    public static PublicKey decodePublicKey(byte[] encoded) {
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new RuntimeException("ECC public key decode failed", e);
        }
    }

    public static PrivateKey decodePrivateKey(byte[] encoded) {
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (Exception e) {
            throw new RuntimeException("ECC private key decode failed", e);
        }
    }
}
