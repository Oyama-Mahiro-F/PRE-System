package crypto.pre;

import crypto.ecc.ECCKeyPair;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;

/**
 * ECC-based Proxy Re-Encryption.
 *
 * 采用 EC-ElGamal 风格的双向代理重加密方案：
 * - Alice 使用 AES-GCM 加密数据，AES 密钥通过 ECDH 与自己的公钥绑定
 * - 密文格式: (R, iv, encryptedData)，其中 R = k*G
 * - 解密需要计算 K = KDF(k * d_A * G)
 * - 重加密密钥 rk = d_B * d_A^{-1} mod n
 * - 代理计算新的会话密钥: K_B = rk * R（点乘），然后用 KDF(K_B) 替换原密钥
 *
 * 实际上，直接使用 ECDH 密钥协商更简洁：
 * - 重加密密钥是 Alice 为 Bob 计算的 wrapped key
 * - Alice 对同一份数据分别用自己和 Bob 的公钥加密 AES 密钥
 * - 代理存储两份 wrapped key，根据授权切换
 * - 代理在任何情况下都无法解密（不持有任何私钥）
 */
public class ECCPRE implements PREInterface {

    private static final int AES_KEY_SIZE = 128;
    private static final int GCM_IV_LEN = 12;
    private static final int GCM_TAG_LEN = 128;

    @Override
    public String getAlgorithmName() { return "ECC-PRE (ECDH-based Key Encapsulation)"; }

    /**
     * 生成重加密密钥（不适用于 ECC-PRE）。
     *
     * ECC-PRE 的重加密密钥生成需要原始密文上下文（提取临时公钥 R 和解封会话密钥），
     * 因此无法仅凭 (alicePrivateKey, bobPublicKey) 完成。
     * 请使用 {@link #precomputeReEncryptionKey(EncryptedMessage, byte[], byte[])}
     * 该方法需要 Alice 持有原始密文以完成解封→重新封装的两阶段操作。
     *
     * @throws UnsupportedOperationException 始终抛出，引导调用方使用正确方法
     */
    @Override
    public byte[] generateReEncryptionKey(byte[] alicePrivateKey, byte[] bobPublicKey) {
        throw new UnsupportedOperationException(
            "ECC-PRE 不支持无密文上下文的重加密密钥生成。"
                + "请使用 precomputeReEncryptionKey(ciphertext, alicePrivateKey, bobPublicKey)。"
                + "原因: ECC-PRE 方案需要从原始密文中提取临时公钥 R 并执行 ECDH 解封，"
                + "仅凭 (sk_A, pk_B) 无法完成此操作。");
    }

    @Override
    public EncryptedMessage encrypt(byte[] plaintext, byte[] alicePublicKeyEncoded) {
        try {
            PublicKey alicePub = ECCKeyPair.decodePublicKey(alicePublicKeyEncoded);

            // 生成随机 AES 密钥
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(AES_KEY_SIZE);
            SecretKey aesKey = kg.generateKey();

            // AES-GCM 加密数据
            byte[] iv = new byte[GCM_IV_LEN];
            new SecureRandom().nextBytes(iv);
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LEN, iv));
            byte[] encryptedData = aesCipher.doFinal(plaintext);

            // 使用 ECDH + Alice's pubKey 封装 AES 密钥
            // 生成临时密钥对 (k, R)
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"), new SecureRandom());
            KeyPair ephemeralKP = kpg.generateKeyPair();

            // ECDH: sharedSecret = k * Q_A
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(ephemeralKP.getPrivate());
            ka.doPhase(alicePub, true);
            byte[] sharedSecret = ka.generateSecret();

            // KDF: 使用 SHA-256 派生 wrapping key
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] wrappingKey = md.digest(sharedSecret);

            // AESWrap the session key (RFC 3394, first 16 bytes of KDF output as KEK)
            byte[] wrapKey128 = java.util.Arrays.copyOf(wrappingKey, 16);
            Cipher wrapCipher = Cipher.getInstance("AESWrap");
            wrapCipher.init(Cipher.WRAP_MODE, new SecretKeySpec(wrapKey128, "AES"));
            byte[] wrappedKey = wrapCipher.wrap(aesKey);

            // 密文格式:
            // primary = R_len(4) || R_encoded || iv || encryptedData
            // auxiliary = wrappedKey (Alice用自己的公钥封装的)
            byte[] rEncoded = ephemeralKP.getPublic().getEncoded();
            byte[] primary = new byte[4 + rEncoded.length + GCM_IV_LEN + encryptedData.length];
            System.arraycopy(intToBytes(rEncoded.length), 0, primary, 0, 4);
            System.arraycopy(rEncoded, 0, primary, 4, rEncoded.length);
            int offset = 4 + rEncoded.length;
            System.arraycopy(iv, 0, primary, offset, GCM_IV_LEN);
            offset += GCM_IV_LEN;
            System.arraycopy(encryptedData, 0, primary, offset, encryptedData.length);

            return new EncryptedMessage(primary, wrappedKey);
        } catch (Exception e) {
            throw new RuntimeException("ECC-PRE encryption failed", e);
        }
    }

    /**
     * 代理执行重加密。
     * 使用重加密密钥（Alice 提供的 Bob-wrapped key）替换 auxiliaryData。
     *
     * 密文结构保持不变 (R, iv, encryptedData)，仅替换 wrappedKey。
     * - auxiliaryData 从 Alice-wrapped key 替换为 Bob-wrapped key
     */
    @Override
    public EncryptedMessage reEncrypt(EncryptedMessage ciphertext, byte[] reEncryptionKey) {
        // reEncryptionKey = R2_len(4) || R2_encoded || bobWrappedKey
        int r2Len = bytesToInt(reEncryptionKey, 0);
        byte[] r2Encoded = java.util.Arrays.copyOfRange(reEncryptionKey, 4, 4 + r2Len);
        byte[] bobWrappedKey = java.util.Arrays.copyOfRange(reEncryptionKey, 4 + r2Len, reEncryptionKey.length);

        // Update primary data: replace R1 with R2
        byte[] oldPrimary = ciphertext.primaryData();
        int oldRLen = bytesToInt(oldPrimary, 0);
        int restLen = oldPrimary.length - 4 - oldRLen; // iv + encryptedData
        byte[] rest = java.util.Arrays.copyOfRange(oldPrimary, 4 + oldRLen, oldPrimary.length);

        byte[] newPrimary = new byte[4 + r2Encoded.length + restLen];
        System.arraycopy(intToBytes(r2Encoded.length), 0, newPrimary, 0, 4);
        System.arraycopy(r2Encoded, 0, newPrimary, 4, r2Encoded.length);
        System.arraycopy(rest, 0, newPrimary, 4 + r2Encoded.length, restLen);

        return new EncryptedMessage(newPrimary, bobWrappedKey);
    }

    @Override
    public byte[] decrypt(EncryptedMessage ciphertext, byte[] bobPrivateKeyEncoded) {
        try {
            PrivateKey bobPriv = ECCKeyPair.decodePrivateKey(bobPrivateKeyEncoded);

            byte[] primary = ciphertext.primaryData();
            byte[] wrappedKey = ciphertext.auxiliaryData();

            // 解析 primary
            int rLen = bytesToInt(primary, 0);
            byte[] rEncoded = Arrays.copyOfRange(primary, 4, 4 + rLen);
            int offset = 4 + rLen;
            byte[] iv = Arrays.copyOfRange(primary, offset, offset + GCM_IV_LEN);
            offset += GCM_IV_LEN;
            byte[] encryptedData = Arrays.copyOfRange(primary, offset, primary.length);

            // 解析临时公钥 R
            PublicKey rPub = ECCKeyPair.decodePublicKey(rEncoded);

            // ECDH: sharedSecret = d_B * R
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(bobPriv);
            ka.doPhase(rPub, true);
            byte[] sharedSecret = ka.generateSecret();

            // KDF
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] unwrappingKey = md.digest(sharedSecret);

            // AES-unwrap (RFC 3394)
            byte[] unwrapKey128 = java.util.Arrays.copyOf(unwrappingKey, 16);
            Cipher unwrapCipher = Cipher.getInstance("AESWrap");
            unwrapCipher.init(Cipher.UNWRAP_MODE, new SecretKeySpec(unwrapKey128, "AES"));
            SecretKey aesKey = (SecretKey) unwrapCipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

            // AES-GCM 解密数据
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LEN, iv));
            return aesCipher.doFinal(encryptedData);
        } catch (Exception e) {
            throw new RuntimeException("ECC-PRE decryption failed", e);
        }
    }

    /**
     * Alice 为 Bob 预计算重加密密钥。
     * Alice 使用自己的私钥解封 AES key，然后用 Bob 的公钥重新封装。
     */
    public byte[] precomputeReEncryptionKey(EncryptedMessage ciphertext,
                                             byte[] alicePrivateKeyEncoded,
                                             byte[] bobPublicKeyEncoded) {
        try {
            PrivateKey alicePriv = ECCKeyPair.decodePrivateKey(alicePrivateKeyEncoded);
            PublicKey bobPub = ECCKeyPair.decodePublicKey(bobPublicKeyEncoded);

            byte[] primary = ciphertext.primaryData();
            byte[] aliceWrappedKey = ciphertext.auxiliaryData();

            // 解析 R
            int rLen = bytesToInt(primary, 0);
            byte[] rEncoded = Arrays.copyOfRange(primary, 4, 4 + rLen);
            PublicKey rPub = ECCKeyPair.decodePublicKey(rEncoded);

            // ECDH with Alice: sharedSecret = d_A * R
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(alicePriv);
            ka.doPhase(rPub, true);
            byte[] sharedSecret = ka.generateSecret();

            // KDF → unwrapping key
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] unwrappingKey = md.digest(sharedSecret);

            // 解封 AES key (RFC 3394 AESWrap)
            byte[] unwrapKey128 = java.util.Arrays.copyOf(unwrappingKey, 16);
            Cipher unwrapCipher = Cipher.getInstance("AESWrap");
            unwrapCipher.init(Cipher.UNWRAP_MODE, new SecretKeySpec(unwrapKey128, "AES"));
            SecretKey aesKey = (SecretKey) unwrapCipher.unwrap(aliceWrappedKey, "AES", Cipher.SECRET_KEY);

            // --- 用 Bob 的公钥重新封装 ---
            KeyPairGenerator kpg2 = KeyPairGenerator.getInstance("EC");
            kpg2.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"), new SecureRandom());
            KeyPair ephemeralKP2 = kpg2.generateKeyPair();

            KeyAgreement ka2 = KeyAgreement.getInstance("ECDH");
            ka2.init(ephemeralKP2.getPrivate());
            ka2.doPhase(bobPub, true);
            byte[] sharedSecret2 = ka2.generateSecret();

            byte[] wrappingKey2 = md.digest(sharedSecret2);

            byte[] wrapKey2_128 = java.util.Arrays.copyOf(wrappingKey2, 16);
            Cipher wrapCipher2 = Cipher.getInstance("AESWrap");
            wrapCipher2.init(Cipher.WRAP_MODE, new SecretKeySpec(wrapKey2_128, "AES"));
            byte[] bobWrappedKey = wrapCipher2.wrap(aesKey);

            // 返回: R2_len(4) || R2_encoded || bobWrappedKey
            byte[] r2Encoded = ephemeralKP2.getPublic().getEncoded();
            byte[] result = new byte[4 + r2Encoded.length + bobWrappedKey.length];
            System.arraycopy(intToBytes(r2Encoded.length), 0, result, 0, 4);
            System.arraycopy(r2Encoded, 0, result, 4, r2Encoded.length);
            System.arraycopy(bobWrappedKey, 0, result, 4 + r2Encoded.length, bobWrappedKey.length);

            return result;
        } catch (Exception e) {
            throw new RuntimeException("Re-encryption key pre-computation failed", e);
        }
    }

    private static byte[] intToBytes(int v) {
        return new byte[]{(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v};
    }

    private static int bytesToInt(byte[] b, int off) {
        return ((b[off] & 0xFF) << 24) | ((b[off+1] & 0xFF) << 16)
             | ((b[off+2] & 0xFF) << 8)  | (b[off+3] & 0xFF);
    }
}
