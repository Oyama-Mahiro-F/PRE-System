package crypto.pre;

import crypto.rsa.RSAKeyPair;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * RSA-based Proxy Re-Encryption (BBS98 shared-modulus style).
 *
 * 共享模数方案: Alice 和 Bob 使用相同的模数 N=pq，各自持有不同的 (e,d) 密钥对。
 * 加密: c_A = m^e_A mod N
 * 重加密密钥: rk = e_B * d_A mod φ(N)
 * 重加密: c_B = c_A^rk mod N = m^e_B mod N
 * 解密: m = c_B^d_B mod N
 *
 * 由于 RSA 不能直接加密任意长度的消息，采用混合加密：
 * - AES-GCM 加密数据
 * - RSA 加密 AES 密钥
 * - 重加密仅对 RSA 加密的密钥部分进行变换
 *
 * ⚠ 安全注意 — 共享模数的固有风险:
 * 由于 Alice 持有 φ(N)，且 Bob 的公钥指数 e_B 是公开的，Alice 可以计算
 * d_B = e_B^{-1} mod φ(N)，从而获得 Bob 的完整私钥。反之亦然。
 * 因此，本方案在实际部署中需满足以下前提之一：
 * (1) 由可信密钥管理中心 (KMC) 统一生成并分发所有密钥对，用户不接触 φ(N)
 * (2) 用户间存在充分的互信关系
 * 对于互不信任的多方场景，应优先选择 ECC-PRE 方案（密钥完全独立）。
 */
public class RSAPRE implements PREInterface {

    private static final int AES_KEY_SIZE = 128;
    private static final int GCM_IV_LEN = 12;
    private static final int GCM_TAG_LEN = 128;

    @Override
    public String getAlgorithmName() { return "RSA-PRE (BBS98 Shared-Modulus)"; }

    @Override
    public byte[] generateReEncryptionKey(byte[] alicePrivateKey, byte[] bobPublicKey) {
        RSAKeyPair alice = RSAKeyPair.decodePrivateKey(alicePrivateKey);
        RSAKeyPair bob = RSAKeyPair.decodePublicKey(bobPublicKey);
        if (!alice.n.equals(bob.n)) {
            throw new IllegalArgumentException("RSA-PRE requires shared modulus N");
        }
        // rk = e_B * d_A mod φ(N)
        BigInteger rk = bob.e.multiply(alice.d).mod(alice.phi);
        return rk.toByteArray();
    }

    @Override
    public EncryptedMessage encrypt(byte[] plaintext, byte[] alicePublicKey) {
        RSAKeyPair alicePub = RSAKeyPair.decodePublicKey(alicePublicKey);
        try {
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

            // RSA 加密 AES 密钥: keyNum = bytesToBigInt(aesKey) ^ e_A mod N
            BigInteger keyNum = new BigInteger(1, aesKey.getEncoded());
            BigInteger encryptedKey = keyNum.modPow(alicePub.e, alicePub.n);

            // 组合: iv || encryptedKeyLen(4) || encryptedKey || encryptedData
            byte[] ekb = encryptedKey.toByteArray();
            byte[] primary = new byte[GCM_IV_LEN + 4 + ekb.length + encryptedData.length];
            System.arraycopy(iv, 0, primary, 0, GCM_IV_LEN);
            byte[] lenb = intToBytes(ekb.length);
            System.arraycopy(lenb, 0, primary, GCM_IV_LEN, 4);
            System.arraycopy(ekb, 0, primary, GCM_IV_LEN + 4, ekb.length);
            System.arraycopy(encryptedData, 0, primary, GCM_IV_LEN + 4 + ekb.length, encryptedData.length);

            return new EncryptedMessage(primary, null);
        } catch (Exception e) {
            throw new RuntimeException("RSA-PRE encryption failed", e);
        }
    }

    @Override
    public EncryptedMessage reEncrypt(EncryptedMessage ciphertext, byte[] reEncryptionKey) {
        byte[] primary = ciphertext.primaryData();

        // parse: iv || encKeyLen(4) || encryptedKey || encryptedData
        int ekLen = bytesToInt(primary, GCM_IV_LEN);
        byte[] encryptedKey = Arrays.copyOfRange(primary, GCM_IV_LEN + 4, GCM_IV_LEN + 4 + ekLen);
        byte[] encryptedData = Arrays.copyOfRange(primary, GCM_IV_LEN + 4 + ekLen, primary.length);

        // reEncryptionKey = NLen(4) || N || rk
        int nLen = bytesToInt(reEncryptionKey, 0);
        BigInteger n = new BigInteger(1, Arrays.copyOfRange(reEncryptionKey, 4, 4 + nLen));
        byte[] rkBytes = Arrays.copyOfRange(reEncryptionKey, 4 + nLen, reEncryptionKey.length);
        BigInteger rkVal = new BigInteger(1, rkBytes);

        // 重加密: newEncryptedKey = encryptedKey^rk mod N = keyNum^(e_A * e_B * d_A) mod N = keyNum^e_B mod N
        BigInteger oldEncKey = new BigInteger(1, encryptedKey);
        BigInteger newEncKey = oldEncKey.modPow(rkVal, n);

        // 重建密文
        byte[] newEkb = newEncKey.toByteArray();
        byte[] newPrimary = new byte[GCM_IV_LEN + 4 + newEkb.length + encryptedData.length];
        System.arraycopy(primary, 0, newPrimary, 0, GCM_IV_LEN); // iv
        byte[] newLenb = intToBytes(newEkb.length);
        System.arraycopy(newLenb, 0, newPrimary, GCM_IV_LEN, 4);
        System.arraycopy(newEkb, 0, newPrimary, GCM_IV_LEN + 4, newEkb.length);
        System.arraycopy(encryptedData, 0, newPrimary, GCM_IV_LEN + 4 + newEkb.length, encryptedData.length);

        return new EncryptedMessage(newPrimary, null);
    }

    @Override
    public byte[] decrypt(EncryptedMessage ciphertext, byte[] bobPrivateKey) {
        RSAKeyPair bob = RSAKeyPair.decodePrivateKey(bobPrivateKey);
        byte[] primary = ciphertext.primaryData();
        try {
            // 解析
            byte[] iv = Arrays.copyOfRange(primary, 0, GCM_IV_LEN);
            int ekLen = bytesToInt(primary, GCM_IV_LEN);
            byte[] encryptedKey = Arrays.copyOfRange(primary, GCM_IV_LEN + 4, GCM_IV_LEN + 4 + ekLen);
            byte[] encryptedData = Arrays.copyOfRange(primary, GCM_IV_LEN + 4 + ekLen, primary.length);

            // RSA 解密 AES 密钥
            BigInteger encKeyNum = new BigInteger(1, encryptedKey);
            BigInteger keyNum = encKeyNum.modPow(bob.d, bob.n);
            byte[] keyBytes = keyNum.toByteArray();
            int keySize = AES_KEY_SIZE / 8;
            if (keyBytes.length > keySize) {
                keyBytes = Arrays.copyOfRange(keyBytes, keyBytes.length - keySize, keyBytes.length);
            } else if (keyBytes.length < keySize) {
                byte[] padded = new byte[keySize];
                System.arraycopy(keyBytes, 0, padded, keySize - keyBytes.length, keyBytes.length);
                keyBytes = padded;
            }
            SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

            // AES-GCM 解密
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LEN, iv));
            return aesCipher.doFinal(encryptedData);
        } catch (Exception e) {
            throw new RuntimeException("RSA-PRE decryption failed", e);
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
