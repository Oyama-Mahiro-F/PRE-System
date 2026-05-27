package crypto.pre;

public interface PREInterface {
    /** 生成重加密密钥：Alice -> Bob */
    byte[] generateReEncryptionKey(byte[] alicePrivateKey, byte[] bobPublicKey);

    /** 使用 Alice 的公钥加密 */
    EncryptedMessage encrypt(byte[] plaintext, byte[] alicePublicKey);

    /** 代理执行重加密 */
    EncryptedMessage reEncrypt(EncryptedMessage ciphertext, byte[] reEncryptionKey);

    /** 使用 Bob 的私钥解密 */
    byte[] decrypt(EncryptedMessage ciphertext, byte[] bobPrivateKey);

    /** 算法名称 */
    String getAlgorithmName();

    final class EncryptedMessage {
        private final byte[] primaryData;
        private final byte[] auxiliaryData;

        public EncryptedMessage(byte[] primaryData, byte[] auxiliaryData) {
            this.primaryData = primaryData;
            this.auxiliaryData = auxiliaryData;
        }

        public byte[] primaryData() { return primaryData; }
        public byte[] auxiliaryData() { return auxiliaryData; }
    }
}
