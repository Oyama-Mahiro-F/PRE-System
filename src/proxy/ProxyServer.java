package proxy;

import crypto.pre.PREInterface;
import crypto.pre.PREInterface.EncryptedMessage;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Semi-trusted proxy server.
 * Stores encrypted data, performs re-encryption upon owner authorization.
 */
public class ProxyServer {

    private final Map<String, StoredRecord> storage = new ConcurrentHashMap<>();
    private final Map<String, byte[]> reEncryptionKeys = new ConcurrentHashMap<>();

    public static class StoredRecord {
        public final EncryptedMessage ciphertext;
        public final String ownerId;
        public final String algorithm;

        public StoredRecord(EncryptedMessage ciphertext, String ownerId, String algorithm) {
            this.ciphertext = ciphertext;
            this.ownerId = ownerId;
            this.algorithm = algorithm;
        }
    }

    public String store(String dataId, EncryptedMessage ciphertext, String ownerId, String algorithm) {
        storage.put(dataId, new StoredRecord(ciphertext, ownerId, algorithm));
        return dataId;
    }

    public void registerReEncryptionKey(String dataId, byte[] reEncryptionKey) {
        if (!storage.containsKey(dataId)) {
            throw new IllegalArgumentException("Data not found: " + dataId);
        }
        reEncryptionKeys.put(dataId, reEncryptionKey);
    }

    public boolean hasReEncryptionKey(String dataId) {
        return reEncryptionKeys.containsKey(dataId);
    }

    public String getOwner(String dataId) {
        StoredRecord r = storage.get(dataId);
        return r != null ? r.ownerId : null;
    }

    public EncryptedMessage requestData(String dataId, String requesterId, PREInterface preEngine) {
        StoredRecord record = storage.get(dataId);
        if (record == null) throw new IllegalArgumentException("Data not found: " + dataId);

        byte[] rk = reEncryptionKeys.get(dataId);
        if (rk == null) {
            throw new SecurityException("No re-encryption key for " + dataId
                + ". Owner has not authorized sharing.");
        }

        System.out.println("  [Proxy] re-encrypting: " + preEngine.getAlgorithmName());
        System.out.println("  [Proxy] original ciphertext size: " + record.ciphertext.primaryData().length + " bytes");
        EncryptedMessage reEncrypted = preEngine.reEncrypt(record.ciphertext, rk);
        System.out.println("  [Proxy] re-encrypted ciphertext size: " + reEncrypted.primaryData().length + " bytes");
        System.out.println("  [Proxy] cannot access plaintext ✓");
        return reEncrypted;
    }

    public String[] listDataIds() {
        return storage.keySet().toArray(new String[0]);
    }

    public String getAlgorithm(String dataId) {
        StoredRecord r = storage.get(dataId);
        return r != null ? r.algorithm : null;
    }
}
