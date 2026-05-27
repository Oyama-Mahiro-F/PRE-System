package crypto.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAKeyPair {
    public final BigInteger n;
    public final BigInteger e;
    public final BigInteger d;
    public final BigInteger p;
    public final BigInteger q;
    public final BigInteger phi;

    public RSAKeyPair(int bitLength) {
        SecureRandom random = new SecureRandom();
        BigInteger primeP = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger primeQ = BigInteger.probablePrime(bitLength / 2, random);
        while (primeP.equals(primeQ)) {
            primeQ = BigInteger.probablePrime(bitLength / 2, random);
        }
        p = primeP;
        q = primeQ;
        n = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger eVal = BigInteger.valueOf(65537);
        while (!phi.gcd(eVal).equals(BigInteger.ONE)) {
            eVal = eVal.add(BigInteger.valueOf(2));
        }
        e = eVal;
        d = e.modInverse(phi);
    }

    /** 用已有参数构造 */
    private RSAKeyPair(BigInteger n, BigInteger e, BigInteger d,
                       BigInteger p, BigInteger q, BigInteger phi) {
        this.n = n; this.e = e; this.d = d;
        this.p = p; this.q = q; this.phi = phi;
    }

    public byte[] getPublicKeyEncoded() {
        // 格式: e 长度(4字节) || e || n 长度(4字节) || n
        byte[] eb = e.toByteArray();
        byte[] nb = n.toByteArray();
        byte[] encoded = new byte[8 + eb.length + nb.length];
        System.arraycopy(intToBytes(eb.length), 0, encoded, 0, 4);
        System.arraycopy(eb, 0, encoded, 4, eb.length);
        System.arraycopy(intToBytes(nb.length), 0, encoded, 4 + eb.length, 4);
        System.arraycopy(nb, 0, encoded, 8 + eb.length, nb.length);
        return encoded;
    }

    public byte[] getPrivateKeyEncoded() {
        byte[] db = d.toByteArray();
        byte[] nb = n.toByteArray();
        byte[] phib = phi.toByteArray();
        byte[] encoded = new byte[12 + db.length + nb.length + phib.length];
        System.arraycopy(intToBytes(db.length), 0, encoded, 0, 4);
        System.arraycopy(db, 0, encoded, 4, db.length);
        int offset = 4 + db.length;
        System.arraycopy(intToBytes(nb.length), 0, encoded, offset, 4);
        System.arraycopy(nb, 0, encoded, offset + 4, nb.length);
        offset = offset + 4 + nb.length;
        System.arraycopy(intToBytes(phib.length), 0, encoded, offset, 4);
        System.arraycopy(phib, 0, encoded, offset + 4, phib.length);
        return encoded;
    }

    public static RSAKeyPair decodePublicKey(byte[] encoded) {
        int eLen = bytesToInt(encoded, 0);
        BigInteger e = new BigInteger(1, java.util.Arrays.copyOfRange(encoded, 4, 4 + eLen));
        int nLen = bytesToInt(encoded, 4 + eLen);
        BigInteger n = new BigInteger(1, java.util.Arrays.copyOfRange(encoded, 8 + eLen, 8 + eLen + nLen));
        return new RSAKeyPair(n, e, null, null, null, null);
    }

    public static RSAKeyPair decodePrivateKey(byte[] encoded) {
        int dLen = bytesToInt(encoded, 0);
        BigInteger d = new BigInteger(1, java.util.Arrays.copyOfRange(encoded, 4, 4 + dLen));
        int offset = 4 + dLen;
        int nLen = bytesToInt(encoded, offset);
        BigInteger n = new BigInteger(1, java.util.Arrays.copyOfRange(encoded, offset + 4, offset + 4 + nLen));
        offset = offset + 4 + nLen;
        int phiLen = bytesToInt(encoded, offset);
        BigInteger phi = new BigInteger(1, java.util.Arrays.copyOfRange(encoded, offset + 4, offset + 4 + phiLen));
        return new RSAKeyPair(n, null, d, null, null, phi);
    }

    private static byte[] intToBytes(int v) {
        return new byte[]{(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v};
    }

    private static int bytesToInt(byte[] b, int off) {
        return ((b[off] & 0xFF) << 24) | ((b[off+1] & 0xFF) << 16)
             | ((b[off+2] & 0xFF) << 8)  | (b[off+3] & 0xFF);
    }
}
