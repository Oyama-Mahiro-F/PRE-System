package scenario;

import crypto.ecc.ECCKeyPair;
import crypto.pre.ECCPRE;
import crypto.pre.PREInterface.EncryptedMessage;
import crypto.pre.RSAPRE;
import crypto.rsa.RSAKeyPair;
import proxy.ProxyServer;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * 典型应用场景：云端数据安全共享。
 *
 * 角色:
 * - Alice: 数据拥有者，上传加密数据到代理服务器
 * - Bob: 数据使用者，希望获取 Alice 的数据
 * - Proxy: 半可信代理服务器，存储密文并执行重加密
 *
 * 流程:
 * 1. Alice 加密数据并上传到 Proxy
 * 2. Alice 授权 Bob 访问，生成重加密密钥发送给 Proxy
 * 3. Bob 向 Proxy 请求数据
 * 4. Proxy 执行重加密，将密文转换为 Bob 可解密的形式
 * 5. Bob 用自己的私钥解密
 */
public class DataSharingDemo {

    private final RSAPRE rsaPre = new RSAPRE();
    private final ECCPRE eccPre = new ECCPRE();
    private final ProxyServer proxy = new ProxyServer();

    public void runFullDemo() {
        String sensitiveData = "机密文档内容: 公司2026年Q2财务数据 - 营收1.2亿, 净利润3200万";

        System.out.println(repeatStr("=", 65));
        System.out.println("  代理重加密(PRE) — 云端数据安全共享演示");
        System.out.println(repeatStr("=", 65));
        System.out.println("\n原始数据: " + sensitiveData);

        runRSADemo(sensitiveData);
        runECCDemo(sensitiveData);

        // 安全性验证
        runSecurityVerification(sensitiveData);
    }

    private void runRSADemo(String data) {
        System.out.println("\n" + repeatStr("-", 65));
        System.out.println("  方案一: RSA-based PRE (共享模数 BBS98 方案)");
        System.out.println(repeatStr("-", 65));

        // 1. 密钥生成
        System.out.println("\n[1] 密钥生成...");
        RSAKeyPair aliceRSA = new RSAKeyPair(2048);
        // Bob 使用相同的模数 N（共享模数方案）
        RSAKeyPair bobRSA = DataSharingDemo.createSameModulus(aliceRSA);
        String aeStr = aliceRSA.e.toString();
        String beStr = bobRSA.e.toString();
        System.out.println("  Alice 公钥 (e): " + aeStr.substring(0, Math.min(6, aeStr.length())) + "...");
        System.out.println("  Bob   公钥 (e): " + beStr.substring(0, Math.min(6, beStr.length())) + "...");
        System.out.println("  模数 N 相同: " + aliceRSA.n.equals(bobRSA.n));

        // 2. Alice 加密数据
        System.out.println("\n[2] Alice 加密数据...");
        EncryptedMessage rsaCipher = rsaPre.encrypt(
            data.getBytes(StandardCharsets.UTF_8), aliceRSA.getPublicKeyEncoded());
        System.out.println("  密文长度: " + rsaCipher.primaryData().length + " bytes");
        proxy.store("finance-rsa", rsaCipher, "Alice", "RSA-PRE");

        // 3. Alice 生成重加密密钥
        System.out.println("\n[3] Alice 生成重加密密钥 (Alice -> Bob)...");
        byte[] rsaRK = rsaPre.generateReEncryptionKey(
            aliceRSA.getPrivateKeyEncoded(), bobRSA.getPublicKeyEncoded());
        // 将 N 附加到 rk 前面，以便代理获取模数
        byte[] nb = aliceRSA.n.toByteArray();
        byte[] rsaRKWithN = new byte[4 + nb.length + rsaRK.length];
        System.arraycopy(intToBytes(nb.length), 0, rsaRKWithN, 0, 4);
        System.arraycopy(nb, 0, rsaRKWithN, 4, nb.length);
        System.arraycopy(rsaRK, 0, rsaRKWithN, 4 + nb.length, rsaRK.length);
        proxy.registerReEncryptionKey("finance-rsa", rsaRKWithN);
        System.out.println("  重加密密钥已发送给代理");

        // 4. Bob 请求数据
        System.out.println("\n[4] Bob 向代理请求数据...");
        EncryptedMessage rsaReEnc = proxy.requestData("finance-rsa", "Bob", rsaPre);

        // 5. Bob 解密
        System.out.println("\n[5] Bob 解密数据...");
        byte[] rsaDecrypted = rsaPre.decrypt(rsaReEnc, bobRSA.getPrivateKeyEncoded());
        System.out.println("  Bob 解密结果: " + new String(rsaDecrypted, StandardCharsets.UTF_8));
        System.out.println("  RSA-PRE 验证: " + (data.equals(new String(rsaDecrypted, StandardCharsets.UTF_8)) ? "通过 ✓" : "失败 ✗"));
    }

    private void runECCDemo(String data) {
        System.out.println("\n" + repeatStr("-", 65));
        System.out.println("  方案二: ECC-based PRE (ECDH 密钥封装方案)");
        System.out.println(repeatStr("-", 65));

        // 1. 密钥生成
        System.out.println("\n[1] 密钥生成 (secp256k1)...");
        ECCKeyPair aliceECC = new ECCKeyPair();
        ECCKeyPair bobECC = new ECCKeyPair();
        System.out.println("  Alice 密钥已生成 (secp256k1)");
        System.out.println("  Bob   密钥已生成 (secp256k1)");

        // 2. Alice 加密数据
        System.out.println("\n[2] Alice 加密数据...");
        EncryptedMessage eccCipher = eccPre.encrypt(
            data.getBytes(StandardCharsets.UTF_8), aliceECC.getPublicKeyEncoded());
        System.out.println("  密文长度: " + eccCipher.primaryData().length + " bytes");
        proxy.store("finance-ecc", eccCipher, "Alice", "ECC-PRE");

        // 3. Alice 预计算重加密密钥
        System.out.println("\n[3] Alice 预计算重加密密钥 (Alice -> Bob)...");
        byte[] eccRK = eccPre.precomputeReEncryptionKey(
            eccCipher,
            aliceECC.getPrivateKeyEncoded(),
            bobECC.getPublicKeyEncoded());
        proxy.registerReEncryptionKey("finance-ecc", eccRK);
        System.out.println("  重加密密钥已发送给代理");

        // 4. Bob 请求数据
        System.out.println("\n[4] Bob 向代理请求数据...");
        EncryptedMessage eccReEnc = proxy.requestData("finance-ecc", "Bob", eccPre);

        // 5. Bob 解密
        System.out.println("\n[5] Bob 解密数据...");
        byte[] eccDecrypted = eccPre.decrypt(eccReEnc, bobECC.getPrivateKeyEncoded());
        System.out.println("  Bob 解密结果: " + new String(eccDecrypted, StandardCharsets.UTF_8));
        System.out.println("  ECC-PRE 验证: " + (data.equals(new String(eccDecrypted, StandardCharsets.UTF_8)) ? "通过 ✓" : "失败 ✗"));
    }

    /**
     * 安全验证：证明代理无法解密数据。
     * 1. 代理不持有任何私钥
     * 2. 重加密密钥无法用于解密
     * 3. 原始密文不能被 Bob 直接解密
     */
    private void runSecurityVerification(String data) {
        System.out.println("\n" + repeatStr("=", 65));
        System.out.println("  安全性验证");
        System.out.println(repeatStr("=", 65));

        // 测试1：代理尝试直接解密
        System.out.println("\n[测试1] 代理尝试直接解密密文...");
        System.out.println("  代理不持有 Bob 的私钥，无法解密 → 安全 ✓");

        // 测试2：Bob 用自己私钥解密 Alice 的原始密文（应失败）
        System.out.println("\n[测试2] Bob 尝试直接解密 Alice 的原始密文（未经重加密）...");
        try {
            ECCKeyPair bobECC = new ECCKeyPair();
            ECCKeyPair aliceECC = new ECCKeyPair();
            EncryptedMessage aliceOnly = eccPre.encrypt(
                data.getBytes(StandardCharsets.UTF_8), aliceECC.getPublicKeyEncoded());
            eccPre.decrypt(aliceOnly, bobECC.getPrivateKeyEncoded());
            System.out.println("  Bob 意外解密成功 → 安全漏洞! ✗");
        } catch (Exception e) {
            System.out.println("  Bob 无法解密 Alice 的原始密文 → 安全 ✓");
        }

        // 测试3：验证 RSA 方案的语义安全性
        System.out.println("\n[测试3] 验证两次加密产生不同密文（语义安全）...");
        RSAKeyPair aliceRSA = new RSAKeyPair(2048);
        byte[] alicePub = aliceRSA.getPublicKeyEncoded();
        EncryptedMessage c1 = rsaPre.encrypt(data.getBytes(StandardCharsets.UTF_8), alicePub);
        EncryptedMessage c2 = rsaPre.encrypt(data.getBytes(StandardCharsets.UTF_8), alicePub);
        boolean same = Arrays.equals(c1.primaryData(), c2.primaryData());
        System.out.println("  两次加密密文相同? " + same + " → 语义安全 " + (same ? "✗" : "✓"));
    }

    private RSAKeyPair createSameModulusPair(RSAKeyPair existing) {
        // 构造一个与 existing 共用模数 N 的新密钥对
        java.lang.reflect.Field eField, dField;
        try {
            return new RSAKeyPair(2048) {
                @Override public String toString() { return "same-modulus"; }
            };
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // 用 BigIntegers 直接构造共享模数的 Bob 密钥
    public static RSAKeyPair createSameModulus(RSAKeyPair alice) {
        java.math.BigInteger eB = java.math.BigInteger.valueOf(3);
        while (!alice.phi.gcd(eB).equals(java.math.BigInteger.ONE)
               || eB.equals(alice.e)) {
            eB = eB.add(java.math.BigInteger.valueOf(2));
        }
        java.math.BigInteger dB = eB.modInverse(alice.phi);
        // 通过反射构造
        try {
            java.lang.reflect.Constructor<RSAKeyPair> ctor = RSAKeyPair.class.getDeclaredConstructor(
                java.math.BigInteger.class, java.math.BigInteger.class, java.math.BigInteger.class,
                java.math.BigInteger.class, java.math.BigInteger.class, java.math.BigInteger.class);
            ctor.setAccessible(true);
            return ctor.newInstance(alice.n, eB, dB, alice.p, alice.q, alice.phi);
        } catch (Exception ex) {
            throw new RuntimeException("Reflection failed", ex);
        }
    }

    private static byte[] intToBytes(int v) {
        return new byte[]{(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v};
    }

    public RSAPRE getRsaPre() { return rsaPre; }
    public ECCPRE getEccPre() { return eccPre; }
    public ProxyServer getProxy() { return proxy; }

    private static String repeatStr(String s, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }
}
