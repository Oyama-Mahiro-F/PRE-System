import crypto.ecc.ECCKeyPair;
import crypto.pre.ECCPRE;
import crypto.pre.PREInterface.EncryptedMessage;
import crypto.pre.RSAPRE;
import crypto.rsa.RSAKeyPair;
import proxy.ProxyServer;
import scenario.DataSharingDemo;

import java.nio.charset.StandardCharsets;

/**
 * PRE data security management system — main entry.
 */
public class Main {

    public static void main(String[] args) {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║  基于代理重加密的数据安全管理算法实现                        ║");
        System.out.println("║  北京邮电大学 信息安全编程技术与实例开发 课程设计            ║");
        System.out.println("║  RSA-PRE (BBS98) & ECC-PRE (ECDH) 方案对比                   ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        DataSharingDemo demo = new DataSharingDemo();
        demo.runFullDemo();

        System.out.println("\n\n");
        runPerformanceComparison();

        System.out.println("\n所有测试完成。");
        System.out.println("\n按任意键退出...");
        try { System.in.read(); } catch (Exception ignored) {}
    }

    private static void runPerformanceComparison() {
        System.out.println(repeat("=", 65));
        System.out.println("  性能对比: RSA-PRE vs ECC-PRE");
        System.out.println(repeat("=", 65));

        RSAPRE rsaPre = new RSAPRE();
        ECCPRE eccPre = new ECCPRE();

        String testData = repeatStr("测试数据: 1234567890ABCDEF", 50);
        byte[] plaintext = testData.getBytes(StandardCharsets.UTF_8);
        int warmup = 5;
        int iterations = 20;

        // === RSA-PRE ===
        System.out.println("\n[RSA-PRE] 密钥生成...");
        long t0 = System.nanoTime();
        RSAKeyPair aliceRSA = new RSAKeyPair(2048);
        RSAKeyPair bobRSA = DataSharingDemo.createSameModulus(aliceRSA);
        long t1 = System.nanoTime();
        System.out.printf("  RSA-2048 密钥对生成: %.2f ms%n", (t1 - t0) / 1_000_000.0);

        // Warmup
        for (int i = 0; i < warmup; i++) {
            EncryptedMessage c = rsaPre.encrypt(plaintext, aliceRSA.getPublicKeyEncoded());
            byte[] rk = rsaPre.generateReEncryptionKey(aliceRSA.getPrivateKeyEncoded(), bobRSA.getPublicKeyEncoded());
            byte[] nb = aliceRSA.n.toByteArray();
            byte[] rkWithN = new byte[4 + nb.length + rk.length];
            System.arraycopy(intToBytes(nb.length), 0, rkWithN, 0, 4);
            System.arraycopy(nb, 0, rkWithN, 4, nb.length);
            System.arraycopy(rk, 0, rkWithN, 4 + nb.length, rk.length);
            EncryptedMessage rc = rsaPre.reEncrypt(c, rkWithN);
            rsaPre.decrypt(rc, bobRSA.getPrivateKeyEncoded());
        }

        double rsaEncTotal = 0, rsaReKeyTotal = 0, rsaReEncTotal = 0, rsaDecTotal = 0;
        for (int i = 0; i < iterations; i++) {
            t0 = System.nanoTime();
            EncryptedMessage c = rsaPre.encrypt(plaintext, aliceRSA.getPublicKeyEncoded());
            t1 = System.nanoTime();
            rsaEncTotal += (t1 - t0);

            t0 = System.nanoTime();
            byte[] rk = rsaPre.generateReEncryptionKey(aliceRSA.getPrivateKeyEncoded(), bobRSA.getPublicKeyEncoded());
            byte[] nb = aliceRSA.n.toByteArray();
            byte[] rkWithN = new byte[4 + nb.length + rk.length];
            System.arraycopy(intToBytes(nb.length), 0, rkWithN, 0, 4);
            System.arraycopy(nb, 0, rkWithN, 4, nb.length);
            System.arraycopy(rk, 0, rkWithN, 4 + nb.length, rk.length);
            t1 = System.nanoTime();
            rsaReKeyTotal += (t1 - t0);

            t0 = System.nanoTime();
            EncryptedMessage rc = rsaPre.reEncrypt(c, rkWithN);
            t1 = System.nanoTime();
            rsaReEncTotal += (t1 - t0);

            t0 = System.nanoTime();
            rsaPre.decrypt(rc, bobRSA.getPrivateKeyEncoded());
            t1 = System.nanoTime();
            rsaDecTotal += (t1 - t0);
        }

        System.out.printf("  RSA-加密:        %.2f ms (avg)%n", rsaEncTotal / iterations / 1_000_000);
        System.out.printf("  RSA-重加密密钥:  %.2f ms (avg)%n", rsaReKeyTotal / iterations / 1_000_000);
        System.out.printf("  RSA-重加密:      %.2f ms (avg)%n", rsaReEncTotal / iterations / 1_000_000);
        System.out.printf("  RSA-解密:        %.2f ms (avg)%n", rsaDecTotal / iterations / 1_000_000);

        // === ECC-PRE ===
        System.out.println("\n[ECC-PRE] 密钥生成...");
        t0 = System.nanoTime();
        ECCKeyPair aliceECC = new ECCKeyPair();
        ECCKeyPair bobECC = new ECCKeyPair();
        t1 = System.nanoTime();
        System.out.printf("  ECC-256 密钥对生成: %.2f ms%n", (t1 - t0) / 1_000_000.0);

        for (int i = 0; i < warmup; i++) {
            EncryptedMessage c = eccPre.encrypt(plaintext, aliceECC.getPublicKeyEncoded());
            byte[] rk = eccPre.precomputeReEncryptionKey(c,
                aliceECC.getPrivateKeyEncoded(), bobECC.getPublicKeyEncoded());
            EncryptedMessage rc = eccPre.reEncrypt(c, rk);
            eccPre.decrypt(rc, bobECC.getPrivateKeyEncoded());
        }

        double eccEncTotal = 0, eccReKeyTotal = 0, eccReEncTotal = 0, eccDecTotal = 0;
        for (int i = 0; i < iterations; i++) {
            t0 = System.nanoTime();
            EncryptedMessage c = eccPre.encrypt(plaintext, aliceECC.getPublicKeyEncoded());
            t1 = System.nanoTime();
            eccEncTotal += (t1 - t0);

            t0 = System.nanoTime();
            byte[] rk = eccPre.precomputeReEncryptionKey(c,
                aliceECC.getPrivateKeyEncoded(), bobECC.getPublicKeyEncoded());
            t1 = System.nanoTime();
            eccReKeyTotal += (t1 - t0);

            t0 = System.nanoTime();
            EncryptedMessage rc = eccPre.reEncrypt(c, rk);
            t1 = System.nanoTime();
            eccReEncTotal += (t1 - t0);

            t0 = System.nanoTime();
            eccPre.decrypt(rc, bobECC.getPrivateKeyEncoded());
            t1 = System.nanoTime();
            eccDecTotal += (t1 - t0);
        }

        System.out.printf("  ECC-加密:        %.2f ms (avg)%n", eccEncTotal / iterations / 1_000_000);
        System.out.printf("  ECC-重加密密钥:  %.2f ms (avg)%n", eccReKeyTotal / iterations / 1_000_000);
        System.out.printf("  ECC-重加密:      %.2f ms (avg)%n", eccReEncTotal / iterations / 1_000_000);
        System.out.printf("  ECC-解密:        %.2f ms (avg)%n", eccDecTotal / iterations / 1_000_000);

        // 汇总
        System.out.println("\n" + repeat("=", 65));
        System.out.println("  性能汇总对比 (avg of " + iterations + " iterations, ~1KB data)");
        System.out.println(repeat("=", 65));
        System.out.printf("  %-16s %10s %10s %10s %10s%n", "方案", "加密(ms)", "重密钥(ms)", "重加密(ms)", "解密(ms)");
        System.out.println("  " + repeat("-", 56));
        System.out.printf("  %-16s %10.2f %10.2f %10.2f %10.2f%n", "RSA-2048",
            rsaEncTotal / iterations / 1_000_000, rsaReKeyTotal / iterations / 1_000_000,
            rsaReEncTotal / iterations / 1_000_000, rsaDecTotal / iterations / 1_000_000);
        System.out.printf("  %-16s %10.2f %10.2f %10.2f %10.2f%n", "ECC-secp256k1",
            eccEncTotal / iterations / 1_000_000, eccReKeyTotal / iterations / 1_000_000,
            eccReEncTotal / iterations / 1_000_000, eccDecTotal / iterations / 1_000_000);
        System.out.println();

        System.out.println(" 安全性对比:");
        System.out.println("   RSA-PRE: 共享模数方案，N 相同，(e_A,d_A)和(e_B,d_B)独立");
        System.out.println("            优点: 数学简洁，重加密过程仅为一次模幂运算");
        System.out.println("            局限: 需共享 N，实际部署中双方需协商模数");
        System.out.println("   ECC-PRE: ECDH 密钥封装，Alice 预计算 Bob 的 wrapped key");
        System.out.println("            优点: 密钥独立，安全性更高，密钥和密文更短");
        System.out.println("            局限: 重加密需 Alice 在线预计算");
        System.out.println("   代理在任何方案中均无法获取明文数据 ✓");
    }

    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }

    private static String repeatStr(String s, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }

    private static byte[] intToBytes(int v) {
        return new byte[]{(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v};
    }
}
