# PRE-System — 代理重加密数据安全管理系统

北京邮电大学 信息安全编程技术与实例开发 课程设计

## 概述

基于**代理重加密（Proxy Re-Encryption, PRE）**技术实现数据安全管理与共享。包含两种方案：

| 方案 | 算法 | 说明 |
|------|------|------|
| RSA-PRE | BBS98 共享模数 | 数学简洁，重加密为单次模幂运算 |
| ECC-PRE | ECDH 密钥封装 | 密钥独立，安全性更高，密文更短 |

## 应用场景

云端数据安全共享：Alice 加密数据上传 → 代理服务器 → 授权后 Bob 解密。代理全程无法获取明文。

## 项目结构

```
src/
├── Main.java                     # 入口 + 性能对比
├── crypto/
│   ├── pre/
│   │   ├── PREInterface.java     # 公共接口
│   │   ├── RSAPRE.java           # RSA-PRE 实现
│   │   └── ECCPRE.java           # ECC-PRE 实现
│   ├── rsa/RSAKeyPair.java       # RSA 密钥工具
│   └── ecc/ECCKeyPair.java       # ECC 密钥工具
├── proxy/ProxyServer.java        # 半可信代理服务器
└── scenario/DataSharingDemo.java # 数据共享场景演示
```

## 运行

**Windows** — 双击 `build.bat`  
**Linux/Mac** — `bash build.sh`

或手动：

```bash
javac -encoding UTF-8 -d out src/crypto/pre/*.java src/crypto/rsa/*.java src/crypto/ecc/*.java src/proxy/*.java src/scenario/*.java src/Main.java
java -Dfile.encoding=UTF-8 -cp out Main
```

## 环境要求

- JDK 1.8+
- 零外部依赖（仅使用 Java 标准库 JCA + SunEC）

## 验证结果

- RSA-PRE 加密→重加密→解密 ✓
- ECC-PRE 加密→重加密→解密 ✓
- 代理无法获取明文 ✓
- 语义安全（相同明文不同密文）✓

## 性能 (avg, ~1KB data)

| 操作 | RSA-2048 | ECC-secp256r1 |
|------|----------|---------------|
| 加密 | 0.37 ms | 2.14 ms |
| 重加密 | 11.01 ms | ~0 ms |
| 解密 | 11.55 ms | 1.42 ms |
