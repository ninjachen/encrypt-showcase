package rocks.ninjachen.examples.utils;


import javax.crypto.Cipher;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.HashMap;

/**
 * Main api description
 * <p>
 * genKeys
 * genKeysByHand
 * loadPublicKey
 * loadPrivateKey
 * encrypt
 * encryptToBase64Str
 * decrypt
 * decryptFromBase64Str
 * sign
 * signToBase64Str
 * verify
 * verifyFromBase64Str
 * </p>
 */
public class RSAUtils {

    /**
     * 注意在不同的jdk下可能会有不同的实现
     */
    public static String ALGORITHM = "RSA";

    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    /**
     * 生成公钥和私钥
     * @param keySize at least 512 bit(RSA)
     * @throws NoSuchAlgorithmException
     */
    public static RSAKeyPair genKeys(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGen.initialize(keySize);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKeyPair(privateKey, publicKey);
    }

    /**
     * 手工制作公私钥，通过计算互质大数。
     *
     * @return 公钥和私钥
     */
    public static HashMap<String, Key> genKeysByHand() {
        int keySize = 512;
        SecureRandom random = new SecureRandom();
        // Choose two distinct prime numbers p and q.
        BigInteger p = BigInteger.probablePrime(keySize / 2, random);
        BigInteger q = BigInteger.probablePrime(keySize / 2, random);
        // Compute n = pq (modulus)
        BigInteger modulus = p.multiply(q);
        // Compute φ(n) = φ(p)φ(q) = (p − 1)(q − 1) = n - (p + q -1), where φ is Euler's totient function.
        // and choose an integer e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1; i.e., e and φ(n) are coprime.
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        BigInteger publicExponent = getCoprime(m, random);
        // Determine d as d ≡ e−1 (mod φ(n)); i.e., d is the multiplicative inverse of e (modulo φ(n)).
        BigInteger privateExponent = publicExponent.modInverse(m);

        try {
            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);
            RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(modulus, privateExponent);

            KeyFactory factory = KeyFactory.getInstance("RSA");

            PublicKey pub = factory.generatePublic(spec);
            PrivateKey priv = factory.generatePrivate(privateSpec);

            HashMap<String, Key> map = new HashMap<>();
            map.put("public", pub);
            map.put("private", priv);
            return map;
        } catch (Exception e) {
            System.out.println(e.toString());
        }
        return null;
    }

    public static BigInteger getCoprime(BigInteger m, SecureRandom random) {
        int length = m.bitLength() - 1;
        BigInteger e = BigInteger.probablePrime(length, random);
        while (!(m.gcd(e)).equals(BigInteger.ONE)) {
            e = BigInteger.probablePrime(length, random);
        }
        return e;
    }

    /**
     * 使用模和指数生成RSA公钥
     * 注意：【此代码用了默认补位方式，为RSA/None/PKCS1Padding，不同JDK默认的补位方式可能不同，如Android默认是RSA
     * /None/NoPadding】
     *
     * @param modulus  模 16进制
     * @param exponent 指数 16进制
     * @return
     */
    public static RSAPublicKey genPublicKey(String modulus, String exponent) {
        try {
            int radix = 16;
            BigInteger b1 = new BigInteger(modulus, radix);
            BigInteger b2 = new BigInteger(exponent, radix);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(b1, b2);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 使用模和指数生成RSA私钥
     * 注意：【此代码用了默认补位方式，为RSA/None/PKCS1Padding，不同JDK默认的补位方式可能不同，如Android默认是RSA
     * /None/NoPadding】
     *
     * @param modulus  模
     * @param exponent 指数
     * @return
     */
    public static RSAPrivateKey genPrivateKey(String modulus, String exponent) {
        try {
            int radix = 16;
            BigInteger b1 = new BigInteger(modulus, radix);
            BigInteger b2 = new BigInteger(exponent, radix);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(b1, b2);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 生成私钥
     * generate private key from der file
     *
     * @param privKeyFile private file, der encoding
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static RSAPrivateKey genPrivateKeyFromFile(File privKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // read private key DER file
        DataInputStream dis = new DataInputStream(new FileInputStream(privKeyFile));
        byte[] privKeyBytes = new byte[(int) privKeyFile.length()];
        dis.read(privKeyBytes);
        dis.close();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // decode private key
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
        RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);
        return privKey;
    }

    /**
     * 生成公钥
     * generate public key from der file
     *
     * @param pubKeyFile
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static RSAPublicKey genPublicKeyFromFile(File pubKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // read public key DER file
        DataInputStream dis = new DataInputStream(new FileInputStream(pubKeyFile));
        byte[] pubKeyBytes = new byte[(int) pubKeyFile.length()];
        dis.readFully(pubKeyBytes);
        dis.close();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // decode public key
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
        RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubSpec);
        return pubKey;
    }

    /**
     * 公钥加密
     * encrypt with public key
     *
     * @param plainText
     * @param publicKey
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(String plainText, RSAPublicKey publicKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(DEFAULT_CHARSET));
        return encrypted;
    }

    /**
     * 私钥解密
     * decrypt with private key
     *
     * @param encryptedBytes
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static String decrypt(byte[] encryptedBytes, RSAPrivateKey privateKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] originBytes = cipher.doFinal(encryptedBytes);
        return new String(originBytes, DEFAULT_CHARSET);
    }

    /**
     * 加密成字符串，字节流用base64转成string
     *
     * @param plainText
     * @param publicKey
     * @return
     * @throws Exception
     */
    public static String encryptToBase64Str(String plainText, RSAPublicKey publicKey)
            throws Exception {
        byte[] encrypted = encrypt(plainText, publicKey);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * 从base64编码的字符串解密
     *
     * @param base64EncodedStr
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static String decryptFromBase64Str(String base64EncodedStr, RSAPrivateKey privateKey) throws Exception {
        byte[] encryptedString = Base64.getDecoder().decode(base64EncodedStr);
        return decrypt(encryptedString, privateKey);
    }

    /**
     * 私钥签名
     *
     * @param plainText
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static byte[] sign(String plainText, RSAPrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(DEFAULT_CHARSET));
        return privateSignature.sign();
    }

    /**
     * 私钥签名成base64字符串
     *
     * @param plainText
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static String signToBase64Str(String plainText, RSAPrivateKey privateKey) throws Exception {
        byte[] signature = sign(plainText, privateKey);
        return signature == null ? null : Base64.getEncoder().encodeToString(signature);
    }

    /**
     * 验证签名
     *
     * @param signature
     * @param plainText
     * @param publicKey
     * @return
     * @throws Exception
     */
    public static boolean verify(byte[] signature, String plainText, RSAPublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(DEFAULT_CHARSET));
        return publicSignature.verify(signature);
    }

    /**
     * 验证base64编码的签名
     *
     * @param base64EncodedSignature
     * @param plainText
     * @param publicKey
     * @return
     * @throws Exception
     */
    public static boolean verifyFromBase64Str(String base64EncodedSignature, String plainText, RSAPublicKey publicKey) throws Exception {
        byte[] signature = Base64.getDecoder().decode(base64EncodedSignature);
        return verify(signature, plainText, publicKey);
    }

    /**
     * RSAKey bundle
     */
    public static class RSAKeyPair {
        private RSAPrivateKey privateKey;
        private RSAPublicKey publicKey;

        public RSAKeyPair() {}

        public RSAKeyPair(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public RSAPrivateKey getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(RSAPrivateKey privateKey) {
            this.privateKey = privateKey;
        }

        public RSAPublicKey getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(RSAPublicKey publicKey) {
            this.publicKey = publicKey;
        }
    }
}