package rocks.ninjachen.examples.utils;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import sun.misc.BASE64Decoder;

import java.io.File;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static org.junit.Assert.*;

/**
 * A careful test case which cover all the usage of RSAUtils.
 * All the private and public key are under resources/ directory.
 * Keypair1: private key is private_key1.der, public key is public_key1.der.
 * Keypair2: private key is private_key2.der, public key is public_key2.der.
 * Private key and its modulus/exponent bundle are equivalent.
 * <p>
 * Generate key with openssl guide.
 * <ul>
 * <li>1. openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
 * <li>2. openssl pkcs8 -topk8 -inform PEM -in private_key.pem -outform DER -nocrypt -out private_key.der
 * <li>3. openssl rsa -inform PEM -in private_key.pem -outform DER -pubout -out public_key.der
 * </ui>
 * <p>
 * Use openssl to find out modulus and exponent.
 * <ul>
 * <li>1. openssl rsa -in private_key.pem -text -noout
 * </ul>
 */
public class RSAUtilsTest {
    public static String priKey1 = "private_key1.der";
    public static String pubKey1 = "public_key1.der";
    public static String priKey2 = "private_key2.der";
    public static String pubKey2 = "public_key2.der";
    public static String modulus = "00d897e315d51bbc9fd392f21d061723718f757cc98305067bad8c3d45a6f81f0902249a3b489fa085619a1484f86422398e691649e41851872c5185778fa26d1ab9b0b062a7525ae072b6c8252150a7ccc1084f9a7fbfc2d10aef549c8a6a0ae8fbd1230f866425123687960f963bd8fc36efa9d5fe19698dee3e64d40015be6c5428a2108b3495b216e2422feaa21c10bd3f37a03965555c25182dfc237b43fa077b43ea241de8ef184cade642b7ef5d2e92201d2906fba51e013e68a026865f51a7c47f9ddcae3eee02bff0c68a7a7da29425862a8ffa08362c02836557a85a3eea7f8540fd1b8ce4bfd2be086b3b2d79e82aa421cdea33cf2245d0ca713933";
    public static String pubExponent = "10001";
    public static String privExponent = "00abc5b173d421fe32e6f168103a8f492dbbaf5a7ad9ecb75a88a56ac67d87d3dd2a14eb384efd41a9e660f31b0d7f24616f1eca6d69771bd94efd8c12e917d0dd5c1cd39639caa785cf944420a64e37f5bbb522a48de1ffd8178afd1874f16a9ba17218132ceae9378b85762e006090525e232e172740f2247ca881005cdce1b9c3b23250a1e6232058e27aeed4dbcc12326754ad00d0e3e0c290fbca1921b48b9edfa879da1165a7d48c510e165e46815cc4f0c6d6504930903d5ef17f1da4d812c72984ecb7e183a51d0a42760a655656d8507e5e1a6f411a943e15ca85b631dddd3ea06fa36701e35e69a74f7aaacff1a423b9741f5c8ae2f39b3faa1bfde9";

    ClassLoader classLoader;
    @Before
    public void setUp() throws Exception {
        classLoader = getClass().getClassLoader();
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void genKeys() throws NoSuchAlgorithmException {
        assertNotNull(RSAUtils.genKeys());
    }

    @Test
    public void genKeysByHand() {
        assertNotNull(RSAUtils.genKeysByHand());
    }

    @Test
    public void genPublicKeyByModulusAndComponents() {
        assertNotNull(RSAUtils.genPublicKey(modulus, pubExponent));
    }

    @Test
    public void genPrivateKeyByModulusAndComponents() {
        assertNotNull(RSAUtils.genPrivateKey(modulus, privExponent));
    }

    @Test
    public void genPrivateKeyFromFile() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        assertNotNull(RSAUtils.genPrivateKeyFromFile(new File(classLoader.getResource(priKey1).getFile())));
    }

    @Test
    public void genPublicKeyFromFile() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        assertNotNull(RSAUtils.genPublicKeyFromFile(new File(classLoader.getResource(pubKey1).getFile())));
    }

    @Test
    public void encryptAndDecrypt() throws Exception {
        String plainText = "I am a long";
        byte[] encrypted = RSAUtils.encrypt(plainText, RSAUtils.genPublicKey(modulus, pubExponent));
        String decryptStr = RSAUtils.decrypt(encrypted, RSAUtils.genPrivateKey(modulus, privExponent));
        assertEquals(plainText, decryptStr);
    }

    @Test
    public void encryptAndDecryptWithBase64Encoding() throws Exception {
        String plainText = "I love milk";
        String encrypted = RSAUtils.encryptToBase64Str(plainText, RSAUtils.genPublicKey(modulus, pubExponent));
        String decryptStr = RSAUtils.decryptFromBase64Str(encrypted, RSAUtils.genPrivateKey(modulus, privExponent));
        assertEquals(plainText, decryptStr);
    }

    @Test
    public void signAndVerify() throws Exception {
        String plainText = "I am a happy dog.";
        byte[] sign = RSAUtils.sign(plainText, RSAUtils.genPrivateKey(modulus, privExponent));
        assertTrue(RSAUtils.verify(sign, plainText, RSAUtils.genPublicKey(modulus, pubExponent)));
    }

    @Test
    public void signAndVerifyWithChinese() throws Exception {
        String plainText = "I am a happy dog.Lets add some chinese。然后出现了一些方块字。";
        byte[] sign = RSAUtils.sign(plainText, RSAUtils.genPrivateKeyFromFile(new File(classLoader.getResource(priKey2).getFile())));
        assertTrue(RSAUtils.verify(sign, plainText, RSAUtils.genPublicKeyFromFile(new File(classLoader.getResource(pubKey2).getFile()))));
    }

    @Test
    public void signAndVerifyWithBase64() throws Exception {
        String plainText = "I am a happy dog.";
        String sign = RSAUtils.signToBase64Str(plainText, RSAUtils.genPrivateKey(modulus, privExponent));
        assertTrue(RSAUtils.verifyFromBase64Str(sign, plainText, RSAUtils.genPublicKey(modulus, pubExponent)));
    }
}