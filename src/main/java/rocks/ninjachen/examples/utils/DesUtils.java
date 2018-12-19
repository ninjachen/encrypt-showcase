package rocks.ninjachen.examples.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

public class DesUtils {

    public static String ALGORITHM = "DES";

    private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    private static final byte[] DEFAULT_KEY_BYTES = {-111, 124, 38, -83, 37, -119, -94, 117};

    public static final Key DEFAULT_KEY = bytesToKey(DEFAULT_KEY_BYTES);

    /**
     * ENCRYPT/DECRYPT/MODE_PADDING
     */
    public static final String CIPHER_ALGORITHM = "DES/ECB/PKCS5Padding";

    public static SecretKey generateKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
        kg.init(56);
        return kg.generateKey();
    }

    public byte[] keyToBytes(Key secretKey) {
        return secretKey.getEncoded();
    }

    public static Key bytesToKey(byte[] key) {
        try {
            DESKeySpec dks = new DESKeySpec(key);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
            SecretKey secretKey = keyFactory.generateSecret(dks);
            return secretKey;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    /**
     * 加密成字符串，字节流用base64转成string
     *
     * @param plainText plainText should be less than 56 bit, the secret key length
     * @param key
     * @return
     * @throws Exception
     */
    public static String encryptToBase64Str(String plainText, Key key)
            throws Exception {
        byte[] encrypted = encrypt(plainText.getBytes(DEFAULT_CHARSET), key);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * 从base64编码的字符串解密
     *
     * @param base64EncodedStr
     * @param key
     * @return
     * @throws Exception
     */
    public static String decryptFromBase64Str(String base64EncodedStr, Key key) throws Exception {
        byte[] encryptedString = Base64.getDecoder().decode(base64EncodedStr);
        return new String(decrypt(encryptedString, key), DEFAULT_CHARSET);
    }


    public static byte[] encrypt(byte[] data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }
}
