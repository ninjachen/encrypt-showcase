package rocks.ninjachen.examples.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.Key;

public class DesUtilsTest {
    Key secretKey;
    String plainText = "de Sede AG uses cookies in order to improve your online experience. By continuing to use desede.ch, you accept our cookie policy";

    @BeforeEach
    public void setUp() throws Exception {
        secretKey = DesUtils.generateKey();
        byte[] keyBytes = {-100, 124, 38, -22, 37, -2, -94, 101};
        secretKey = DesUtils.bytesToKey(keyBytes);
    }

    @Test
    public void generateKey() throws Exception{
        Assertions.assertNotNull(DesUtils.generateKey());
    }

    @Test
    public void encryptAndDecrypt() throws Exception {
        String encrypted = DesUtils.encryptToBase64Str(plainText, secretKey);
        String decrypted = DesUtils.decryptFromBase64Str(encrypted, secretKey);
        Assertions.assertEquals(plainText, decrypted);
    }

}