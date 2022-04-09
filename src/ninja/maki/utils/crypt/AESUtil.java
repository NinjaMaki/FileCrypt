package ninja.maki.utils.crypt;

import ninja.maki.logger.Logger;
import ninja.maki.utils.SystemUtil;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class AESUtil {
    private final Map<INPUT, String> map = new HashMap<>();

    public AESUtil(TYPE type) {
        map.put(INPUT.KEY, SystemUtil.getRandom(16));
        if(type == TYPE.CBC) {
            map.put(INPUT.IV, SystemUtil.getRandom(16));
        }
    }

    public AESUtil(String key) {
        map.clear();
        map.put(INPUT.KEY, key);
    }

    public AESUtil(String key, String iv) {
        map.clear();
        map.put(INPUT.KEY, key);
        map.put(INPUT.IV, iv);
    }

    public void setKeyFromString(String pass) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128, new SecureRandom(pass.getBytes()));
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] b = secretKey.getEncoded();
            String key = SystemUtil.byte2hex(b);
            map.put(INPUT.KEY, key);
        }catch (NoSuchAlgorithmException e) {
            Logger.log(e.getMessage(), Logger.Type.ERROR);
        }
    }

    public String getKey() {
        return map.get(INPUT.KEY);
    }

    public String getIv() {
        return map.get(INPUT.IV);
    }

    public String encrypt(String content) throws Exception {
        String key = getKey();
        if (key == null) {
            Logger.log("Where's the key bruh.", Logger.Type.ERROR);
            return null;
        }
        String iv = getIv();
        if (iv == null) {
            byte[] raw = key.getBytes("utf-8");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            byte[] encrypted = cipher.doFinal(content.getBytes("utf-8"));
            return new BASE64Encoder().encode(encrypted);
        }else {
            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                int blockSize = cipher.getBlockSize();
                byte[] dataBytes = content.getBytes();
                int plaintextLength = dataBytes.length;
                if (plaintextLength % blockSize != 0) {
                    plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
                }
                byte[] plaintext = new byte[plaintextLength];
                System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);
                SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
                IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes());
                cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
                byte[] encrypted = cipher.doFinal(plaintext);
                return new BASE64Encoder().encode(encrypted);
            } catch (Exception e) {
                Logger.log(e.getMessage(), Logger.Type.ERROR);
                return null;
            }
        }
    }

    public String decrypt(String content) throws Exception {
        String key = getKey();
        if (key == null) {
            Logger.log("Where's the key bruh.", Logger.Type.ERROR);
            return null;
        }
        String iv = getIv();
        if (iv == null) {
            byte[] raw = key.getBytes("utf-8");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            byte[] encrypted1 = new BASE64Decoder().decodeBuffer(content);
            byte[] original = cipher.doFinal(encrypted1);
            String originalString = new String(original, "utf-8");
            return originalString;
        }else {
            byte[] encrypted1 = new BASE64Decoder().decodeBuffer(content);
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
            byte[] original = cipher.doFinal(encrypted1);
            String originalString = new String(original, "utf-8");
            return originalString;
        }
    }

    enum INPUT {
        KEY, IV
    }

    public enum TYPE {
        ECB, CBC
    }
}
