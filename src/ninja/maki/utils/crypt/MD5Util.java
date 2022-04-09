package ninja.maki.utils.crypt;

import ninja.maki.logger.Logger;
import ninja.maki.utils.SystemUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Util {

    public static String encrypt(String content) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(content.getBytes());
            return SystemUtil.byte2hex(messageDigest.digest());
        }catch(NoSuchAlgorithmException e) {
            Logger.log(e.getMessage(), Logger.Type.ERROR);
            return null;
        }
    }
}
