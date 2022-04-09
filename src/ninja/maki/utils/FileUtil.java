package ninja.maki.utils;

import ninja.maki.FileCrypt;
import ninja.maki.logger.Logger;
import ninja.maki.utils.crypt.AESUtil;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.Arrays;

public class FileUtil {

    public static void encrypt(String input, boolean replace) {
        Thread t = new Thread(() -> {
            long start = System.currentTimeMillis();
            try {
                FileInputStream fileInputStream = new FileInputStream(input);
                if(input.substring(input.lastIndexOf(".")).equalsIgnoreCase("." + FileCrypt.AUTHOR.toLowerCase())) {
                    Logger.log("Already encrypted <" + input + ">.", Logger.Type.ERROR);
                    return;
                }
                if(!canEncrypt(input)) {
                    Logger.log("Cannot encrypt <" + input + ">, please check whitelist(top priority) and blacklist.", Logger.Type.ERROR);
                    return;
                }
                String output = input + "." + FileCrypt.AUTHOR.toLowerCase();
                Logger.log("Start encrypt <" + input + "> to <" + output + ">.", Logger.Type.SUCCESS);
                FileOutputStream fileOutputStream = new FileOutputStream(output);
                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                keyGenerator.init(128);
                SecretKey secretKey = keyGenerator.generateKey();
                byte[] key = secretKey.getEncoded();
                byte[] iv = SystemUtil.getRandom(16).getBytes();
                AESUtil aesUtil = new AESUtil(AESUtil.TYPE.ECB);
                aesUtil.setKeyFromString(FileCrypt.NAME.toLowerCase() + FileCrypt.AUTHOR.toLowerCase());
                fileOutputStream.write(aesUtil.encrypt(FileCrypt.NAME).getBytes());
                fileOutputStream.write(key);
                fileOutputStream.write(aesUtil.encrypt(FileCrypt.AUTHOR).getBytes());
                fileOutputStream.write(iv);
                Logger.log("Created and written sign, key and iv to <" + output + ">.(" + (System.currentTimeMillis() - start) + "ms)", Logger.Type.INFO);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);
                byte[] buffer = new byte[1024];
                int n;
                while ((n = cipherInputStream.read(buffer)) != -1) {
                    fileOutputStream.write(buffer, 0, n);
                }
                cipherInputStream.close();
                fileInputStream.close();
                fileOutputStream.close();
                if(replace) {
                    File inputFile = new File(input);
                    inputFile.delete();
                }
                Logger.log("Successfully encrypt <" + input + "> to <" + output + ">.(" + (System.currentTimeMillis() - start) + "ms)", Logger.Type.SUCCESS);
            } catch (FileNotFoundException e) {
                String[] list = new File(input).list();
                if (list == null) {
                    Logger.log(e.getMessage(), Logger.Type.ERROR);
                    return;
                }
                for (String file : list) {
                    FileUtil.encrypt(input + "\\" + file, replace);
                }
            } catch (Exception e) {
                Logger.log(e.getMessage(), Logger.Type.ERROR);
            }
        });
        t.start();
    }

    public static void decrypt(String input, boolean replace) {
        Thread t = new Thread(() -> {
            long start = System.currentTimeMillis();
            try {
                FileInputStream fileInputStream = new FileInputStream(input);
                if (!input.substring(input.lastIndexOf(".")).equalsIgnoreCase("." + FileCrypt.AUTHOR.toLowerCase())) {
                    Logger.log("Illegal File Input.(Type)", Logger.Type.ERROR);
                    return;
                }
                String output = input.substring(0, input.lastIndexOf("."));
                Logger.log("Start decrypt <" + input + "> to <" + output + ">.", Logger.Type.SUCCESS);
                FileOutputStream fileOutputStream = new FileOutputStream(output);
                AESUtil aesUtil = new AESUtil(AESUtil.TYPE.ECB);
                aesUtil.setKeyFromString(FileCrypt.NAME.toLowerCase() + FileCrypt.AUTHOR.toLowerCase());
                byte[] nameSign = aesUtil.encrypt(FileCrypt.NAME).getBytes();
                byte[] authorSign = aesUtil.encrypt(FileCrypt.AUTHOR).getBytes();
                byte[] fileNameSign = new byte[nameSign.length];
                byte[] fileAuthorSign = new byte[authorSign.length];
                byte[] key = new byte[16];
                byte[] iv = new byte[16];
                fileInputStream.read(fileNameSign);
                fileInputStream.read(key);
                fileInputStream.read(fileAuthorSign);
                fileInputStream.read(iv);
                Logger.log("Read sign, key and iv from <" + input + ">.(" + (System.currentTimeMillis() - start) + "ms)", Logger.Type.INFO);
                if (Arrays.equals(fileNameSign, nameSign) && Arrays.equals(fileAuthorSign, authorSign)) {
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
                    CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);
                    byte[] buffer = new byte[1024];
                    int n;
                    while ((n = cipherInputStream.read(buffer)) != -1) {
                        fileOutputStream.write(buffer, 0, n);
                    }
                    cipherInputStream.close();
                    if(replace) {
                        File inputFile = new File(input);
                        inputFile.delete();
                    }
                    Logger.log("Successfully decrypt <" + input + "> to <" + output + ">.(" + (System.currentTimeMillis() - start) + "ms)", Logger.Type.SUCCESS);
                } else {
                    Logger.log("Illegal File Input.(Sign)", Logger.Type.ERROR);
                }
                fileInputStream.close();
                fileOutputStream.close();
            } catch (FileNotFoundException e) {
                String[] list = new File(input).list();
                if (list == null) {
                    Logger.log(e.getMessage(), Logger.Type.ERROR);
                    return;
                }
                for (String file : list) {
                    FileUtil.decrypt(input + "\\" + file, replace);
                }
            } catch (Exception e) {
                Logger.log(e.getMessage(), Logger.Type.ERROR);
            }
        });
        t.start();
    }

    private static boolean canEncrypt(String input) {
        if(Arrays.asList(FileCrypt.whitelist).size() == 0 && Arrays.asList(FileCrypt.blacklist).size() == 0) return true;
        String type = input.substring(input.lastIndexOf(".")).toLowerCase();
        if(Arrays.asList(FileCrypt.whitelist).size() > 0) {
            return Arrays.asList(FileCrypt.whitelist).contains(type);
        }else {
            return !Arrays.asList(FileCrypt.blacklist).contains(type);
        }
    }
}
