package com.paycorp.security;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Encryption {

  private static final Logger LOGGER = LoggerFactory.getLogger(Encryption.class);

  private static final String ALGORITHM = "AES";
  private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

  public String encrypt(String plainText, String key) throws Exception {

    // Though it is Hex PHP is treating it as string and using 32 characters
    SecretKeySpec secretKey = new SecretKeySpec(key.substring(0, 32).getBytes(), ALGORITHM);

    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);

    byte[] ivArr = cipher.getIV();
    byte[] encArr = cipher.doFinal(plainText.getBytes());

    // Append IV to the encrypted text
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    outputStream.write(ivArr);
    outputStream.write(encArr);
    byte contentArr[] = outputStream.toByteArray();

    return Base64.getEncoder().withoutPadding().encodeToString(contentArr);
  }

  public String decrypt(String encryptText, String key) throws Exception {

    byte[] arrDecode = Base64.getDecoder().decode(encryptText);

    // Though it is Hex PHP is treating it as string and using 32 characters
    LOGGER.info("Key: " + key);
    SecretKeySpec secretKey = new SecretKeySpec(key.substring(0, 32).getBytes(), "AES");

    // Extract IV and encrypted text
    byte[] arrIV = Arrays.copyOfRange(arrDecode, 0, 16);
    byte[] arrEnc = Arrays.copyOfRange(arrDecode, 16, arrDecode.length);

    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(arrIV));

    return new String(cipher.doFinal(arrEnc));
  }

}
