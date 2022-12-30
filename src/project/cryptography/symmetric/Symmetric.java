package project.cryptography.symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

import static project.utils.Constants.*;

public class Symmetric {
    /**
     * Function to generate a secret key
     * In the second stage, we will use this function inside the signup function
     * When the key is generated, it will be stored in the database for the user who is signed up
     **/
    public static SecretKey generateAESKey() {
        SecureRandom securerandom = new SecureRandom();

        KeyGenerator keygenerator = null;

        try {
            keygenerator = KeyGenerator.getInstance(AES);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.out.println(GENERATING_KEY_ERROR_MESSAGE);
        }

        assert keygenerator != null;
        keygenerator.init(AES_KEY_SIZE, securerandom);

        return keygenerator.generateKey();
    }

    /**
     * Function to initialize a vector (iv) with an arbitrary value
     **/
    public static byte[] generateIV() {
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return Base64.getEncoder().encode(initializationVector);
    }

    /**
     * This function takes ciphertext, with the key to generate a MAC
     **/
    public static String generateMac(String cipherText, String secretKey) {
        Mac mac = null;
        try {
            mac = Mac.getInstance(MAC_ALGORITHM);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(INCORRECT_MAC_ALGORITHM);
        }

        byte[] decodedKey = Base64.getDecoder().decode(secretKey);
        SecretKeySpec originalKey = new SecretKeySpec(decodedKey, AES);

        assert mac != null;
        try {
            mac.init(originalKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            System.out.println(INVALID_SECRET_KEY);
        }

        return Base64.getEncoder().encodeToString(mac.doFinal(Base64.getDecoder().decode(cipherText)));
    }

    /**
     * This function takes ciphertext, the key with the mac and verify it
     **/
    public static boolean verifyMAC(String cipherText, String secretKey, String mac) {
        String refMac = generateMac(cipherText, secretKey);
        return MessageDigest.isEqual(Base64.getDecoder().decode(refMac), Base64.getDecoder().decode(mac));
    }

    /**
     * This function takes plaintext, the key with an initialization vector to convert the plainText into a CipherText.
     **/
    public static String encrypt(String plainText, String secretKey, byte[] iv) {

        byte[] decodedKey = Base64.getDecoder().decode(secretKey);
        SecretKeySpec originalKey = new SecretKeySpec(decodedKey, AES);

        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

        try {
            Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);

            cipher.init(Cipher.ENCRYPT_MODE, originalKey, spec);

            byte[] cipherText = cipher.doFinal(plainText.getBytes());

            return Base64.getEncoder().encodeToString(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
            return ENCRYPTION_ERROR_MESSAGE;
        }
    }

    /**
     * This function performs the reverse operation of the [encrypt] function.
     * It converts ciphertext to the plaintext using the key
     **/
    public static String decrypt(String cipherText, String secretKey, String iv, String mac) {
        if (verifyMAC(cipherText, secretKey, mac)) {
            try {
                byte[] initializationVector = Base64.getDecoder().decode(iv);

                byte[] decodedKey = Base64.getDecoder().decode(secretKey);
                SecretKeySpec originalKey = new SecretKeySpec(decodedKey, AES);

                GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, initializationVector);

                Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);

                cipher.init(Cipher.DECRYPT_MODE, originalKey, spec);

                byte[] result = cipher.doFinal(Base64.getDecoder().decode(cipherText));

                return new String(result);
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println(DECRYPTION_ERROR_MESSAGE);
                return DECRYPTION_ERROR_MESSAGE;
            }
        } else {
            System.out.println(AUTHENTICATION_ERROR_MESSAGE);
            return AUTHENTICATION_ERROR_MESSAGE;
        }
    }

    /**
     * This function takes the plain text (after verifying the mac) and makes sure to not equal any of our consistent error
     *  return true of not equal
     **/
    public static boolean verifyPlainText(String plainText) {
        return !(Objects.equals(plainText, AUTHENTICATION_ERROR_MESSAGE) || Objects.equals(plainText, DATABASE_KEY_ERROR) || Objects.equals(plainText, DECRYPTION_ERROR_MESSAGE));
    }
}
