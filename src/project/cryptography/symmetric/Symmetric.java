package project.cryptography.symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class Symmetric {
    private static final String AES = "AES";

    private static final String AES_CIPHER_ALGORITHM = "AES/GCM/NoPadding";

    private static final int GCM_TAG_LENGTH = 16;

    /**
     * Function to generate a secret key
     * In the second stage, we will use this function inside the signup function
     * When the key is generated, it will be stored in the database for the user who is signed up
     **/
    public static SecretKey generateAESKey() throws Exception {
        SecureRandom securerandom = new SecureRandom();

        KeyGenerator keygenerator = KeyGenerator.getInstance(AES);

        keygenerator.init(256, securerandom);

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
     * This function takes plaintext, the key with an initialization vector to convert the plainText into a CipherText.
     **/
    public static String encrypt(String plainText, String secretKey, byte[] iv) throws Exception {
        // 1) Convert key type from String to SecretKey
        byte[] decodedKey = Base64.getDecoder().decode(secretKey);
        SecretKeySpec originalKey = new SecretKeySpec(decodedKey, AES);

        // 2) Create GCMParameterSpec
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

        // 3) Get an instance from Cipher and pass algorithm to it
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);

        // 4) Init the cipher instance and set its mode to encryption mode
        cipher.init(Cipher.ENCRYPT_MODE, originalKey, spec);

        // 5) Do encryption
        byte[] cipherText = cipher.doFinal(plainText.getBytes());

        /* ****************** */
        System.out.println("Symmetric (Encrypt): Original Message Is: " + plainText);
        System.out.println("Symmetric (Encrypt): Encrypted Message Is: " + Base64.getEncoder().encodeToString(cipherText));
        /* ****************** */

        // 6) Return the encrypted text
        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     * This function performs the reverse operation of the [encrypt] function.
     * It converts ciphertext to the plaintext using the key
     **/
    public static String decrypt(String cipherText, String secretKey, String iv) throws Exception {
        // 1) convert iv type from String to list of bytes because we can pass only strings in sockets
        byte[] initializationVector = Base64.getDecoder().decode(iv);

        // 2) Convert key type from String to SecretKey
        byte[] decodedKey = Base64.getDecoder().decode(secretKey);
        SecretKeySpec originalKey = new SecretKeySpec(decodedKey, AES);

        // 3) Create GCMParameterSpec
        GCMParameterSpec spec = new GCMParameterSpec(128, initializationVector);

        // 4) Get an instance from Cipher and pass algorithm to it
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);

        // 5) Init the cipher instance and set its mode to decryption mode
        cipher.init(Cipher.DECRYPT_MODE, originalKey, spec);

        // 6) Try to decrypt the cipher text and if data is corrupted will throw an exception
        try {
            byte[] result = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            System.out.println("Symmetric (Decrypt): Encrypted Message Is: " + cipherText);
            System.out.println("Symmetric (Decrypt): Original Message Is: " + new String(result));
            // 6.1) Everything is Ok and data integrity test is passed
            return new String(result);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            System.out.println("Symmetric (Decrypt): Data is corrupted it could be the encrypted message or the iv");
            // 6.2) Data integrity test is failed
            return null;
        }

    }
}
