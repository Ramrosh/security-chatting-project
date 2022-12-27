package project.cryptography.symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class Symmetric {
    private static final String AES = "AES";

    private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5PADDING";

    /**
     * Function to generate a secret key
     * In the second stage, we will use this function inside the signup function
     * When the key is generated, it will be stored in the database for the user who is signed up
     **/
    public static SecretKey generateAESKey() throws Exception {
        SecureRandom securerandom = new SecureRandom();

        KeyGenerator keygenerator = KeyGenerator.getInstance(AES);

        keygenerator.init(256, securerandom);

        SecretKey key = keygenerator.generateKey();

        return key;
    }

    /**
     * Function to initialize a vector (iv) with an arbitrary value
     **/
    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * This function takes plaintext, the key with an initialization vector to convert the plainText into a CipherText.
     **/
    public static String encrypt(String plainText, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        byte[] cipherText = cipher.doFinal(plainText.getBytes());

        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     * This function performs the reverse operation of the [encrypt] function.
     * It converts ciphertext to the plaintext using the key
     **/
    public static String decrypt(String cipherText, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        byte[] result = cipher.doFinal(Base64.getDecoder().decode(cipherText));

        return new String(result);
    }

//    // Driver code
//    public static void main(String args[]) throws Exception {
//        SecretKey Symmetrickey = createAESKey();
//
//        System.out.println("The Symmetric Key is :" + DatatypeConverter.printHexBinary(Symmetrickey.getEncoded()));
//
//        byte[] initializationVector = createInitializationVector();
//
//        String plainText = "This is the message " + "I want To Encrypt.";
//
//        // Encrypting the message
//        // using the symmetric key
//        byte[] cipherText = encrypt(plainText, Symmetrickey, initializationVector);
//
//        System.out.println("The ciphertext or " + "Encrypted Message is: " + DatatypeConverter.printHexBinary(cipherText));
//
//        // Decrypting the encrypted
//        // message
//        String decryptedText = decrypt(cipherText, Symmetrickey, initializationVector);
//
//        System.out.println("Your original message is: " + decryptedText);
//    }
}
