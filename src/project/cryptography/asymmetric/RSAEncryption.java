package project.cryptography.asymmetric;

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import static project.utils.Constants.*;

public class RSAEncryption {

    /**
     * Initialize public and private keys from the files
     * And if files do not exist this method will generate a new pair of the public and private key
     **/
    public static void init() {
        try {
            readKeyFromFile(SERVER_PUBLIC_KEY_FILE);
            readKeyFromFile(SERVER_PRIVATE_KEY_FILE);
        } catch (IOException ioException) {
            System.out.println("Cannot read from the file" + ioException.getMessage());
            System.out.println("Generating a new instance...");
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
                keyPairGenerator.initialize(RSA_KEY_SIZE);

                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                Key publicKey = keyPair.getPublic();
                Key privateKey = keyPair.getPrivate();

                KeyFactory keyFactory = KeyFactory.getInstance(RSA);
                RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
                RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);

                saveKeyToFile(SERVER_PUBLIC_KEY_FILE, publicKeySpec.getModulus(), publicKeySpec.getPublicExponent());
                saveKeyToFile(SERVER_PRIVATE_KEY_FILE, privateKeySpec.getModulus(), privateKeySpec.getPrivateExponent());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Save the key (public or private) to the file after generating it
     **/
    private static void saveKeyToFile(String fileName, BigInteger modulus, BigInteger exponent) throws IOException {
        try (ObjectOutputStream ObjOutputStream = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)))) {
            ObjOutputStream.writeObject(modulus);
            ObjOutputStream.writeObject(exponent);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * Read the key (public or private) from the file
     **/
    private static Key readKeyFromFile(String keyFileName) throws IOException {
        Key key = null;
        InputStream inputStream = new FileInputStream(keyFileName);
        try (ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(inputStream))) {
            BigInteger modulus = (BigInteger) objectInputStream.readObject();
            BigInteger exponent = (BigInteger) objectInputStream.readObject();
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            if (keyFileName.startsWith("public"))
                key = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
            else key = keyFactory.generatePrivate(new RSAPrivateKeySpec(modulus, exponent));

        } catch (Exception e) {
            e.printStackTrace();
        }
        return key;
    }

    /**
     * This function takes plaintext and the publicKey, and return the CipherText.
     **/
    public static String encrypt(String plainText, Key publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);

            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] cipherText = cipher.doFinal(plainText.getBytes());

            return Base64.getEncoder().encodeToString(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
            return RSA_ENCRYPTION_ERROR_MESSAGE;
        }
    }


    /**
     * This function takes CipherText, and return the plainText.
     **/
    public static String decrypt(String cipherText, Key privateKey) {
        try {

            byte[] cipherTextArray = Base64.getDecoder().decode(cipherText);

            Cipher cipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);

            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);

            return new String(decryptedTextArray);
        } catch (Exception e) {
            e.printStackTrace();
            return RSA_DECRYPTION_ERROR_MESSAGE;
        }
    }

    public static Key getPublicKey() {
        try {
            return readKeyFromFile(SERVER_PUBLIC_KEY_FILE);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }


    public static Key getPrivateKey() {
        try {
            return readKeyFromFile(SERVER_PRIVATE_KEY_FILE);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}