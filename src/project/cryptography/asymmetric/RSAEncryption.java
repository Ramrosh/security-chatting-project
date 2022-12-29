package project.cryptography.asymmetric;

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public class RSAEncryption {
    static private Key publicKey;

    static private Key privateKey;

    static private final int KeySize = 4096;

    static private final String RSA = "RSA";

    static private final String PublicKeyFile = "public.key";

    static private final String PrivateKeyFile = "private.key";

    static private final String RSA_CIPHER_ALGORITHM = "RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING";

    /**
     * Initialize public and private keys from the files
     * And if files do not exist this method will generate a new pair of the public and private key
     **/
    public static void init() {
        try {
            publicKey = readKeyFromFile(PublicKeyFile);
            privateKey = readKeyFromFile(PrivateKeyFile);
        } catch (IOException ioException) {
            System.out.println("Cannot read from the file" + ioException.getMessage());
            System.out.println("Generating a new instance...");
            try {
                // Get an instance of the RSA key generator
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
                keyPairGenerator.initialize(KeySize);
                // Generate the KeyPair
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                // Get the public and private key
                publicKey = keyPair.getPublic();
                privateKey = keyPair.getPrivate();
                // Get the RSAPublicKeySpec and RSAPrivateKeySpec
                KeyFactory keyFactory = KeyFactory.getInstance(RSA);
                RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
                RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
                // Saving the Key to the file
                saveKeyToFile(PublicKeyFile, publicKeySpec.getModulus(), publicKeySpec.getPublicExponent());
                saveKeyToFile(PrivateKeyFile, privateKeySpec.getModulus(), privateKeySpec.getPrivateExponent());
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
     * This function takes plaintext, and return the CipherText.
     * Important! do not use this function before initialize the RSA
     **/
    public static String encrypt(String plainText) throws Exception {
        Key publicKey = readKeyFromFile(PublicKeyFile);
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);
        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        // Perform Encryption
        byte[] cipherText = cipher.doFinal(plainText.getBytes());

        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     * This function takes plaintext and the publicKey, and return the CipherText.
     **/
    public static String encrypt(String plainText, Key publicKey) throws Exception {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);
        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        // Perform Encryption
        byte[] cipherText = cipher.doFinal(plainText.getBytes());

        return Base64.getEncoder().encodeToString(cipherText);
    }


    /**
     * This function takes CipherText, and return the plainText.
     * Important! do not use this function before initialize the RSA
     **/
    public static String decrypt(String cipherText) throws Exception {
        Key privateKey = readKeyFromFile(PrivateKeyFile);

        byte[] cipherTextArray = Base64.getDecoder().decode(cipherText);

        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance(RSA_CIPHER_ALGORITHM);

        // Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // Perform Decryption
        byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);

        return new String(decryptedTextArray);
    }

    public static Key getPublicKey() {
        try {
            return readKeyFromFile(PublicKeyFile);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
