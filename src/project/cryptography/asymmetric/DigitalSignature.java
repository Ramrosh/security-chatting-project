package project.cryptography.asymmetric;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import static project.utils.Constants.*;

public class DigitalSignature {

    /**
     * Function to implement Digital signature using SHA256 [SIGNING_ALGORITHM] and RSA algorithm by passing private key.
     **/
    public static String createDigitalSignature(String input, PrivateKey Key) {
        try {
            Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
            signature.initSign(Key);
            signature.update(Base64.getDecoder().decode(input));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            return CREATE_DIGITAL_SIGNATURE_ERROR_MESSAGE;
        }
    }

    /**
     * Function for Verification of the digital signature by using the public key
     **/
    public static boolean verifyDigitalSignature(String input, String signatureToVerify, PublicKey key) {
        try {
            Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
            signature.initVerify(key);
            signature.update(Base64.getDecoder().decode(input));
            return signature.verify(Base64.getDecoder().decode(signatureToVerify));
        } catch (Exception e) {
            return false;
        }

    }
}
