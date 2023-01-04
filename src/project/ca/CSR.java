package project.ca;

import project.cryptography.asymmetric.DigitalSignature;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class CSR implements Serializable {
    String subject;
    PublicKey subjectPublicKey;
    String publicKeySignature;

    public CSR(String subject, PublicKey subjectPublicKey) {
        this.subject = subject;
        this.subjectPublicKey = subjectPublicKey;
    }
    public void signCSRPublicKey(PrivateKey privateKey){
        this.publicKeySignature= DigitalSignature.createDigitalSignature(Base64.getEncoder().encodeToString(subjectPublicKey.getEncoded()),privateKey);
    }
    public String getPublicKeySignatureInBase64Encoding(){
        return Base64.getEncoder().encodeToString(subjectPublicKey.getEncoded());
    }
}
