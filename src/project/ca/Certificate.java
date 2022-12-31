package project.ca;

import project.cryptography.asymmetric.DigitalSignature;
import project.cryptography.asymmetric.RSAEncryption;

import java.io.*;
import java.security.*;
import java.time.LocalDate;
import java.util.Base64;

import static project.utils.Constants.*;

public class Certificate implements Serializable {
   public String subject;
   public PublicKey subjectPublicKey;
   public String caSignature;
   public LocalDate issueDate;
   public LocalDate expiryDate;
   //we need this for the certificate signature
   private static final PublicKey CAPublicKey = (PublicKey) RSAEncryption.getPublicKey(CA_PUBLIC_KEY_FILE);

    public Certificate(String subject, PublicKey subjectPublicKey) {
        this.subject = subject;
        this.subjectPublicKey = subjectPublicKey;
        this.issueDate=LocalDate.now();
        this.expiryDate=issueDate.plusYears(1);
    }

    public void setCaSignature(String caSignature) {
        this.caSignature = caSignature;
    }

    /** this method returns the text representation of the certificate's body which wil be signed.
     ** the text representation should be compatible with signature input string encoding which is base64.
     **/
    public String getBase64EncodedCertificateBody(){
        String str= this.subject.toString() + ':'
                + Base64.getEncoder().encodeToString(subjectPublicKey.getEncoded())+':'
                + this.issueDate.toString()+':'
                +this.expiryDate.toString();
        return Base64.getEncoder().encodeToString(str.getBytes());
    }

    public static void initCertificate(String certificatePath) throws IOException {
        try {
            retrieveFromFile(certificatePath);
        } catch (IOException ioException) {
           throw ioException;
        }
    }

    public void storeToFile(String certificateFileName){
        try (ObjectOutputStream ObjOutputStream = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(CERTIFICATE_FOLDER_PATH + certificateFileName)))) {
            ObjOutputStream.writeObject(this);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Certificate retrieveFromFile(String certificatePath) throws IOException{
        Certificate certificate = null;
        InputStream inputStream = new FileInputStream(CERTIFICATE_FOLDER_PATH + certificatePath);
        try (ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(inputStream))) {
           certificate= (Certificate) objectInputStream.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return certificate;
    }

    public Boolean VerifyCertificate(Certificate certificate,String subject){
        //check signature
        boolean signatureIsValid= DigitalSignature.verifyDigitalSignature(certificate.getBase64EncodedCertificateBody(),certificate.caSignature,CAPublicKey);
        //check subject
        boolean subjectsAreIdentical=subject.equals(certificate.subject);
        //check expiry date
        boolean hasNotExpired=certificate.expiryDate.isAfter(LocalDate.now());
        return signatureIsValid && subjectsAreIdentical && hasNotExpired;
    }
}
