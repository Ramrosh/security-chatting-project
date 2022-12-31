package project.ca;

import java.io.Serializable;
import java.security.PublicKey;

public class CSR implements Serializable {
    String subject;
    PublicKey subjectPublicKey;

    public CSR(String subject, PublicKey subjectPublicKey) {
        this.subject = subject;
        this.subjectPublicKey = subjectPublicKey;
    }
}
