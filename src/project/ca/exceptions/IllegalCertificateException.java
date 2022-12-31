package project.ca.exceptions;

public class IllegalCertificateException extends Exception{
    static String message="The certificate is invalid";

    public IllegalCertificateException() {
        super(message);
    }
}
