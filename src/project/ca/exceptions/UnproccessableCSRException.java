package project.ca.exceptions;

public class UnproccessableCSRException extends Exception{
    static String message="Your CSR is rejected";
    public UnproccessableCSRException() {
        super(message);
    }
}
