package project;

import project.ca.CSR;
import project.ca.Certificate;
import project.ca.exceptions.IllegalCertificateException;
import project.ca.exceptions.UnproccessableCSRException;
import project.cryptography.asymmetric.DigitalSignature;
import project.cryptography.asymmetric.RSAEncryption;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static project.utils.Constants.*;


public class ChatServerMultiThreading {
    private static final int port = 11111;
    private static final PublicKey CAPublicKey = (PublicKey) RSAEncryption.getPublicKey(CA_PUBLIC_KEY_FILE);

    public static void main(String[] args) throws Exception {
        try (ServerSocket listener = new ServerSocket(port)) {
            RSAEncryption.init(SERVER_PUBLIC_KEY_FILE, SERVER_PRIVATE_KEY_FILE);
            System.out.println("The chat server is running...");
            ExecutorService pool = Executors.newFixedThreadPool(20);
            pool.execute(new CertificateNCSRHandler() );
            while (true) {
                pool.execute(new ChatServer(listener.accept()));
            }
        }
    }

    private static class CertificateNCSRHandler implements Runnable {
        @Override
        public void run() {
            try {
                Certificate.initCertificate(SERVER_CERTIFICATE_FILE);
            } catch (IOException ioException) {
                System.out.println("Cannot reach file " + ioException.getMessage());
                System.out.println("making a new CSR");
                try {
                    //initializing ca server connection
                    InetAddress ip = InetAddress.getLocalHost();
                    Socket socket = new Socket(ip, 22222);
                    //initializing input&output streams
                    //Scanner inputFromSocket = new Scanner(socket.getInputStream());
                    //PrintWriter outputToSocket = new PrintWriter(socket.getOutputStream(), true);
                    ObjectOutputStream objectOutputToSocket = new ObjectOutputStream(socket.getOutputStream());
                    ObjectInputStream objectInputFromSocket = new ObjectInputStream(socket.getInputStream());
                    //send request of
                    //outputToSocket.println(SERVER_CSR_MESSAGE);
                    objectOutputToSocket.writeObject(SERVER_CSR_MESSAGE);
                    //making CSR object
                    String subject = String.valueOf(port);
                    PublicKey serverPublicKey = (PublicKey) RSAEncryption.getPublicKey(SERVER_PUBLIC_KEY_FILE);
                    PrivateKey serverPrivateKey=(PrivateKey)RSAEncryption.getPrivateKey(SERVER_PRIVATE_KEY_FILE);
                    CSR serverCSR = new CSR(subject, serverPublicKey);
                    //sign the public key provided in CSR by the same pair's private key
                    serverCSR.signCSRPublicKey(serverPrivateKey);
                    //send CSR object through socket
                    objectOutputToSocket.writeObject(serverCSR);
                    //receive CA response
                   // String response = inputFromSocket.nextLine();
                    String response = (String) objectInputFromSocket.readObject();
                    if (response.equals("approved")) {
                        Certificate certificate = (Certificate) objectInputFromSocket.readObject();
                        //check signature of certificate
                        if (DigitalSignature.verifyDigitalSignature(certificate.getBase64EncodedCertificateBody(), certificate.caSignature, CAPublicKey)) {
                            certificate.storeToFile(SERVER_CERTIFICATE_FILE);
                            System.out.println("certificate is created");
                        } else {
                            throw new IllegalCertificateException();
                        }
                    } else {
                        throw new UnproccessableCSRException();
                    }
                } catch (Exception e) {
                    System.err.println(e.getMessage());
                }

            }
        }
    }
}



