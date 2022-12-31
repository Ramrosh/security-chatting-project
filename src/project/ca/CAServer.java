package project.ca;

import project.cryptography.asymmetric.DigitalSignature;
import project.cryptography.asymmetric.RSAEncryption;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static project.utils.Constants.*;

public class CAServer {

    public static void main(String[] args) throws Exception {
        try (ServerSocket listener = new ServerSocket(22222)) {
            RSAEncryption.init(CA_PUBLIC_KEY_FILE, CA_PRIVATE_KEY_FILE);
            System.out.println("CA server is running...");
            ExecutorService pool = Executors.newFixedThreadPool(10);
            while (true) {
                pool.execute(new CAServerThread(listener.accept()));
            }
        }
    }
    private static class CAServerThread implements Runnable {
        Socket socket;
        private Scanner inputFromSocket;
        private PrintWriter outputToSocket;
        private ObjectOutputStream objectOutputToSocket;
        private ObjectInputStream objectInputFromSocket;

        CAServerThread(Socket socket){
            this.socket=socket;
        }

        @Override
        public void run() {
            System.out.println("Connected: " + socket);
            try {
                this.inputFromSocket = new Scanner(socket.getInputStream());//input from client
                this.outputToSocket = new PrintWriter(socket.getOutputStream(), true);//output to client
                this.objectOutputToSocket = new ObjectOutputStream(socket.getOutputStream());
                this.objectInputFromSocket=new ObjectInputStream(socket.getInputStream());
                while (inputFromSocket.hasNextLine()) {
                    String clientRequestChoice = inputFromSocket.nextLine();
                    switch (clientRequestChoice) {
                        case SERVER_CSR_MESSAGE:{
                            System.out.println("got a server CSR");
                            this.handleServerCSR();
                            break;
                        }
                        case CLIENT_CSR_MESSAGE: {
                           this.handleClientCSR();
                            break;
                        }
                        default: {
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Error:" + socket);
            } finally {
                try {
                    inputFromSocket.close();
                    outputToSocket.close();
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                System.out.println("Closed: " + socket);
            }
        }

        private void handleServerCSR(){
            try {
                CSR receivedCSR=(CSR)objectInputFromSocket.readObject();
                //start verification
                if (verifyServerSubject(receivedCSR)) {
                    outputToSocket.println("approved");
                    //create the certificate and sign its body
                    Certificate serverCertificate=new Certificate(receivedCSR.subject,receivedCSR.subjectPublicKey);
                    String bodyToBeSigned=serverCertificate.getBase64EncodedCertificateBody();
                    String signature= DigitalSignature.createDigitalSignature(bodyToBeSigned,(PrivateKey) RSAEncryption.getPrivateKey(CA_PRIVATE_KEY_FILE));
                    serverCertificate.setCaSignature(signature);
                    objectOutputToSocket.writeObject(serverCertificate);
                } else {
                    outputToSocket.println("rejected");
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
        private boolean verifyServerSubject(CSR receivedCSR){
            try{
                System.out.println("verifying");
                InetAddress ip = InetAddress.getLocalHost();
                Socket socket = new Socket(ip, Integer.parseInt(receivedCSR.subject));
                Scanner inputFromSocket=new Scanner(socket.getInputStream());
                PrintWriter outputToSocket=new PrintWriter(socket.getOutputStream(),true);
                outputToSocket.println("ca");//added this because the client could be ChatClient too, which should be handled differently
                String randomVerificationCode=randomGeneratedStr(10);
                outputToSocket.println(randomVerificationCode);
                String receivedCode=inputFromSocket.nextLine();
                return receivedCode.equals(randomVerificationCode);

            }catch (Exception e){
                e.printStackTrace();
            }
           return false;
        }
        private  String randomGeneratedStr(int stringLength) {
            // a list of characters to choose from in form of a string
            String AlphaNumericStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvxyz0123456789";
            // creating a StringBuffer size of AlphaNumericStr
            StringBuilder s = new StringBuilder(stringLength);
            int i;
            for ( i=0; i<stringLength; i++) {
                //generating a random number using math.random()
                int ch = (int)(AlphaNumericStr.length() * Math.random());
                //adding Random character one by one at the end of s
                s.append(AlphaNumericStr.charAt(ch));
            }
            return s.toString();
        }

        private void handleClientCSR(){}
    }
}
