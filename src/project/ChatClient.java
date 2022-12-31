package project;

import project.cryptography.asymmetric.DigitalSignature;
import project.cryptography.asymmetric.RSAEncryption;
import project.cryptography.symmetric.AESEncryption;

import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import static project.utils.ConsolePrintingColors.*;
import static project.utils.Constants.*;

public class ChatClient {

    private String sessionKey;

    //attributes
    boolean isLoggedIn;

    private static String myPhoneNumber;
    //input&output streams
    private Scanner inputFromSocket;
    private PrintWriter outputToSocket;
    private Scanner inputFromTerminal;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private PublicKey serverPublicKey;

    //constructors
    public ChatClient() {
        this.isLoggedIn = false;
        this.myPhoneNumber = "";
    }

    public int getPortNum() {
        int mod = Integer.parseInt(myPhoneNumber) % 10000;
        int base = Integer.parseInt(myPhoneNumber) / 10000 - 90000;
        int newPort = base + mod;
        return Math.abs(newPort);
    }

    //methods
    public void run()//run client to send requests to server
    {
        try {
            InetAddress ip = InetAddress.getLocalHost();
            Socket socket = new Socket(ip, 11111);
            System.out.println("my port : " + socket.getLocalPort());
            this.inputFromTerminal = new Scanner(System.in);
            this.inputFromSocket = new Scanner(socket.getInputStream());//input from server
            this.outputToSocket = new PrintWriter(socket.getOutputStream(), true);//output to server
            ClientGetMessages clientGetMessages = new ClientGetMessages();
            handleHandshake();
            clientRequests:
            do {
                if (!this.isLoggedIn)//case the client is not logged in
                {
                    System.out.println("Enter 1 for sign up , 2 for login,3 for exit ");
                    String userChoice = inputFromTerminal.nextLine();
                    switch (userChoice) {
                        case "1"://sign up
                        {
                            this.requestSignup();
                            clientGetMessages = new ClientGetMessages();
                            clientGetMessages.start();
                            break;
                        }
                        case "2"://log in
                        {
                            this.requestLogin();
                            clientGetMessages = new ClientGetMessages();
                            clientGetMessages.start();
                            break;
                        }
                        case "3"://exit
                        {
                            this.requestExiting();
                            clientGetMessages.stopGetMessages();
                            socket.close();
                            System.out.println(ANSI_PURPLE + "exiting ...see ya :)" + ANSI_RESET);
                            break clientRequests;
                        }
                        default:
                            break;
                    }
                } else //case the client is logged in
                {
                    System.out.println("Enter 1 for sending a message , 2 for reviewing your messages,3 logout ,4 for exit ");
                    String userChoice = inputFromTerminal.nextLine();
                    switch (userChoice) {
                        case "1"://send a message
                        {
                            this.requestSendingNewMessage();
                            break;
                        }
                        case "2"://review old messages
                        {
                            this.requestPreviewingOldMessages();
                            break;
                        }
                        case "3"://logout
                        {
                            this.resetClientState();
                            clientGetMessages.stopGetMessages();
                            System.out.println("logged out :)");
                            break;
                        }
                        case "4"://exit
                        {
                            this.requestExiting();
                            clientGetMessages.stopGetMessages();
                            socket.close();
                            System.out.println(ANSI_PURPLE + "exiting ...see ya :)" + ANSI_RESET);
                            break clientRequests;
                        }
                        default:
                            break;
                    }
                }
            } while (true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //handling requests
    private void requestLogin() {
        //send to  server that it is login request
        outputToSocket.println("login");
        //input signup parameters
        System.out.println("Enter phone number");
        String phoneNumber = inputFromTerminal.nextLine();
        System.out.println("Enter password");
        String password = inputFromTerminal.nextLine();
        //send to  server signup parameters
        outputToSocket.println(phoneNumber);
        outputToSocket.println(password);
        //get response from server
        String response = inputFromSocket.nextLine();
        System.out.println("response from server ( " + response + " )");
        //change login status if it's a success
        if (!response.contains("error")) {
            this.isLoggedIn = true;
            this.myPhoneNumber = phoneNumber;
            initializeKeys();
            System.out.println(ANSI_GREEN + "I am logged in now :) " + ANSI_RESET);
        }
    }

    private void requestSignup() {
        //send to  server that it is signup request
        outputToSocket.println("signup");
        //input signup parameters
        System.out.println("Enter phone number");
        String phoneNumber = inputFromTerminal.nextLine();
        System.out.println("Enter password");
        String password = inputFromTerminal.nextLine();
        //send to  server signup parameters
        outputToSocket.println(phoneNumber);
        outputToSocket.println(password);
        //get response from server
        String response = inputFromSocket.nextLine();
        System.out.println("response from server ( " + response + " )");
        //change login status if it's a success
        if (!response.contains("error")) {
            this.isLoggedIn = true;
            this.myPhoneNumber = phoneNumber;
            initializeKeys();
            System.out.println(ANSI_GREEN + "I am logged in now :) " + ANSI_RESET);
        }
    }

    private void requestSendingNewMessage() throws Exception {
        //send to  server that it is sending message request
        outputToSocket.println("sendMessage");
        outputToSocket.println(myPhoneNumber);
        System.out.println("sending message from " + myPhoneNumber);
        System.out.println("Enter 1 to add a new contact , 2 to choose from saved contact");
        String sendingChoice = inputFromTerminal.nextLine();
        String receiverNumber = "";
        boolean hasError = false;
        switch (sendingChoice) {
            case "1": // add a new contact
            {
                outputToSocket.println("newContact");
                System.out.println("enter the number:");
                receiverNumber = inputFromTerminal.nextLine();
                outputToSocket.println(receiverNumber);
                // check if the number existed ...get response from server
                String response = decryptFromServer();
                if (response.contains("error")) {
                    hasError = true;
                }
                System.out.println("response from server ( " + response + " )");
                break;
            }
            case "2": //choose from saved contact
            {
                outputToSocket.println("oldContact");
                // get numbers from the server
                String message = decryptFromServer();
                if (AESEncryption.verifyPlainText(message)) {
                    int contactNumber = Integer.parseInt(message);
                    System.out.println("contactNumber " + contactNumber);
                    ArrayList<String> MyContacts = new ArrayList<>();
                    for (int i = 1; i <= contactNumber; i++) {
                        MyContacts.add(decryptFromServer());
                    }
                    if (MyContacts.get(0).contains("error")) {
                        hasError = true;
                        System.out.println("response from server ( " + MyContacts.get(0) + " )");
                    } else {
                        System.out.println("choose the id of the number you want to send a message to:");
                        for (int i = 1; i <= contactNumber; i++) {
                            System.out.println("(" + i + "): " + MyContacts.get(i - 1));
                        }
                        int id = Integer.parseInt(inputFromTerminal.nextLine());
                        receiverNumber = MyContacts.get(id - 1);
                        outputToSocket.println(receiverNumber);
                    }
                    break;
                }
            }
            default:
                break;
        }
        if (!hasError) {
            String TERMINATOR_STRING = "#send";
            System.out.println("enter the message: (press " + TERMINATOR_STRING + " to send)");
            StringBuilder message = new StringBuilder();;
            String str;
            while (!(str = inputFromTerminal.nextLine()).equals(TERMINATOR_STRING)) {
                message.append(str);
            }
            encryptToServer(message.toString());
            System.out.println("sending...");
            //get response from server
            System.out.println("Response from server ( " + decryptFromServer() + " )");
        }
    }

    private void requestPreviewingOldMessages() {
        System.out.println("reviewing messages");
        outputToSocket.println("showMessages");
        outputToSocket.println(myPhoneNumber);
        String message = decryptFromServer();
        if (AESEncryption.verifyPlainText(message)) {
            int messagesNumber = Integer.parseInt(message);
            for (int i = 0; i < messagesNumber; i++) {
                System.out.println(decryptFromServer());
            }
        }
    }

    private void requestExiting() {
        this.resetClientState();
        outputToSocket.close();
        inputFromSocket.close();
    }
    //util methods

    private class ClientGetMessages extends Thread {
        static ServerSocket getMessagesServerSocket;

        public void stopGetMessages() {
            try {
                isLoggedIn = false;
                getMessagesServerSocket.close();
                this.interrupt();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        @Override
        public void run() {
            try {
                getMessagesServerSocket = new ServerSocket(getPortNum());
                while (isLoggedIn) {
                    Socket getMessagesSocket = getMessagesServerSocket.accept();
                    Scanner inputFromOtherSocket = new Scanner(getMessagesSocket.getInputStream());
                    if (inputFromOtherSocket.hasNextLine()) {
                        System.out.println(decryptFromServer(inputFromOtherSocket));
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void resetClientState() {
        outputToSocket.println(myPhoneNumber);
        this.isLoggedIn = false;
        myPhoneNumber = "";
    }

    private void encryptToServer(String message) {
        byte[] iv = AESEncryption.generateIV();
        String encryptedMessage = AESEncryption.encrypt(message, sessionKey, iv);
        if (encryptedMessage != null) {
            outputToSocket.println(encryptedMessage);
            outputToSocket.println(Base64.getEncoder().encodeToString(iv));
            outputToSocket.println(AESEncryption.generateMac(encryptedMessage, sessionKey));
            outputToSocket.println(DigitalSignature.createDigitalSignature(encryptedMessage, privateKey));
        }
    }

    private String decryptFromServer() {
        String messageReceived = inputFromSocket.nextLine();
        String iv = inputFromSocket.nextLine();
        String mac = inputFromSocket.nextLine();
        String signature = inputFromSocket.nextLine();
        if (DigitalSignature.verifyDigitalSignature(messageReceived, signature, serverPublicKey)) {
            return AESEncryption.decrypt(messageReceived, sessionKey, iv, mac);
        } else {
            return VERIFY_DIGITAL_SIGNATURE_ERROR_MESSAGE;
        }
    }

    private String decryptFromServer(Scanner inputFromOtherSocket) {
        String messageReceived = inputFromOtherSocket.nextLine();
        String iv = inputFromOtherSocket.nextLine();
        String mac = inputFromOtherSocket.nextLine();
        String signature = inputFromOtherSocket.nextLine();
        if (DigitalSignature.verifyDigitalSignature(messageReceived, signature, serverPublicKey)) {
            return AESEncryption.decrypt(messageReceived, sessionKey, iv, mac);
        } else {
            return VERIFY_DIGITAL_SIGNATURE_ERROR_MESSAGE;
        }
    }

    private void handleHandshake() throws SecurityException {
        try {
            outputToSocket.println(REQUEST_PUBLIC_KEY_MESSAGE);

            serverPublicKey = KeyFactory.getInstance(RSA).generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(inputFromSocket.nextLine())));

            sessionKey = Base64.getEncoder().encodeToString(AESEncryption.generateAESKey().getEncoded());

            outputToSocket.println(RSAEncryption.encrypt(sessionKey, serverPublicKey));

            System.out.println(decryptFromServer());
        } catch (Exception e) {
            throw new SecurityException(HANDSHAKE_ERROR_MESSAGE);
        }
    }

    private void initializeKeys() {
        RSAEncryption.init(USER_PUBLIC_KEY_PATH(myPhoneNumber), USER_PRIVATE_KEY_PATH(myPhoneNumber));
        publicKey = (PublicKey) RSAEncryption.getPublicKey(USER_PUBLIC_KEY_PATH(myPhoneNumber));
        privateKey = (PrivateKey) RSAEncryption.getPublicKey(USER_PRIVATE_KEY_PATH(myPhoneNumber));
        encryptToServer(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
    }

    public static void main(String[] args) {
        ChatClient client = new ChatClient();
        client.run();
    }
}
