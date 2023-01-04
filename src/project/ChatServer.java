package project;


import project.ca.Certificate;
import project.cryptography.asymmetric.DigitalSignature;
import project.cryptography.asymmetric.RSAEncryption;
import project.cryptography.symmetric.AESEncryption;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import static project.utils.Constants.*;
import static project.utils.ConsolePrintingColors.ANSI_BLUE;
import static project.utils.ConsolePrintingColors.ANSI_RESET;

public class ChatServer implements Runnable {

    private Scanner inputFromSocket;
    private PrintWriter outputToSocket;

    private final Socket socket;
    private final Hasher hasher;
    private static final PublicKey CAPublicKey = (PublicKey) RSAEncryption.getPublicKey(CA_PUBLIC_KEY_FILE);
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private String sessionKey;
    private PublicKey userPublicKey;
    private Certificate certificate;

    private ObjectOutputStream objectOutputToSocket;


    ChatServer(Socket socket) {
        this.socket = socket;
        hasher = new Hasher();
        publicKey = (PublicKey) RSAEncryption.getPublicKey(SERVER_PUBLIC_KEY_FILE);
        privateKey = (PrivateKey) RSAEncryption.getPrivateKey(SERVER_PRIVATE_KEY_FILE);
        try {
            certificate=Certificate.retrieveFromFile(SERVER_CERTIFICATE_FILE);
        } catch (IOException e) {
            System.out.println("certificate is not created yet :)");
        }
        try {
            objectOutputToSocket = new ObjectOutputStream(socket.getOutputStream());
            objectOutputToSocket.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        assert publicKey != null : INIT_SERVER_PUBLIC_ERROR_MESSAGE;
        assert privateKey != null : INIT_SERVER_PRIVATE_ERROR_MESSAGE;
    }

    public int getPortNum(String receiverPhoneNumber) {
        int mod = Integer.parseInt(receiverPhoneNumber) % 10000;
        int base = Integer.parseInt(receiverPhoneNumber) / 10000 - 90000;
        int newPort = base + mod;
        return Math.abs(newPort);
    }

    @Override
    public void run() {
        System.out.println("Connected: " + socket);
        try {
            this.inputFromSocket = new Scanner(socket.getInputStream());//input from client
            this.outputToSocket = new PrintWriter(socket.getOutputStream(), true);//output to client
            String clientType=inputFromSocket.nextLine();//types are:ca,client.
            if(clientType.equals("ca"))
            {
                //handle the code verification request from CA
                 this.handleSubjectVerification();
                 return;
            }
            else
                handleHandshake();
            while (inputFromSocket.hasNextLine()) {
                String clientRequestChoice = inputFromSocket.nextLine();
                switch (clientRequestChoice) {
                    case "login": {
                        this.handleUserLogin();
                        break;
                    }
                    case "signup": {
                        this.handleUserSignup();
                        break;
                    }
                    case "sendMessage": {
                        this.handleUserMessageSending();
                        break;
                    }
                    case "showMessages": {
                        this.handleUserMessagesPreview();
                        break;
                    }
                    case "logout": {
                        String clientPhoneNumber = inputFromSocket.nextLine();
                        PortIdCollection.setOffline(clientPhoneNumber);
                        System.out.println("logging out");
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

    private void handleSubjectVerification(){
        String receivedCode=inputFromSocket.nextLine();
        System.out.println("enter the code : "+receivedCode);
        String inputCode=new Scanner(System.in).nextLine();
        System.out.println("you have input : "+inputCode);
        outputToSocket.println(inputCode);
    }
    //handling inputs and outputs of requests&responses methods
    private void handleUserLogin() {
        //get phone number and password from client
        String phoneNumber = inputFromSocket.nextLine();
        String password = inputFromSocket.nextLine();
        //get user's hashed password from db
        String hashedPassword = DBConnector.getUserHashedPassword(phoneNumber);
        boolean validPassword = false;
        if (!hashedPassword.contains("error"))//check if password retrieval passed
        {
            //check password validity
            validPassword = this.hasher.authenticate(password.toCharArray(), hashedPassword);
        }
        //output response to client
        String response = validPassword ? "logged in successfully" : "error in logging in";
        outputToSocket.println(response);
        //if valid add phoneNumber and port to socketIdPairs
        if (validPassword) {
            startUserSession(phoneNumber);
        }
    }


    private void handleUserSignup() throws Exception {
        //get phone number and password from client
        String phoneNumber = inputFromSocket.nextLine();
        String password = inputFromSocket.nextLine();
        String hashedPassword = this.hasher.hash(password.toCharArray());
        String secretKey = Base64.getEncoder().encodeToString(AESEncryption.generateAESKey().getEncoded());
        String successOrErrorMessage = DBConnector.signup(phoneNumber, hashedPassword, secretKey);
        //output response to client
        outputToSocket.println(successOrErrorMessage);
        //if valid add phoneNumber and port to socketIdPairs
        if (!successOrErrorMessage.contains("error")) {
            startUserSession(phoneNumber);
        }
    }

    private void handleUserMessageSending() {
        String clientPhoneNumber = inputFromSocket.nextLine();
        String contactChoice = inputFromSocket.nextLine();
        String receiverNumber = "";
        Certificate receiverCertificate = null;
        boolean hasError = false;
        switch (contactChoice) {
            case "newContact": {
                receiverNumber = inputFromSocket.nextLine();
                String successOrErrorMessage = DBConnector.addingContact(clientPhoneNumber, receiverNumber);
                if (successOrErrorMessage.contains("error")) {
                    hasError = true;
                }
                encryptToClient(successOrErrorMessage);
                break;
            }
            case "oldContact": {
                ArrayList<String> contacts = DBConnector.getContacts(clientPhoneNumber);
                if (contacts.get(0).contains("error")) {
                    hasError = true;
                }
                for (String s : contacts) {
                    System.out.println(s);
                }
                encryptToClient(String.valueOf(contacts.size()));
                for (String contact : contacts)
                    encryptToClient(contact);
                if (!hasError) receiverNumber = inputFromSocket.nextLine();
                break;
            }
            default:
                break;
        }
        if (!hasError)//if no error was received by db send the message
        {

            try {
                receiverCertificate = Certificate.retrieveFromFile(CLIENT_CERTIFICATE_PATH(receiverNumber));
                objectOutputToSocket.writeObject(receiverCertificate);
            } catch (IOException e) {
                System.out.println("certificate is not created yet :)");
            }

            StringBuilder signature = new StringBuilder();
            String str = decryptFromClient(signature);
            if (!AESEncryption.verifyPlainText(str)) {
                encryptToClient(str);
                return;
            }
            System.out.println("contactChoice " + contactChoice);
            System.out.println("clientPhoneNumber : " + clientPhoneNumber);
            System.out.println("receiverNumber : " + receiverNumber);
            System.out.println("message : " + str);
            System.out.println("signature is: " + signature.toString());
            // save the message into db
            String successOrErrorMessage = DBConnector.sendMessage(clientPhoneNumber, receiverNumber, str, signature.toString());
            //output response to client
            encryptToClient(successOrErrorMessage);
            // send the message for the other client
            try {
                if (PortIdCollection.online(receiverNumber)) { // TODO get receiver phone number form DB
                    System.out.println("other socket: host and port " + InetAddress.getLocalHost() + getPortNum(receiverNumber));
                    Socket otherSocket = new Socket(InetAddress.getLocalHost(), getPortNum(receiverNumber));
                    PrintWriter outputToOtherSocket = new PrintWriter(otherSocket.getOutputStream(), true);
                    String response = ANSI_BLUE + "new message arrived from : " + clientPhoneNumber + ", content: " + str + ANSI_RESET;
                    encryptToClient(response, receiverNumber, outputToOtherSocket);
                    outputToOtherSocket.close();
                    otherSocket.close();
                } else System.out.println("the other is not online");
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void handleUserMessagesPreview() {
        String clientPhoneNumber = inputFromSocket.nextLine();
        System.out.println("showing messages to " + clientPhoneNumber);
        // get the messages of the client
        ArrayList<HashMap> result = DBConnector.getMessages(clientPhoneNumber);
        System.out.println("messages result = " + result);
        encryptToClient(String.valueOf(result.size()));
        for (HashMap hashMap : result) {
            String message = "";
            if (clientPhoneNumber.equals(hashMap.get("sender_phone_number"))) {
                message = "From: Me, To: " + hashMap.get("receiver_phone_number") + ", msg: " + hashMap.get("content") + ", at:" + hashMap.get("sent_at");
            } else if (clientPhoneNumber.equals(hashMap.get("receiver_phone_number"))) {
                message = "From: " + hashMap.get("sender_phone_number") + ", To: ME" + ", msg: " + hashMap.get("content") + ", at:" + hashMap.get("sent_at");
            } else if (hashMap.containsKey("error")) {
                message = hashMap.get("error").toString();
            } else {
                message = "Saved Message:" + ", msg: " + hashMap.get("content") + ", at:" + hashMap.get("sent_at");
            }
            encryptToClient(message);
        }
    }

    // TODO: get user secret key from DataBase
    private void encryptToClient(String message, String receiverPhoneNumber, PrintWriter outputToOtherSocket) {
        String userSecretKey = DBConnector.getUserSecretKey(receiverPhoneNumber);
        if (!userSecretKey.contains("error")) {
            byte[] iv = AESEncryption.generateIV();
            String encryptedMessage = AESEncryption.encrypt(message, userSecretKey, iv);
            String mac = AESEncryption.generateMac(encryptedMessage, userSecretKey);
            if (!Objects.equals(encryptedMessage, AES_ENCRYPTION_ERROR_MESSAGE)) {
                outputToOtherSocket.println(encryptedMessage);
                outputToOtherSocket.println(Base64.getEncoder().encodeToString(iv));
                outputToOtherSocket.println(mac);
                outputToOtherSocket.println(DigitalSignature.createDigitalSignature(encryptedMessage, privateKey));
            }
            return;
        }
        System.out.println(DATABASE_KEY_ERROR);
    }

    private void encryptToClient(String message) {
        byte[] iv = AESEncryption.generateIV();
        String encryptedMessage = AESEncryption.encrypt(message, sessionKey, iv);
        String mac = AESEncryption.generateMac(encryptedMessage, sessionKey);
        if (!Objects.equals(encryptedMessage, AES_ENCRYPTION_ERROR_MESSAGE)) {
            outputToSocket.println(encryptedMessage);
            outputToSocket.println(Base64.getEncoder().encodeToString(iv));
            outputToSocket.println(mac);
            outputToSocket.println(DigitalSignature.createDigitalSignature(encryptedMessage, privateKey));
        }
    }

    private String decryptFromClient() {
        String message = inputFromSocket.nextLine();
        String iv = inputFromSocket.nextLine();
        String mac = inputFromSocket.nextLine();
        String signature = inputFromSocket.nextLine();
        if (userPublicKey != null) {
            if (DigitalSignature.verifyDigitalSignature(message, signature, userPublicKey)) {
                return AESEncryption.decrypt(message, sessionKey, iv, mac);
            }
            return VERIFY_DIGITAL_SIGNATURE_ERROR_MESSAGE;
        }
        return AESEncryption.decrypt(message, sessionKey, iv, mac);
    }

    private String decryptFromClient(StringBuilder signatureBuilder) {
        String message = inputFromSocket.nextLine();
        String iv = inputFromSocket.nextLine();
        String mac = inputFromSocket.nextLine();
        String signature = inputFromSocket.nextLine();
        if (DigitalSignature.verifyDigitalSignature(message, signature, userPublicKey)) {
            signatureBuilder.append(signature);
            return AESEncryption.decrypt(message, sessionKey, iv, mac);
        }
        return VERIFY_DIGITAL_SIGNATURE_ERROR_MESSAGE;
    }

    private void handleHandshake() throws SecurityException {
        String request = inputFromSocket.nextLine();

        if (Objects.equals(request, REQUEST_DIGITAL_SIGNATURE_MESSAGE)) {
            System.out.println("Handshake Started :), Sending digital certificate...");
            try {
                ObjectOutputStream objectToSocket=new ObjectOutputStream(socket.getOutputStream());
                objectToSocket.writeObject(this.certificate);
                sessionKey = RSAEncryption.decrypt(inputFromSocket.nextLine(), privateKey);
            } catch (IOException e) {
                e.printStackTrace();
            }
            encryptToClient(SESSION_KEY_ACCEPTED);
        } else {
            throw new SecurityException(HANDSHAKE_ERROR_MESSAGE);
        }
    }

    public void initializeUserPublicKey(String phoneNumber) {
        try {
            ObjectInputStream objectFromSocket=new ObjectInputStream(socket.getInputStream());
            Certificate userCertificate=(Certificate) objectFromSocket.readObject();
            boolean isValid=Certificate.verifyCertificate(userCertificate,phoneNumber);
            if(isValid){
                userPublicKey = userCertificate.subjectPublicKey ;
            }else{
                System.out.println("invalid certificate");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void startUserSession(String phoneNumber) {
        // store the session key in DB
        String sessionKeySuccessOrErrorMessage = DBConnector.setUserSecretKey(phoneNumber, sessionKey);
        // if session key stored successfully initialize user public key
        if (!sessionKeySuccessOrErrorMessage.contains("error")) {
            initializeUserPublicKey(phoneNumber);
            // store the public key in DB
            String publicKeySuccessOrErrorMessage = DBConnector.setUserPublicKey(phoneNumber, Base64.getEncoder().encodeToString(userPublicKey.getEncoded()));
            // if public key stored successfully
            if (!publicKeySuccessOrErrorMessage.contains("error")) {
                PortIdCollection.portIDPairs.add(new PortIDPair(socket.getPort(), phoneNumber));
                System.out.println(PortIdCollection.portIDPairs);
            }
        }
    }
}