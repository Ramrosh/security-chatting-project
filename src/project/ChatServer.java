package project;


import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;

public class ChatServer implements Runnable {

    private Socket socket;
    private Hasher hasher;
    private Scanner inputFromSocket;
    private PrintWriter outputToSocket;

    ChatServer(Socket socket) {
        this.socket = socket;
        hasher = new Hasher();
    }

    @Override
    public void run() {
        System.out.println("Connected: " + socket);
        try {
            this.inputFromSocket = new Scanner(socket.getInputStream());//input from client
            this.outputToSocket = new PrintWriter(socket.getOutputStream(), true);//output to client
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
                        System.out.println("logging out");
                        break;
                    }
                    default: {
                        break;
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("Error:" + socket);
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.out.println("Closed: " + socket);
        }
    }

    //handling inputs and outputs of requests&responses methods
    private void handleUserLogin(){
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
            PortIdCollection.portIDPairs.add(new PortIDPair(socket.getPort(), phoneNumber));
            System.out.println(PortIdCollection.portIDPairs);
        }
    }
    private void handleUserSignup(){
        //get phone number and password from client
        String phoneNumber = inputFromSocket.nextLine();
        String password = inputFromSocket.nextLine();
        String hashedPassword = this.hasher.hash(password.toCharArray());

        String successOrErrorMessage = DBConnector.signup(phoneNumber, hashedPassword);
        //output response to client
        outputToSocket.println(successOrErrorMessage);
        //if valid add phoneNumber and port to socketIdPairs
        if (!successOrErrorMessage.contains("error")) {
            PortIdCollection.portIDPairs.add(new PortIDPair(socket.getPort(), phoneNumber));
            System.out.println(PortIdCollection.portIDPairs);
        }
    }
    private void handleUserMessageSending(){
        String clientPhoneNumber = inputFromSocket.nextLine();
        String contactChoice = inputFromSocket.nextLine();
        String receiverNumber = "";
        boolean hasError=false;
        switch (contactChoice) {
            case "newContact": {
                receiverNumber = inputFromSocket.nextLine();
                String successOrErrorMessage = DBConnector.addingContact(clientPhoneNumber, receiverNumber);
                if(successOrErrorMessage.contains("error")){
                    hasError=true;
                }
                //output response to client
                outputToSocket.println(successOrErrorMessage);
                break;
            }
            case "oldContact": {
                ArrayList<String> contacts = DBConnector.getContacts(clientPhoneNumber);
                if(contacts.get(0).contains("error")){
                    hasError=true;
                }
                for (String s : contacts) {
                    System.out.println(s);
                }
                outputToSocket.println(contacts.size()); // send the size so the client can iterate over it
                for (String contact : contacts)
                    outputToSocket.println(contact);
                if(!hasError)
                    receiverNumber = inputFromSocket.nextLine();
                break;
            }
            default:
                break;
        }
        if(!hasError)//if no error was received by db send the message
        {
            StringBuilder message = new StringBuilder();
            String str = "";
            while (!(str = inputFromSocket.nextLine()).equals("#send")) {
                System.out.println(str);
                message.append(str);
            }
            System.out.println("contactChoice " + contactChoice);
            System.out.println("clientPhoneNumber : " + clientPhoneNumber);
            System.out.println("receiverNumber : " + receiverNumber);
            System.out.println("message : " + message);
            // save the message into db
            String successOrErrorMessage = DBConnector.sendMessage(clientPhoneNumber, receiverNumber,
                    message.toString());
            //output response to client
            outputToSocket.println(successOrErrorMessage);
            // send the message for the other client
                        /*int otherSocketPort = PortIdCollection.getSocketPort(receiverNumber);
                        String host = PortIdCollection.getHost(receiverNumber);
                        Socket otherSocket = new Socket(host, otherSocketPort);
                        System.out.println("other socket: "+ otherSocket);
                        PrintWriter outputToOtherSocket;
                        outputToOtherSocket = new PrintWriter(otherSocket.getOutputStream(), true);
                        outputToOtherSocket.print(true);
                        outputToOtherSocket.println(clientPhoneNumber);
                        outputToOtherSocket.println("content: " + message);*/
        }
    }
    private void handleUserMessagesPreview(){
        String clientPhoneNumber = inputFromSocket.nextLine();
        System.out.println("showing messages to " + clientPhoneNumber);
        // get the messages of the client
        ArrayList<HashMap> result = DBConnector.getMessages(clientPhoneNumber);
        System.out.println("messages result = "+result);
        outputToSocket.println(result.size());
        for (HashMap hashMap : result) {
            String message = "";
            if (clientPhoneNumber.equals(hashMap.get("sender_phone_number"))) {
                message = "From: Me, To: " + hashMap.get("receiver_phone_number") +
                        ", msg: " + hashMap.get("content") + ", at:" + hashMap.get("sent_at");
            } else if (clientPhoneNumber.equals(hashMap.get("receiver_phone_number"))) {
                message = "From: " + hashMap.get("sender_phone_number") + ", To: ME" +
                        ", msg: " + hashMap.get("content") + ", at:" + hashMap.get("sent_at");
            }else if(hashMap.containsKey("error")){
                message=hashMap.get("error").toString();
            }
            else {
                message = "Saved Message:" +
                        ", msg: " + hashMap.get("content") + ", at:" + hashMap.get("sent_at");
            }
            outputToSocket.println(message);
        }
    }
}