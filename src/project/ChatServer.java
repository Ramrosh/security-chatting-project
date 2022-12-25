package project;


import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;

public class ChatServer implements Runnable { // runnable interface has the run method that threads execute

    private Socket socket;
    private Hasher hasher;

    ChatServer(Socket socket) {
        this.socket = socket;
        hasher = new Hasher();
    }

    @Override
    public void run() {
        System.out.println("Connected: " + socket);
        try {
            Scanner inputFromSocket = new Scanner(socket.getInputStream());//input from client
            PrintWriter outputToSocket = new PrintWriter(socket.getOutputStream(), true);//output to client
            while (inputFromSocket.hasNextLine()) {
                String clientRequestChoice = inputFromSocket.nextLine();
                switch (clientRequestChoice) {
                    case "login": {
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
                        break;
                    }
                    case "signup": {
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
                        break;
                    }
                    case "sendMessage": {
                        String clientPhoneNumber = inputFromSocket.nextLine();
                        String contactChoice = inputFromSocket.nextLine();
                        String receiverNumber = "";
                        switch (contactChoice) {
                            case "newContact": {
                                receiverNumber = inputFromSocket.nextLine();
                                String successOrErrorMessage = DBConnector.addingContact(clientPhoneNumber, receiverNumber);
                                //output response to client
                                outputToSocket.println(successOrErrorMessage);
                                break;
                            }
                            case "oldContact": {
                                ArrayList<String> contacts = DBConnector.getContacts(clientPhoneNumber);
                                for (String s : contacts) {
                                    System.out.println(s);
                                }
                                outputToSocket.println(contacts.size()); // send the size so the client can iterate over it
                                for (String contact : contacts)
                                    outputToSocket.println(contact);
                                receiverNumber = inputFromSocket.nextLine();
                                break;
                            }
                            default:
                                break;
                        }
                        if (!(contactChoice.equals("newContact") || contactChoice.equals("oldContact"))) break;
                        StringBuilder message = new StringBuilder();
                        String str = "";
                        while (!(str = inputFromSocket.nextLine()).isBlank()) {
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
                        break;
                    }
                    case "showMessages": {
                        String clientPhoneNumber = inputFromSocket.nextLine();
                        System.out.println("showing messages to " + clientPhoneNumber);
                        // get the messages of the client
                        ArrayList<HashMap> result = DBConnector.getMessages(clientPhoneNumber);
                        outputToSocket.println(result.size());
                        for (HashMap hashMap : result) {
                            String message = "";
                            if (clientPhoneNumber.equals(hashMap.get("sender_phone_number"))) {
                                message = "From: Me, To: " + hashMap.get("receiver_phone_number") +
                                        ", msg: " + hashMap.get("content") + ", at:" + hashMap.get("sent_at");
                            } else if (clientPhoneNumber.equals(hashMap.get("receiver_phone_number"))) {
                                message = "From: " + hashMap.get("sender_phone_number") + ", To: ME" +
                                        ", msg: " + hashMap.get("content") + ", at:" + hashMap.get("sent_at");
                            } else {
                                message = "Saved Message:" +
                                        ", msg: " + hashMap.get("content") + ", at:" + hashMap.get("sent_at");
                            }
                            outputToSocket.println(message);
                        }
                        break;
                    }
                    case "logout": {
                        System.out.println("logging out");
                        break;
                    }
                    default: {
                        outputToSocket.close();
                        inputFromSocket.close();
                        socket.close();
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
}