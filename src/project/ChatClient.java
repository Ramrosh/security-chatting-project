package project;

import project.cryptography.symmetric.Symmetric;

import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;

import static project.utils.ConsolePrintingColors.*;

public class ChatClient {

    /**
     * We can use this map for getting user's secret key by [myPhoneNumber]
     **/
    private final Map<String, String> keys = new HashMap<>() {{
        put("0933062132", "Sv3DSAebkWl1/52LqurnOCoJygpE3E3rda14OcjfQGk=");
        put("0953954152", "QefDGTafpKCi/3WGg2TkAYRHFGSkhUiqOVE344jNsHM=");
        put("0955222043", "P7lsK/e8rVi9xOtBU5Zvo5JX4ozeLK5M/6sT7mCAQkY=");
        put("0955222044", "4n/1hyt6uMgQaJRqlooplo+uWhEAJWf5yyi2prTDW60=");
        put("0992371147", "UDFxrAb9uZ2k8K49YigxXG85li1By+//+aL73gIqMD4=");
        put("0992371148", "cVK0my61a3R+WVEH96ELehVJrpSuf+zb7E97jQpO9VA=");
        put("0944815425", "9aM6rCwUZ5xtZjrRmXx0ZEpnnXK8JwybbABqam5AoCc=");
    }};

    //attributes
    boolean isLoggedIn;

    private String myPhoneNumber;
    //input&output streams
    private Scanner inputFromSocket;
    private PrintWriter outputToSocket;
    private Scanner inputFromTerminal;

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
            System.err.println(e.getMessage());
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
            System.out.println(ANSI_GREEN + "I am logged in now :) " + ANSI_RESET);
        }
    }

    private void requestSendingNewMessage() {
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
                if (Symmetric.verifyPlainText(message)) {
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
            String message;
            while (!(message = inputFromTerminal.nextLine()).equals(TERMINATOR_STRING)) {
                encryptToServer(message);
            }
            encryptToServer(TERMINATOR_STRING);
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
        if (Symmetric.verifyPlainText(message)) {
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
        ServerSocket getMessagesServerSocket;

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
        this.myPhoneNumber = "";
    }

    private void encryptToServer(String message) {
        byte[] iv = Symmetric.generateIV();
        String encryptedMessage = Symmetric.encrypt(message, keys.get(myPhoneNumber), iv);
        if (encryptedMessage != null) {
            outputToSocket.println(encryptedMessage);
            outputToSocket.println(Base64.getEncoder().encodeToString(iv));
            outputToSocket.println(Symmetric.generateMac(encryptedMessage, keys.get(myPhoneNumber)));
        }
    }

    private String decryptFromServer() {
        String messageReceived = inputFromSocket.nextLine();
        String iv = inputFromSocket.nextLine();
        String mac = inputFromSocket.nextLine();
        return Symmetric.decrypt(messageReceived, keys.get(myPhoneNumber), iv, mac);
    }

    private String decryptFromServer(Scanner inputFromOtherSocket) {
        String messageReceived = inputFromOtherSocket.nextLine();
        String iv = inputFromOtherSocket.nextLine();
        String mac = inputFromOtherSocket.nextLine();
        return Symmetric.decrypt(messageReceived, keys.get(myPhoneNumber), iv, mac);
    }

    public static void main(String[] args) {
        ChatClient client = new ChatClient();
        client.run();
    }
}
