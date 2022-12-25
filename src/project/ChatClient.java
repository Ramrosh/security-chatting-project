package project;

import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Scanner;

import static project.utils.ConsolePrintingColors.ANSI_GREEN;
import static project.utils.ConsolePrintingColors.ANSI_RESET;

public class ChatClient {
    //attributes
    boolean isLoggedIn;
    boolean isOn;
    private String myPhoneNumber;
    //input&output streams
    private Scanner inputFromSocket;
    private PrintWriter outputToSocket;
    private Scanner inputFromTerminal;

    //constructors
    public ChatClient() {
        this.isLoggedIn = false;
        this.isOn = false;
        this.myPhoneNumber = "";
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
            //this.getMessages(inputFromSocket);
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
                            break;
                        }
                        case "2"://log in
                        {
                           this.requestLogin();
                            break;
                        }
                        case "3"://exit
                        {
                            outputToSocket.close();
                            inputFromSocket.close();
                            socket.close();
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
                            System.out.println("logged out Goodbye :)");
                            break;
                        }
                        case "4"://exit
                        {
                            outputToSocket.close();
                            inputFromSocket.close();
                            socket.close();
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
    private void requestLogin(){
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
            this.isOn = true;
            System.out.println(ANSI_GREEN+"I am logged in now :) "+ANSI_RESET);
        }
    }
    private void requestSignup(){
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
            this.isOn = true;
            System.out.println(ANSI_GREEN+"I am logged in now :) "+ANSI_RESET);
        }
    }
    private void requestSendingNewMessage(){
        //send to  server that it is sending message request
        outputToSocket.println("sendMessage");
        outputToSocket.println(myPhoneNumber);
        System.out.println("sending message from " + myPhoneNumber);
        System.out.println("Enter 1 to add a new contact , 2 to choose from saved contact");
        String sendingChoice = inputFromTerminal.nextLine();
        String receiverNumber = "";
        boolean hasError=false;
        switch (sendingChoice) {
            case "1": // add a new contact
            {
                outputToSocket.println("newContact");
                System.out.println("enter the number:");
                receiverNumber = inputFromTerminal.nextLine();
                outputToSocket.println(receiverNumber);
                // check if the number existed ...get response from server
                String response = inputFromSocket.nextLine();
                if (response.contains("error"))
                {
                    hasError=true;
                }
                System.out.println("response from server ( " + response + " )");
                break;
            }
            case "2": //choose from saved contact
            {
                outputToSocket.println("oldContact");
                // get numbers from the server
                int contactNumber = Integer.parseInt(inputFromSocket.nextLine());
                System.out.println("contactNumber "+ contactNumber);
                ArrayList<String> MyContacts = new ArrayList<>();
                for (int i = 1; i <= contactNumber; i++) {
                    String response = inputFromSocket.nextLine();
                    MyContacts.add(response);
                }
                if (MyContacts.get(0).contains("error")) {
                    hasError=true;
                    System.out.println("response from server ( " + MyContacts.get(0) + " )");
                } else {
                    System.out.println("choose the id of the number you want to send a message to:");
                    for (int i = 1; i <= contactNumber; i++) {
                        System.out.println("(" + i + "): " + MyContacts.get(i-1));
                    }
                    int id = Integer.parseInt(inputFromTerminal.nextLine());
                    receiverNumber = MyContacts.get(id - 1);
                    outputToSocket.println(receiverNumber);
                }
                break;
            }
            default:
                break;
        }
        if(!hasError){
            String TERMINATOR_STRING = "#send";
            System.out.println("enter the message: (press " + TERMINATOR_STRING + " to send)");
            String message;
            while (!(message = inputFromTerminal.nextLine()).equals(TERMINATOR_STRING)) {
                outputToSocket.println(message);
            }
            outputToSocket.println("#send");
            System.out.println("sending...");
            //get response from server
            String response = inputFromSocket.nextLine();
            System.out.println("response from server ( " + response + " )");
        }
    }
    private void requestPreviewingOldMessages(){
        System.out.println("reviewing messages");
        outputToSocket.println("showMessages");
        outputToSocket.println(myPhoneNumber);
        int messagesNumber = Integer.parseInt(inputFromSocket.nextLine());
        for (int i = 0; i < messagesNumber; i++) {
            String message = inputFromSocket.nextLine();
            System.out.println(message);
        }
    }

    //util methods
    private void getMessages(Scanner inputFromSocket){
        Thread getMessages = new Thread(){
            @Override
            public void run(){
                String messageReceived ="", senderPhoneNumber = "";
                while (isOn){
                    System.out.println("waiting messages...");
                    if(inputFromSocket.hasNextBoolean()){
                        inputFromSocket.nextBoolean();
                        senderPhoneNumber = inputFromSocket.next();
                        messageReceived = inputFromSocket.nextLine();
                        System.out.println("new message arrived from :" +senderPhoneNumber);
                        System.out.println(messageReceived);
                    }
                }
            }
        };
        getMessages.start();
    }
    private void resetClientState(){
        this.isLoggedIn = false;
        this.isOn = false;
        this.myPhoneNumber = "";
    }

    public static void main(String[] args) {
        ChatClient client = new ChatClient();
        client.run();
    }
}
