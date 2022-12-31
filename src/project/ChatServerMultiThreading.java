package project;

import project.cryptography.asymmetric.RSAEncryption;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static project.utils.Constants.*;


public class ChatServerMultiThreading {
    public static void main(String[] args) throws Exception {
        try (ServerSocket listener = new ServerSocket(11111)) {
            RSAEncryption.init(SERVER_PUBLIC_KEY_FILE, SERVER_PRIVATE_KEY_FILE);
            System.out.println("The chat server is running...");
            ExecutorService pool = Executors.newFixedThreadPool(20);
            while (true) {
                pool.execute(new ChatServer(listener.accept()));
            }
        }
    }
}



