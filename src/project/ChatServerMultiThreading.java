package project;

import project.cryptography.asymmetric.RSAEncryption;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class ChatServerMultiThreading {
    public static void main(String[] args) throws Exception {
        try (ServerSocket listener = new ServerSocket(11111)) {
            RSAEncryption.init();
            System.out.println("The chat server is running...");
            ExecutorService pool = Executors.newFixedThreadPool(20);
            while (true) {
                    pool.execute(new ChatServer(listener.accept()));
            }
        }
    }
}



