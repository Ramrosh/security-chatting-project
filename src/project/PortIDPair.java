package project;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

public class PortIDPair {
    int socketPort;
    String id;

    PortIDPair(int socketPort, String id) {
        this.socketPort = socketPort;
        this.id = id;
    }
}
