package project;

import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;

public class PortIdCollection {
    public static ArrayList<PortIDPair> portIDPairs=new ArrayList<>();

    public static int getSocketPort (String id){
        for (PortIDPair portIDPair : portIDPairs) {
            if (portIDPair.id.equals(id)) {
                return portIDPair.socketPort;
            }
        }
        return -1;
    }

    public static String getHost(String receiverNumber) {
        try {
            InetAddress ip = InetAddress.getLocalHost();
            return ip.getHostAddress();
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }
}
