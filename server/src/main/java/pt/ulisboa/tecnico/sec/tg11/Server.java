package pt.ulisboa.tecnico.sec.tg11;

import javax.management.remote.rmi.RMIServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.Key;

/**
 * Created by trosado on 01/03/17.
 *
 */
public class Server implements ServerInterface {

    public static void main(String [] args){
        Registry reg = null;
        try {
            reg = LocateRegistry.createRegistry(1099);
        } catch (Exception e) {
            System.out.println("ERROR: Could not create the registry.");
            e.printStackTrace();
        }
        Server serverObject = new Server();
        System.out.println("Waiting...");
        try {
            reg.rebind("PWMServer", (ServerInterface) UnicastRemoteObject.exportObject(serverObject, 0));
        } catch (Exception e) {
            System.out.println("ERROR: Failed to register the server object.");
            e.printStackTrace();
        }
        while (true);
    }

    public void register(Key publicKey) {
        System.out.println("Registering User");
    }

    public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) {
        System.out.println("Putting stuff");
    }

    public byte[] get(Key publicKey, byte[] domain, byte[] username) {
        byte[] val = "abc".getBytes();
        return val;
    }
}
