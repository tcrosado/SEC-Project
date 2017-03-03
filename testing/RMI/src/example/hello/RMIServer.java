package example.hello;

/**
 * Created by patcheco on 03/03/17.
 */
import java.rmi.*;
import java.rmi.registry.*;
import java.rmi.server.*;

public class RMIServer implements RMIInterface {

    @Override
    public void sendMessage(String s) throws RemoteException {
        System.out.println(s);
    }

    @Override
    public String getMessage(String text) throws RemoteException {
        return "Your message is: " + text;
    }

    public static void main(String[] args) {
        Registry reg = null;
        try {
            reg = LocateRegistry.createRegistry(1099);
        } catch (Exception e) {
            System.out.println("ERROR: Could not create the registry.");
            e.printStackTrace();
        }
        RMIServer serverObject = new RMIServer();
        System.out.println("Waiting...");
        try {
            reg.rebind("server", (RMIInterface) UnicastRemoteObject.exportObject(serverObject, 0));
        } catch (Exception e) {
            System.out.println("ERROR: Failed to register the server object.");
            e.printStackTrace();
        }
    }
}
