package example.hello;

/**
 * Created by patcheco on 03/03/17.
 */
import java.rmi.*;
import java.rmi.registry.*;

public class RMIClient {

    public static void main(String[] args) {

        String text = "RMI Test Message";
        RMIInterface rmi = null;

        try {
            Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
            rmi = (RMIInterface) registry.lookup("server");
            System.out.println("Connected to Server");
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (rmi != null) {
            try {
                rmi.sendMessage(text);
                System.out.println(rmi.getMessage(text));
            } catch (RemoteException e) {
                e.printStackTrace();
            }
            System.out.println("Finished");
        }
    }
}
