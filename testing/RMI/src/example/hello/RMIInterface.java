package example.hello;

/**
 * Created by patcheco on 03/03/17.
 */
import java.rmi.*;

public interface RMIInterface extends Remote {

    public void sendMessage(String text) throws RemoteException;

    public String getMessage(String text) throws RemoteException;

}