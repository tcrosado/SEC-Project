package pt.ulisboa.tecnico.sec.tg11;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.Key;
/**
 * Created by trosado on 03/03/17.
 */
public interface ServerInterface extends Remote {

    void register(Key publicKey) throws RemoteException;
    void put(Key publicKey,byte[] domain, byte[] username,byte[] password) throws RemoteException;
    byte[] get(Key publicKey,byte[] domain, byte[] username) throws RemoteException;
}
