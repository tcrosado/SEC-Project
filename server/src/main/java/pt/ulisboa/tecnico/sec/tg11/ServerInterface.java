package pt.ulisboa.tecnico.sec.tg11;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.Key;
import java.util.UUID;

import pt.ulisboa.tecnico.sec.tg11.exceptions.PasswordDoesNotExistException;
import pt.ulisboa.tecnico.sec.tg11.exceptions.UserAlreadyExistsException;
import pt.ulisboa.tecnico.sec.tg11.exceptions.UserDoesNotExistException;
/**
 * Created by trosado on 03/03/17.
 */
public interface ServerInterface extends Remote {

    UUID register(Key publicKey) throws RemoteException, UserAlreadyExistsException;

    void put(UUID userID, byte[] domain, byte[] username, byte[] password) throws RemoteException, UserDoesNotExistException;

    byte[] get(UUID userID, byte[] domain, byte[] username) throws RemoteException, UserDoesNotExistException, PasswordDoesNotExistException;
}
