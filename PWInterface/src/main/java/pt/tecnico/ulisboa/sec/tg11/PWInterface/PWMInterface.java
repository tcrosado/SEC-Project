package pt.tecnico.ulisboa.sec.tg11.PWInterface;

import java.rmi.RemoteException;
import java.security.Key;
import java.util.UUID;
import java.rmi.Remote;

import pt.tecnico.ulisboa.sec.tg11.PWInterface.exceptions.PasswordDoesNotExistException;
import pt.tecnico.ulisboa.sec.tg11.PWInterface.exceptions.UserAlreadyExistsException;
import pt.tecnico.ulisboa.sec.tg11.PWInterface.exceptions.UserDoesNotExistException;



public interface PWMInterface extends Remote{
	
	UUID register(Key publicKey) throws RemoteException, UserAlreadyExistsException;

    void put(UUID userID, byte[] domain, byte[] username, byte[] password) throws RemoteException, UserDoesNotExistException;

    byte[] get(UUID userID, byte[] domain, byte[] username) throws RemoteException, UserDoesNotExistException, PasswordDoesNotExistException;

}
