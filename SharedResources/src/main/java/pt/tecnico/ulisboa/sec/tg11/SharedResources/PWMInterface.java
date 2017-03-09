package pt.tecnico.ulisboa.sec.tg11.SharedResources;

import java.rmi.RemoteException;
import java.security.Key;
import java.util.UUID;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.PasswordDoesNotExistException;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.UserAlreadyExistsException;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.UserDoesNotExistException;

import java.rmi.Remote;



public interface PWMInterface extends Remote{
	
	UUID register(Key publicKey) throws RemoteException, UserAlreadyExistsException;

    void put(UUID userID, byte[] domain, byte[] username, byte[] password) throws RemoteException, UserDoesNotExistException;

    byte[] get(UUID userID, byte[] domain, byte[] username) throws RemoteException, UserDoesNotExistException, PasswordDoesNotExistException;

}
