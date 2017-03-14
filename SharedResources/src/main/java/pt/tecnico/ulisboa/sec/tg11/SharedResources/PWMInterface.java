package pt.tecnico.ulisboa.sec.tg11.SharedResources;

import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.InvalidSignatureException;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.PasswordDoesNotExistException;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.UserAlreadyExistsException;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.UserDoesNotExistException;

import java.io.IOException;
import java.rmi.Remote;



public interface PWMInterface extends Remote{
	
	UUID register(Key publicKey) throws RemoteException, UserAlreadyExistsException;

    void put(UUID userID, byte[] msg) throws RemoteException, UserDoesNotExistException;
    /* UUID userID, byte[] domain, byte[] username, byte[] password */
    
    byte[] get(UUID userID, byte[] msg) throws RemoteException, UserDoesNotExistException, PasswordDoesNotExistException;
    /*UUID userID, byte[] domain, byte[] username*/
    
    void receiveSessionKey(byte[] message) throws RemoteException, InvalidKeyException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException, IOException, InvalidSignatureException, UserDoesNotExistException;
}
