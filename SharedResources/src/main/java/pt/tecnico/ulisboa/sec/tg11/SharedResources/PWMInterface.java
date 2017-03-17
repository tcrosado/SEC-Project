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

import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.InvalidNonceException;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.InvalidSignatureException;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.InvalidRequestException;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.UserAlreadyExistsException;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.UserDoesNotExistException;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.WrongUserIDException;

import java.io.IOException;
import java.math.BigInteger;
import java.rmi.Remote;



public interface PWMInterface extends Remote{
	
	UUID register(Key publicKey) throws RemoteException, UserAlreadyExistsException;
	
	BigInteger requestNonce(UUID userID) throws RemoteException;
	
    void put(byte[] msg) throws RemoteException, UserDoesNotExistException, InvalidNonceException,InvalidSignatureException, WrongUserIDException;
    /* UUID userID, byte[] domain, byte[] username, byte[] password */
    

    byte[] get(byte[] msg) throws RemoteException, UserDoesNotExistException, InvalidRequestException, InvalidNonceException, WrongUserIDException, InvalidSignatureException;
    /*UUID userID, byte[] domain, byte[] username*/
}
