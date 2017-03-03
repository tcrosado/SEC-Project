package pt.ulisboa.tecnico.sec.tg11;

import javax.management.remote.rmi.RMIServer;

import pt.ulisboa.tecnico.sec.tg11.exceptions.UserAlreadyExistsException;
import pt.ulisboa.tecnico.sec.tg11.exceptions.UserDoesNotExistException;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.Key;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Created by trosado on 01/03/17.
 *
 */
public class Server implements ServerInterface {
	
	
	Map<Key, UUID> _userkeys = new HashMap<Key, UUID>();
	Map<UUID, List<Login>> _userlogin = new HashMap<UUID, List<Login>>();

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

    public void put(UUID userID, byte[] domain, byte[] username, byte[] password) throws RemoteException, UserDoesNotExistException{
        
    	
    	if(_userlogin.containsKey(userID)){
    		
    		if(_userlogin.get(userID).isEmpty()){
    			Login log = new Login(username, domain, password);
    			_userlogin.get(userID).add(log);
    		}
    	}
    	else
    		throw new UserDoesNotExistException(userID);
    }

    public byte[] get(Key publicKey, byte[] domain, byte[] username) {
        byte[] val = "abc".getBytes();
        return val;
    }

	public UUID register(Key publicKey) throws RemoteException, UserAlreadyExistsException {
		
		UUID user = UUID.randomUUID();
		
		if(!_userkeys.containsKey(publicKey)){
			_userkeys.put(publicKey, user);
			List<Login> log = new ArrayList<Login>();
			_userlogin.put(user, log);
		}
		else
			throw new UserAlreadyExistsException(user);
		
		return user;
	}

}
