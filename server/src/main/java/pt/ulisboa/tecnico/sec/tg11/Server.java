package pt.ulisboa.tecnico.sec.tg11;

import pt.ulisboa.tecnico.sec.tg11.exceptions.PasswordDoesNotExistException;
import pt.ulisboa.tecnico.sec.tg11.exceptions.UserAlreadyExistsException;
import pt.ulisboa.tecnico.sec.tg11.exceptions.UserDoesNotExistException;
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
        boolean update = false;
    	
    	if(_userlogin.containsKey(userID)){
            List<Login> login_list = _userlogin.get(userID);

            if(!login_list.isEmpty()){
                for (Login l: login_list) {
                    if( (l.getDomain().equals(domain)) && (l.getUsername().equals(username))){
                        l.setPassword(password);
                        update = true;
                    }
                }
            }
            if(!update){
                Login log = new Login(username, domain, password);
                login_list.add(log);
            }
    	}
    	else
    		throw new UserDoesNotExistException(userID);
    }


    public byte[] get(UUID userID, byte[] domain, byte[] username) throws UserDoesNotExistException, PasswordDoesNotExistException {
        if(_userlogin.containsKey(userID)){
            List<Login> login_list = _userlogin.get(userID);

            if(!login_list.isEmpty()){
                for (Login l: login_list) {
                    if( (l.getDomain().equals(domain)) && (l.getUsername().equals(username))){
                        return l.getPassword();
                    }
                }
            }
            throw new PasswordDoesNotExistException(userID, domain, username);
        }
        else
            throw new UserDoesNotExistException(userID);
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
