package pt.ulisboa.tecnico.sec.tg11;

import java.rmi.NoSuchObjectException;
import java.rmi.NotBoundException;
import pt.tecnico.ulisboa.sec.tg11.PWInterface.PWMInterface;
import pt.tecnico.ulisboa.sec.tg11.PWInterface.exceptions.*;
import pt.ulisboa.tecnico.sec.tg11.Login;

import java.rmi.Remote;
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
public class Server implements PWMInterface {
	
	private final String SERVER_NAME = "PWMServer";


	Map<Key, UUID> _userkeys = new HashMap<Key, UUID>();
	static Map<UUID, List<Login>> _userlogin = new HashMap<UUID, List<Login>>();
	

    private Registry reg;
    private int port;

    public Server() throws RemoteException {
        this(1099);
    }

    public Server(int port) throws RemoteException {
        this.port = port;
        reg = LocateRegistry.createRegistry(this.port);
    }

    public void setUp() throws RemoteException {

        System.out.println("Waiting...");

        try {
            reg.rebind(SERVER_NAME, (PWMInterface) UnicastRemoteObject.exportObject((PWMInterface) this, this.port));
        } catch (Exception e) {
            System.out.println("ERROR: Failed to register the server object.");
            e.printStackTrace();
        }

    }

    public static void main(String [] args){
        Server server;
        try {
            server = new Server();
            server.setUp();
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        while (true);
    }
	

    public void put(UUID userID, byte[] domain, byte[] username, byte[] password) throws RemoteException, UserDoesNotExistException{
    	
    	if(_userlogin.containsKey(userID)){
            List<Login> login_list = _userlogin.get(userID);

            if(!login_list.isEmpty()){
                for (Login l: login_list) {
                    if((l.getDomain().equals(domain)) && l.getUsername().equals(username)){
                    	l.setPassword(password);
                    	return;
                    }
                }
            }
            
            Login l = new Login(username, domain, password);
            login_list.add(l);
            
    	}
    	else
    		throw new UserDoesNotExistException(userID);
    }


    public byte[] get(UUID userID, byte[] domain, byte[] username) throws RemoteException, UserDoesNotExistException, PasswordDoesNotExistException {
        
    	if(_userlogin.containsKey(userID)){
            List<Login> login_list = _userlogin.get(userID);
            
            if(!login_list.isEmpty()){
                for (Login l: login_list) {
                    if((l.getDomain().equals(domain)) && (l.getUsername().equals(username))){
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

	public void shutdown() throws RemoteException, NotBoundException {
	    reg.unbind(SERVER_NAME);
        UnicastRemoteObject.unexportObject(reg, true);
    }

}