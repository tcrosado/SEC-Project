package pt.ulisboa.tecnico.sec.tg11;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.NoSuchObjectException;
import java.rmi.NotBoundException;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.MessageManager;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.PWMInterface;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.*;
import pt.ulisboa.tecnico.sec.tg11.Login;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
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
    private static final String PATH_TO_KEYSTORE = "./src/main/resources/keystore.jks";
    private final String KEY_NAME = "privatekey";
    private static KeyStore _keystore;
    private static String _keystorepw;

	Map<UUID, Key> _userkeys = new HashMap<UUID,Key>();
	static Map<UUID, List<Login>> _userlogin = new HashMap<UUID, List<Login>>();
	

    private Registry reg;
    private int port;

    public Server() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        this(1099);
    }

    public Server(int port) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        this.port = port;
        reg = LocateRegistry.createRegistry(this.port);

        _keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        _keystorepw = "1234567";

        // get user password and file input stream
        char[] password = _keystorepw.toCharArray();

        _keystore.load(new FileInputStream(PATH_TO_KEYSTORE), password);
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
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        while (true);
    }
	

    public void put(byte[] msg) throws RemoteException, UserDoesNotExistException{
        /*UUID userID, byte[] domain, byte[] username, byte[] password*/
        try {
            PrivateKey key = (PrivateKey) _keystore.getKey(KEY_NAME,_keystorepw.toCharArray());
            MessageManager manager = new MessageManager(msg,key);
            UUID userID = manager.getUserID();
            Key clientKey = _userkeys.get(userID);
            manager.verifySignature(clientKey);

            byte[] domain = manager.getContent("domain");
            byte[] username = manager.getContent("username");
            byte[] password = manager.getContent("password");

            if(_userlogin.containsKey(userID)){
                List<Login> login_list = _userlogin.get(userID);

                if(!login_list.isEmpty()){
                    for (Login l: login_list) {
                        if((Arrays.equals(l.getDomain(),domain)) && Arrays.equals(l.getUsername(),username)){
                            l.setPassword(password);
                            _userlogin.replace(userID, login_list);
                            return;
                        }
                    }
                }

                List<Login> l = new ArrayList<Login>(login_list);
                l.add(new Login(username, domain, password));
                _userlogin.put(userID, l);
                return;

            }
            else
                throw new UserDoesNotExistException(userID);

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidSignatureException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }


    public byte[] get(byte[] msg) throws RemoteException, UserDoesNotExistException, PasswordDoesNotExistException {
    	/*UUID userID, byte[] domain, byte[] username*/

        try {
            PrivateKey key = (PrivateKey) _keystore.getKey(KEY_NAME,_keystorepw.toCharArray());
            MessageManager manager = new MessageManager(msg,key);
            UUID userID = manager.getUserID();
            Key clientKey = _userkeys.get(userID);
            manager.verifySignature(clientKey);


            byte[] domain = manager.getContent("domain");
            byte[] username = manager.getContent("username");
            if(_userlogin.containsKey(userID)){

                List<Login> login_list = _userlogin.get(userID);

                if(!login_list.isEmpty()){
                    for (Login l: login_list) {
                        if(Arrays.equals(l.getDomain(), domain) && (Arrays.equals(l.getUsername(), username))){
                            return l.getPassword();
                        }
                    }
                }
                throw new PasswordDoesNotExistException(userID, domain, username);
            }
            else
                throw new UserDoesNotExistException(userID);

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidSignatureException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

	public UUID register(Key publicKey) throws RemoteException, UserAlreadyExistsException {
		
		UUID user = UUID.randomUUID();

        for(UUID id : _userkeys.keySet())
            if(_userkeys.get(id).equals(publicKey))
                throw new UserAlreadyExistsException(publicKey);

        _userkeys.put(user,publicKey);
        List<Login> log = new ArrayList<Login>();
        _userlogin.put(user, log);

		return user;
	}

	public void shutdown() throws RemoteException, NotBoundException {
	    reg.unbind(SERVER_NAME);
        UnicastRemoteObject.unexportObject(reg, true);
    }

}
