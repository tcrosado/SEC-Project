package pt.ulisboa.tecnico.sec.tg11;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.rmi.NoSuchObjectException;
import java.rmi.NotBoundException;


import pt.ulisboa.tecnico.sec.tg11.Login;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.MessageManager;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.PWMInterface;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.*;


import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

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
    private PrivateKey _privateKey;
    private PublicKey _publicKey;

	private Map<UUID, Key> _userKeys = new ConcurrentHashMap<UUID, Key>();
	private static Map<UUID, List<Login>> _userlogin = new ConcurrentHashMap<UUID, List<Login>>();
	private Map<UUID,List<BigInteger>> _nonces;

    private Registry reg;
    private int port;

    public Server() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        this(1099);
    }

    public Server(int port) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        this.port = port;
        _nonces = new HashMap<UUID,List<BigInteger>>();
        reg = LocateRegistry.createRegistry(this.port);

        _keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        _keystorepw = "1234567";

        // get user password and file input stream
        char[] password = _keystorepw.toCharArray();

        _keystore.load(new FileInputStream(PATH_TO_KEYSTORE), password);
        _privateKey = (PrivateKey) _keystore.getKey(KEY_NAME,_keystorepw.toCharArray());
        _publicKey = _keystore.getCertificate(KEY_NAME).getPublicKey();
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
    

    public static void main(String [] args) throws UnrecoverableKeyException{
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
	

    public byte[] put(byte[] msg) throws RemoteException, UserDoesNotExistException, InvalidNonceException, InvalidSignatureException, WrongUserIDException{
        /*UUID userID, byte[] domain, byte[] username, byte[] password*/
        try {
            MessageManager manager = new MessageManager(msg);
            UUID userID = manager.getUserID();

            Key clientKey = _userKeys.get(userID);
            
            if(clientKey == null)
            	throw new WrongUserIDException(userID);
            
            manager.setPublicKey(clientKey);
            manager.verifySignature();
            
            this.verifyNounce(userID, manager.getNonce());
            
            byte[] domain = manager.getContent("domain");
            byte[] username = manager.getContent("username");
            byte[] password = manager.getContent("password");

            MessageManager sendManager = new MessageManager(generateNonce(),_privateKey,_publicKey);


            if(_userlogin.containsKey(userID)){
                List<Login> login_list = _userlogin.get(userID);

                if(!login_list.isEmpty()){
                    for (Login l: login_list) {
                        if((Arrays.equals(l.getDomain(),domain)) && Arrays.equals(l.getUsername(),username)){
                            l.setPassword(password);
                            _userlogin.replace(userID, login_list);
                            sendManager.putPlainTextContent("Status","ACK".getBytes());
                            return sendManager.generateMessage();
                        }
                    }
                }
                List<Login> l = new ArrayList<Login>(login_list);
                l.add(new Login(username, domain, password));
                _userlogin.put(userID, l);
                sendManager.putPlainTextContent("Status","ACK".getBytes());
                return sendManager.generateMessage();

            }
            else
                throw new UserDoesNotExistException(userID);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
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
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null; //FIXME
    }


    public byte[] get(byte[] msg) throws RemoteException, InvalidSignatureException, UserDoesNotExistException, InvalidRequestException, InvalidNonceException, WrongUserIDException {
    	/*UUID userID, byte[] domain, byte[] username*/
        /*TODO
        *  - Server returning messages through the MessageManager
        * */
        try {

        	MessageManager receiveManager = new MessageManager(msg);
        	UUID userID = receiveManager.getUserID();
            Key clientKey = _userKeys.get(userID);
            
            if(clientKey == null)
            	throw new WrongUserIDException(userID);
            
            receiveManager.setPublicKey(clientKey);
            receiveManager.verifySignature();

            this.verifyNounce(userID, receiveManager.getNonce());

            byte[] domain = receiveManager.getContent("domain");
            byte[] username = receiveManager.getContent("username");


            MessageManager sendManager = new MessageManager(this.generateNonce(),_privateKey,_publicKey);


            if(_userlogin.containsKey(userID)){
                List<Login> login_list = _userlogin.get(userID);
                if(!login_list.isEmpty()){
                	
                    for (Login l: login_list) {
                        if(Arrays.equals(l.getDomain(), domain) && (Arrays.equals(l.getUsername(), username))){
                            sendManager.putPlainTextContent("Password",l.getPassword());
                            return sendManager.generateMessage();
                        }
                    }
                }
                throw new InvalidRequestException(userID, domain, username);
            }
            else
                throw new UserDoesNotExistException(userID);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
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
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

	public byte[] register(Key publicKey) throws RemoteException, UserAlreadyExistsException {

        try {
            MessageManager sendManager = new MessageManager(generateNonce(),_privateKey,_publicKey);

            UUID user = UUID.randomUUID();

            for(UUID id : _userKeys.keySet())
                if(_userKeys.get(id).equals(publicKey))
                    throw new UserAlreadyExistsException(publicKey);

            _userKeys.put(user,publicKey);
            List<Login> log = new ArrayList<Login>();
            _userlogin.put(user, log);

            sendManager.putPlainTextContent("UUID",user.toString().getBytes());

            return sendManager.generateMessage();

        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null; //FIXME
    }

	public void shutdown() throws RemoteException, NotBoundException {
	    reg.unbind(SERVER_NAME);
        UnicastRemoteObject.unexportObject(reg, true);
    }

	public byte[] requestNonce(UUID userID) throws RemoteException {
        try {
            MessageManager mm = new MessageManager(generateNonce(),_privateKey,_publicKey);

            BigInteger nonce = generateNonce();
            List<BigInteger> list = _nonces.get(userID);
            if(list == null){
                list = new ArrayList<BigInteger>();
                _nonces.put(userID, list);
            }

            list.add(nonce);


            mm.putPlainTextContent("Nonce",nonce.toByteArray());

            return mm.generateMessage();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null; //FIXME
    }

	private BigInteger generateNonce(){
        return new BigInteger(64, new SecureRandom());
    }
	
	private void verifyNounce(UUID userID,BigInteger nonce) throws InvalidNonceException{
		List<BigInteger> nonceList = _nonces.get(userID);
		if(nonceList.contains(nonce))
			nonceList.remove(nonce);
		else
			throw new InvalidNonceException(nonce);
		
	}

}
