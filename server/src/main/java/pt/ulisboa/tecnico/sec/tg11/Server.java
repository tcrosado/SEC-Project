package pt.ulisboa.tecnico.sec.tg11;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.rmi.NotBoundException;


import org.apache.log4j.Logger;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.MessageManager;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.PWMInterface;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.*;


import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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
import java.util.concurrent.ConcurrentHashMap;
import java.sql.Timestamp;
;

/**
 * Created by trosado on 01/03/17.
 *
 */
public class Server implements PWMInterface {

    static Logger logger = Logger.getLogger(Server.class.getName());
	
	private static String SERVER_REGISTRY_NAME = null;
	private static Integer timestamp;
    private final String KEY_NAME = "privatekey";
    private static String _keystorepw;
    private PrivateKey _privateKey;
    private PublicKey _publicKey;

	private Map<UUID, Key> _userKeys = new HashMap<UUID, Key>();
	private static Map<UUID, List<Login>> _userlogin = new ConcurrentHashMap<UUID, List<Login>>();
	private Map<UUID,List<BigInteger>> _nonces;

    private static Registry reg;
    private int port;


    public Server(int id) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        this(1099+id, id);
    }

    public Server(int port, int id) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        this.port = port;
        timestamp = 0;
        _nonces = new HashMap<UUID,List<BigInteger>>();
        reg = LocateRegistry.createRegistry(this.port);
        _keystorepw = "1234567";

       setServerKeys(id);

    }

    public void setUp() throws RemoteException {


        logger.info("Server "+SERVER_REGISTRY_NAME+" ready on port "+port);
        try {
            reg.rebind(SERVER_REGISTRY_NAME, (PWMInterface) UnicastRemoteObject.exportObject((PWMInterface) this, this.port));
        } catch (Exception e) {
            logger.error("ERROR: Failed to register the server object.");
           // e.printStackTrace();
        }

    }
    

    public static void main(String [] args) throws UnrecoverableKeyException, InterruptedException {
        Server server;
        try {
        	
        	
        	if(args.length == 1){
            	server = new Server(Integer.parseInt(args[0]));
            	server.setUp();
        	}
        	else if(args.length == 2 ){
        		server = new Server(Integer.parseInt(args[0]), Integer.parseInt(args[1]));
        		server.setUp();
        	}	
        	else{
        		logger.info("Wrong input arguments");
        		System.exit(0);;
        	}
        	
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


        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run() {
                try {
                    logger.info(SERVER_REGISTRY_NAME+" is shutting down.");
                    shutdown();
                    Thread.sleep(1);
                } catch (RemoteException e) {
                    e.printStackTrace();
                } catch (NotBoundException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

        Object lockObject=new Object();
        synchronized(lockObject){
            lockObject.wait();
        }
    }
	

    public byte[] put(byte[] msg) throws RemoteException, UserDoesNotExistException, InvalidNonceException, InvalidSignatureException, WrongUserIDException{
        /*UUID userID, byte[] domain, byte[] username, byte[] password*/
        try {
            MessageManager receivedManager = new MessageManager(msg);
            UUID userID = receivedManager.getUserID();

            Key clientKey = _userKeys.get(userID);
            
            if(clientKey == null)
            	throw new WrongUserIDException(userID);
            
            receivedManager.setPublicKey(clientKey);
            receivedManager.verifySignature();
            
            this.verifyNounce(userID, receivedManager.getNonce());

            byte[] domain = receivedManager.getContent("domain");
            byte[] username = receivedManager.getContent("username");
            byte[] password = receivedManager.getContent("password");
            Timestamp physicalTs = receivedManager.getTimestamp();
            Integer logicalTs = Integer.parseInt(new String(receivedManager.getContent("LogicalTimestamp")));


            if(_userlogin.containsKey(userID)){
                List<Login> login_list = _userlogin.get(userID);

                if(!login_list.isEmpty()){
                    for (Login l: login_list) {
                        if((Arrays.equals(l.getDomain(),domain)) && Arrays.equals(l.getUsername(),username)){

                            if(logicalTs > l.getLogicalTimestamp()) {
                                login_list.remove(l);
                                Login newLogin = new Login(username, domain, password,logicalTs, physicalTs);
                                logger.debug("Updated password on "+SERVER_REGISTRY_NAME + " for userid -> " + userID.toString() );
                                return updateLoginList(login_list,newLogin,userID,receivedManager.getNonce().toByteArray());

                            }else if(logicalTs == l.getLogicalTimestamp()){
                                if (physicalTs.after(l.getPhysicalTimestamp())){
                                    login_list.remove(l);
                                    Login newLogin = new Login(username, domain, password,logicalTs, physicalTs);
                                    logger.debug("Updated password on "+SERVER_REGISTRY_NAME + " for userid -> " + userID.toString() );

                                    return updateLoginList(login_list,newLogin,userID,receivedManager.getNonce().toByteArray());
                                }
                            }
                        }
                    }
                }
                List<Login> lList = new ArrayList<Login>(login_list);
                Login l = new Login(username, domain, password,logicalTs, physicalTs);
                logger.debug("Added password on "+SERVER_REGISTRY_NAME+" for userid -> " + userID.toString() );
                return updateLoginList(lList,l,userID,receivedManager.getNonce().toByteArray());
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

        return null;
    }


    public byte[] get(byte[] msg) throws RemoteException, InvalidSignatureException, UserDoesNotExistException, InvalidRequestException, InvalidNonceException, WrongUserIDException {
    	/*UUID userID, byte[] domain, byte[] username*/

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
                            sendManager.putPlainTextContent("TransactionID", receiveManager.getNonce().toByteArray());
                            logger.debug("Gotten password on "+SERVER_REGISTRY_NAME + " for userid -> " + userID.toString() );
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
        return null;
    }

    public byte[] getLatestTimestamp(byte[] msg) throws RemoteException,WrongUserIDException,InvalidSignatureException,InvalidNonceException {

        try {
            MessageManager receiveManager =  new MessageManager(msg);
            UUID userID = receiveManager.getUserID();
            Key clientKey = _userKeys.get(userID);
            if(clientKey == null)
                throw new WrongUserIDException(userID);

            receiveManager.setPublicKey(clientKey);
            receiveManager.verifySignature();

            this.verifyNounce(userID, receiveManager.getNonce());

            MessageManager sendManager = new MessageManager(generateNonce(),_privateKey,_publicKey);
            sendManager.putPlainTextContent("TransactionID", receiveManager.getNonce().toByteArray());
            sendManager.putPlainTextContent("LogicalTimestamp",new String(""+timestamp).getBytes());
            return sendManager.generateMessage();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }


        return new byte[0];
    }

    public byte[] register(Key publicKey) throws RemoteException, UserAlreadyExistsException {

        try {
            MessageManager sendManager = new MessageManager(generateNonce(),_privateKey,_publicKey);

            UUID user = generateUUID(publicKey.getEncoded());
            for(UUID id : _userKeys.keySet())
                if(_userKeys.get(id).equals(publicKey))
                    throw new UserAlreadyExistsException(publicKey);

            _userKeys.put(user,publicKey);
            List<Login> log = new ArrayList<Login>();
            _userlogin.put(user, log);
            logger.debug("Created user on "+SERVER_REGISTRY_NAME+" with id -> "+user+".");
            sendManager.putPlainTextContent("TransactionID", sendManager.getNonce().toByteArray());
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
        return null;
    }

	public static void shutdown() throws RemoteException, NotBoundException {
	    reg.unbind(SERVER_REGISTRY_NAME);
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
        return null;
    }


    private UUID generateUUID(byte[] bytes){
        return UUID.nameUUIDFromBytes(bytes);
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
	
	public void setServerKeys(int id) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException{
		
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());


        // get user password and file input stream
        char[] password = _keystorepw.toCharArray();
        
        String path_to_keystore = "./src/main/resources/keystore" + id + ".jks";

        keystore.load(new FileInputStream(path_to_keystore), password);
        _privateKey = (PrivateKey) keystore.getKey(KEY_NAME,_keystorepw.toCharArray());
        _publicKey = keystore.getCertificate(KEY_NAME).getPublicKey();
        SERVER_REGISTRY_NAME = "PWMServer"+id;
        
	}

	private byte[] updateLoginList(List<Login> login_list,Login l,UUID userID,byte[] receivedNonce) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException, SignatureException, ClassNotFoundException {
        MessageManager sendManager = new MessageManager(generateNonce(),_privateKey,_publicKey);
        login_list.add(l);
        _userlogin.put(userID, login_list);
        sendManager.putPlainTextContent("Status", "ACK".getBytes());
        sendManager.putPlainTextContent("TransactionID", receivedNonce);
        updateLogicalTimestamp(l.getLogicalTimestamp());
        return sendManager.generateMessage();
    }

    private static void updateLogicalTimestamp( Integer logicalTs){
	    //updates to the latest timestamp
	    timestamp = timestamp < logicalTs ? logicalTs :timestamp;
    }

}
