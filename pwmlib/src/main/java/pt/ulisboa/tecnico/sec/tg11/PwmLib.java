package pt.ulisboa.tecnico.sec.tg11;


import pt.tecnico.ulisboa.sec.tg11.SharedResources.MessageManager;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.PWMInterface;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.rmi.ConnectException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.*;
import java.sql.Timestamp;
import java.util.concurrent.*;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Created by trosado on 01/03/17.
 */
public class PwmLib {

    private final int REPLICAS = 4;
    private final String CLIENT_PUBLIC_KEY = "privatekey";

    private static final String PATH_TO_KEYSTORE = "./src/main/resources/keystore.jks";
    private static final String PATH_TO_SERVER_CERT = "./src/main/resources/server1.cer";

    private char[] _ksPassword;
    private KeyStore _ks = null;
    private UUID _userID = null;
    private PublicKey _publicKey;
    private PrivateKey _privateKey;

    private static ConcurrentHashMap<String,Thread> _threadList = null;
    private AbstractMap<String,Key> _serverKey;
    


    public void init(KeyStore ks,char[] password) throws RemoteException, NotBoundException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, FileNotFoundException {
        /*Specification: initializes the library before its first use.
        This method should receive a reference to a key store that must contain the private and public key
        of the user, as well as any other parameters needed to access this key store (e.g., its password)
        and to correctly initialize the cryptographic primitives used at the client side.
        These keys maintained by the key store will be the ones used in the following session of commands
        issued at the client side, until a close() function is called.
        */
    	
    	this._ks = ks;
        this._ksPassword = password;
        this._publicKey = ks.getCertificate(CLIENT_PUBLIC_KEY).getPublicKey();
        this._privateKey = (PrivateKey) ks.getKey(CLIENT_PUBLIC_KEY, this._ksPassword);
        //System.out.println("A CHAVE SIMETRICA É: "+Base64.getEncoder().encodeToString(_symmetricKey.getEncoded()));

        this._threadList = new ConcurrentHashMap<String, Thread>();
        this._serverKey = new HashMap<String, Key>();


        for(int i=1;i<=REPLICAS;i++){
            String serverName = "PWMServer"+i;
            _serverKey.put(serverName,getCertificate(i));
        }

        
    }

    private PWMInterface getServer(Integer i) {

        try {
            Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099+i);
            String serverName = "PWMServer"+i;
         return (PWMInterface) registry.lookup(serverName);
        } catch (ConnectException e){
            e.printStackTrace();
        } catch (RemoteException e) {
            e.printStackTrace();
        } catch (NotBoundException e) {
            e.printStackTrace();
        }
        return null;


    }

    public UUID register_user() throws Throwable { //FIXME change if not working
        /*Specification: registers the user on the _serverManager, initializing the required data structures to
        securely store the passwords.*/

        ExecutorService pool = Executors.newFixedThreadPool(REPLICAS);
        ExecutorCompletionService executor = new ExecutorCompletionService(pool);
        
        //LANCAR PEDIDOS
        for(int i=1;i<=REPLICAS;i++){
            final Integer in = i;
            final String serverName = "PWMServer"+i;
        executor.submit(() -> {
            AbstractMap<Timestamp,UUID> uuidHashMap = new HashMap<Timestamp,UUID>();
            PWMInterface server = getServer(in);
            
            if(server == null)
                return uuidHashMap;
            
            byte[] result = new byte[0];
            MessageManager receiveManager = null;
            
            
            result = server.register(_publicKey);
            receiveManager = verifySignature(serverName,result);
            uuidHashMap.put(receiveManager.getTimestamp()
                    ,UUID.fromString(new String(receiveManager.getContent("UUID"))));
            

            return uuidHashMap;
        });

        }
        
        //ESPERA E ARMAZENA RESPOSTAS
        TreeMap<Timestamp,UUID> tree = new TreeMap<>();
        Map<String, List<Throwable>> exceptions = new HashMap<String, List<Throwable>>();
        int neededAnswers = REPLICAS-1;
        for(int i=0;i<REPLICAS;i++){
            try {
            	            	
                Future<AbstractMap> result = executor.take();
                AbstractMap<Timestamp,UUID> temp = result.get();
                
                for(Timestamp ts : temp.keySet()){
                    tree.put(ts,temp.get(ts));
                }
            } catch (ExecutionException e) {
            	
            	Throwable ex = e.getCause() == null ? e : e.getCause();
                
            	String exceptionName = ex.getClass().getCanonicalName();
        		
            	if(!exceptions.containsKey(exceptionName)){
            		List<Throwable> l = new ArrayList<>();
            		l.add(ex);
            		exceptions.put(exceptionName, l);
            	}else{
            		
            		exceptions.get(exceptionName).add(ex);
            	}

            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        for(String exceptionName: exceptions.keySet()){
	        if(exceptions.get(exceptionName).size()>=neededAnswers){
	            throw exceptions.get(exceptionName).get(0);
	        }
        }
        
        if(tree.isEmpty())
            return null;
        
        return tree.lastEntry().getValue();

    }

    public void save_password (UUID userID, byte[] domain, byte[] username, byte[] password) throws Throwable {
        /*Specification: stores the triple (domain, username, password) on the _serverManager. This corresponds
        to an insertion if the (domain, username) pair is not already known by the _serverManager, or to an update otherwise.
        */
        int acks = 0;

        ExecutorService pool = Executors.newFixedThreadPool(REPLICAS);
        ExecutorCompletionService executor = new ExecutorCompletionService(pool);

        for(int i=1;i<=REPLICAS;i++){
            final Integer in = i;
            final String serverName = "PWMServer"+i;
            executor.submit(() -> {
                AbstractMap<Timestamp,String> resultHashMap = new HashMap<Timestamp,String>();
                PWMInterface server = getServer(in);
                if(server == null)
                    return "Error";
                //get nounce
                byte[] result = server.requestNonce(userID);
                MessageManager mm = verifySignature(serverName,result);
                BigInteger nonce = new BigInteger(mm.getContent("Nonce"));

                //generate and send put message
                MessageManager content = new MessageManager(nonce,userID, _privateKey, this._publicKey);
                content.putHashedContent("domain",domain);
                content.putHashedContent("username",username);
                content.putCipheredContent("password",password);
                byte[] response = server.put(content.generateMessage());

                MessageManager resp = new MessageManager(response);
                
                if(Arrays.equals(nonce.toByteArray(), resp.getContent("TransactionID")))
                	return new String(resp.getContent("Status"));
                else
                	return null;
            });
        }

        List<String> list = new ArrayList<>();
        Map<String, List<Throwable>> exceptions = new HashMap<String, List<Throwable>>();
        
        int neededAnswers = REPLICAS-1;
        for(int i=0;i<REPLICAS;i++){
            Future<String> result = executor.take();
            try {
                String resultStatus = result.get();
                if(resultStatus.equals("ACK")){
                   list.add(resultStatus);
                    if(i>=neededAnswers)
                        return;   //If it succeeds just return
                }
            } catch (ExecutionException e) {
            	
            	Throwable ex = e.getCause() == null ? e : e.getCause();
               
            	String exceptionName = ex.getClass().getCanonicalName();
        		
            	if(!exceptions.containsKey(exceptionName)){
            		List<Throwable> l = new ArrayList<>();
            		l.add(ex);
            		exceptions.put(exceptionName, l);
            	}else{
            		
            		exceptions.get(exceptionName).add(ex);
            	}
                		
                
            }
        }
        
        for(String exceptionName: exceptions.keySet()){
	        if(exceptions.get(exceptionName).size()>=neededAnswers){
	            throw exceptions.get(exceptionName).get(0);
	        }
        }
        
        throw new ActionFailedException();

    }


    public byte[] retrieve_password(UUID userID, byte[] domain, byte[] username) throws Throwable {
        /*Specification: retrieves the password associated with the given (domain, username) pair. The behavior of
        what should happen if the (domain, username) pair does not exist is unspecified
        */

        ExecutorService pool = Executors.newFixedThreadPool(REPLICAS);
        ExecutorCompletionService executor = new ExecutorCompletionService(pool);

        for(int i=1;i<=REPLICAS;i++){
            final Integer in = i;
            final String serverName = "PWMServer"+i;
            executor.submit(() -> {

                AbstractMap<Timestamp,byte[]> pwHashMap = new HashMap<Timestamp,byte[]>();
                PWMInterface server = getServer(in);
                
                if(server == null)
                    return pwHashMap;
                //get nounce
                byte[] result = server.requestNonce(userID);
                MessageManager mm = verifySignature(serverName, result);
                BigInteger nonce = new BigInteger(mm.getContent("Nonce"));

                //generate and send get message
                MessageManager content = new MessageManager(nonce, userID, _privateKey, this._publicKey);
                content.putHashedContent("domain", domain);
                content.putHashedContent("username", username);
                byte[] passMsg = server.get(content.generateMessage());
                MessageManager receiveManager = verifySignature(serverName, passMsg);
                
                //VERIFICA NONCE DO SERVER PARA PREVENIR MAN-IN-THE-MIDDLE SERVER-CLI
                if(Arrays.equals(nonce.toByteArray(), receiveManager.getContent("TransactionID")))
                    pwHashMap.put(receiveManager.getTimestamp(),receiveManager.getDecypheredContent("Password"));
                
                return pwHashMap;
            });

        }

        TreeMap<Timestamp,byte[]> tree = new TreeMap<>();
        Map<String, List<Throwable>> exceptions = new HashMap<String, List<Throwable>>();
        int neededAnswers = REPLICAS-1;
        for(int i=0;i<REPLICAS;i++){
            try {
                Future<AbstractMap> result = executor.take();
                AbstractMap<Timestamp,byte[]> temp = result.get();
                for(Timestamp ts : temp.keySet()){
                	tree.put(ts,temp.get(ts));
                }
            } catch (ExecutionException e) {
            	Throwable ex = e.getCause() == null ? e : e.getCause();
                
            	String exceptionName = ex.getClass().getCanonicalName();
        		
            	if(!exceptions.containsKey(exceptionName)){
            		List<Throwable> l = new ArrayList<>();
            		l.add(ex);
            		exceptions.put(exceptionName, l);
            	}else{
            		
            		exceptions.get(exceptionName).add(ex);
            	}
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        for(String exceptionName: exceptions.keySet()){
	        if(exceptions.get(exceptionName).size()>=neededAnswers){
	            throw exceptions.get(exceptionName).get(0);
	        }
        }

        if(tree.isEmpty())
            return null;
        
        	
        
        //atomic part
        
        byte[] received_pass = tree.lastEntry().getValue();
        this.save_password(userID, domain, username, received_pass);
        
        return received_pass;
    }

    public void close(){
        /*  concludes the current session of commands with the client library. */
    	//System.exit(0);

    }

    private Key getCertificate(int i) throws FileNotFoundException, CertificateException {
        String path = "./src/main/resources/server"+i+".cer";
        FileInputStream fin = new FileInputStream(path);
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
        return certificate.getPublicKey();
    }
    private MessageManager verifySignature(String serverName,byte[] msg) throws InvalidSignatureException {
        MessageManager mm = null;
        try {
            mm = new MessageManager(msg,_privateKey);
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
        } catch (InvalidSignatureException e) {
            e.printStackTrace();
        }
        mm.setPublicKey((Key) _serverKey.get(serverName));
        try {
            mm.verifySignature();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return mm;
    }

}
