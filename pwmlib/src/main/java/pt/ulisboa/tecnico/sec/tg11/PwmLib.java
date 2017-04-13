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
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.HashMap;
import java.util.UUID;

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

    private AbstractMap<String,PWMInterface> _serverList = null;
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

        this._serverList = new HashMap<String, PWMInterface>();
        this._serverKey = new HashMap<String, Key>();


        for(int i=1;i<=REPLICAS;i++){
            Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099+i);
            String serverName = "PWMServer"+i;
            _serverKey.put(serverName,getCertificate(i));
            _serverList.put(serverName,(PWMInterface) registry.lookup(serverName));
        }
        
    }

    public UUID register_user() throws UserAlreadyExistsException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, SignatureException, IOException, ClassNotFoundException, InvalidSignatureException, UserDoesNotExistException {
        /*Specification: registers the user on the _serverManager, initializing the required data structures to
        securely store the passwords.*/
        UUID firstUID = null;
        for(String serverName: _serverList.keySet()){
            PWMInterface server = _serverList.get(serverName);
            byte[] result = server.register(_publicKey);
            MessageManager receiveManager = verifySignature(serverName,result);
            UUID user  = UUID.fromString(new String(receiveManager.getContent("UUID")));
            if(firstUID != null)
                if(firstUID != user){
                    System.out.println("abort");
                    return null;
                }
                else
                    firstUID = user;
        }

        return firstUID;

    }

    public void save_password (UUID userID, byte[] domain, byte[] username, byte[] password) throws UserDoesNotExistException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, InvalidAlgorithmParameterException, ClassNotFoundException, InvalidNonceException, InvalidSignatureException, WrongUserIDException {
        /*Specification: stores the triple (domain, username, password) on the _serverManager. This corresponds
        to an insertion if the (domain, username) pair is not already known by the _serverManager, or to an update otherwise.
        */
        int acks = 0;

        for(String serverName: _serverList.keySet()) {
            PWMInterface server = _serverList.get(serverName);

            //get nounce
            byte[] result = server.requestNonce(userID);
            MessageManager mm = verifySignature(serverName,result);
            BigInteger nonce = new BigInteger(mm.getContent("Nonce"));

            //generate and send put message
            MessageManager content = new MessageManager(nonce,userID, _privateKey, this._publicKey);
            content.putHashedContent("domain",domain);
            content.putHashedContent("username",username);
            content.putCipheredContent("password",password);
            result = server.put(content.generateMessage());

            //verify signature of response
            mm = verifySignature(serverName,result);

            if(!mm.getContent("Status").equals("ACK")){
                //FIXME fazer reverse -> nao deu ACK

            }
            ++acks;
        }

        if(acks < REPLICAS/2){
            //FIXME fazer reverse -> nao deu ACKs suficientes

        }

    }


    public byte[] retrieve_password(UUID userID, byte[] domain, byte[] username) throws UserDoesNotExistException, InvalidRequestException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, SignatureException, IOException, InvalidAlgorithmParameterException, ClassNotFoundException, InvalidNonceException, WrongUserIDException, InvalidSignatureException {
        /*Specification: retrieves the password associated with the given (domain, username) pair. The behavior of
        what should happen if the (domain, username) pair does not exist is unspecified
        */
        byte[] firstPassword = null;
        for(String serverName: _serverList.keySet()) {
            PWMInterface server = _serverList.get(serverName);
            byte[] result = server.requestNonce(userID);
            MessageManager mm = verifySignature(serverName,result);
            BigInteger nonce = new BigInteger(mm.getContent("Nonce"));
            MessageManager content = new MessageManager(nonce,userID, _privateKey,this._publicKey);
            content.putHashedContent("domain", domain);
            content.putHashedContent("username", username);
            byte[] passMsg = server.get(content.generateMessage());
            MessageManager receiveManager = verifySignature(serverName,passMsg);

            if(firstPassword != null){
                byte[] receivedPassword = receiveManager.getContent("Password");
                if(!Arrays.equals(firstPassword,receivedPassword)){
                    System.out.print("Abort");
                    return new byte[0];
                }
            }
            else
                firstPassword = receiveManager.getContent("Password");
        }

        return firstPassword;

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
    private MessageManager verifySignature(String serverName,byte[] msg) throws BadPaddingException, ClassNotFoundException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, SignatureException, InvalidKeyException, InvalidSignatureException, NoSuchPaddingException {
        MessageManager mm = new MessageManager(msg);
        mm.setPublicKey((Key) _serverKey.get(serverName));
        mm.verifySignature();
        return mm;
    }


}
