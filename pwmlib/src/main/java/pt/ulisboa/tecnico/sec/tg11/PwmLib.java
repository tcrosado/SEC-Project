package pt.ulisboa.tecnico.sec.tg11;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.AESMessageManager;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.RSAMessageManager;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.PWMInterface;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.UUID;

/**
 * Created by trosado on 01/03/17.
 */
public class PwmLib {
    private final String CLIENT_PUBLIC_KEY = "privatekey";
    private static final String PATH_TO_KEYSTORE = "./src/main/resources/keystore.jks";
    private static final String PATH_TO_SERVER_CERT = "./src/main/resources/server.cer";
    private char[] _ksPassword;
    private KeyStore _ks = null;
    private UUID _userID = null;
    private PWMInterface _server = null;
    private PublicKey _publicKey;
    private PrivateKey _privateKey;
    public PublicKey _serverKey;
   // private Key _sessionKey;
    


    public void init(KeyStore ks,char[] password) throws RemoteException, NotBoundException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, FileNotFoundException {
        /*Specification: initializes the library before its first use.
        This method should receive a reference to a key store that must contain the private and public key
        of the user, as well as any other parameters needed to access this key store (e.g., its password)
        and to correctly initialize the cryptographic primitives used at the client side.
        These keys maintained by the key store will be the ones used in the following session of commands
        issued at the client side, until a close() function is called.
        */
    	
    	FileInputStream fin = new FileInputStream(PATH_TO_SERVER_CERT);
    	CertificateFactory f = CertificateFactory.getInstance("X.509");
    	X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
    	
    	_serverKey = certificate.getPublicKey();
    	
        this._ks = ks;
        this._ksPassword = password;
        this._publicKey = ks.getCertificate(CLIENT_PUBLIC_KEY).getPublicKey();
        this._privateKey = (PrivateKey) ks.getKey(CLIENT_PUBLIC_KEY, this._ksPassword);
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        _server = (PWMInterface) registry.lookup("PWMServer");
        
    }

    public UUID register_user() throws UserAlreadyExistsException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, SignatureException, IOException, ClassNotFoundException, InvalidSignatureException, UserDoesNotExistException {
        /*Specification: registers the user on the _server, initializing the required data structures to
        securely store the passwords.*/
     
        this._userID = _server.register(_publicKey);
        //this.generateAndSendSessionKey();
        return _userID;
    }

    public void save_password (UUID userID, byte[] domain, byte[] username, byte[] password) throws UserDoesNotExistException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, InvalidAlgorithmParameterException, ClassNotFoundException {
        /*Specification: stores the triple (domain, username, password) on the _server. This corresponds
        to an insertion if the (domain, username) pair is not already known by the _server, or to an update otherwise.
        */

        RSAMessageManager content = new RSAMessageManager(_userID, _privateKey);
        content.putContent("domain",domain);
        content.putContent("username",username);
        content.putContent("password",password);

        _server.put(content.generateMessage());
    }


    public byte[] retrieve_password(UUID userID, byte[] domain, byte[] username) throws UserDoesNotExistException, PasswordDoesNotExistException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, SignatureException, IOException, InvalidAlgorithmParameterException, ClassNotFoundException {
        /*Specification: retrieves the password associated with the given (domain, username) pair. The behavior of
        what should happen if the (domain, username) pair does not exist is unspecified
        */
    	
    	RSAMessageManager content = new RSAMessageManager(_userID, _privateKey);
    	content.putContent("domain", domain);
    	content.putContent("username", username);
    	
        return _server.get(content.generateMessage());

    }
    
    /*private void setSessionKey(Key k){
    	_sessionKey = k;
    }
    
    private void generateAndSendSessionKey() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, SignatureException, IOException, ClassNotFoundException, InvalidSignatureException, UserDoesNotExistException{
    	
    	KeyGenerator kgen = KeyGenerator.getInstance("AES");
    	kgen.init(128);
    	
    	_sessionKey = kgen.generateKey();
    	
    	RSAMessageManager msg = new RSAMessageManager(_userID, _privateKey, _publicKey, _serverKey);
    	msg.putContent("sessionKey", _sessionKey.getEncoded());
    	msg.putContent("_userID", getIdAsByte(msg.getUserID()));
    	
    	_server.receiveSessionKey(msg.generateMessage());
    }
    
    public byte[] getIdAsByte(UUID uuid)
    {
        ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
        bb.putLong(uuid.getMostSignificantBits());
        bb.putLong(uuid.getLeastSignificantBits());
        return bb.array();
    }*/

    public void close(){
        /*  concludes the current session of commands with the client library. */
    	//System.exit(0);

    }

}
