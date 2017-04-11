package pt.ulisboa.tecnico.sec.tg11;


import pt.tecnico.ulisboa.sec.tg11.SharedResources.MessageManager;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.UUID;

/**
 * Created by trosado on 01/03/17.
 */
public class PwmLib {
    private final String CLIENT_PUBLIC_KEY = "privatekey";
    private static final String PATH_TO_KEYSTORE = "./src/main/resources/keystore.jks";

    private char[] _ksPassword;
    private KeyStore _ks = null;
    private UUID _userID = null;
    private PublicKey _publicKey;
    private PrivateKey _privateKey;
    private ServerManager _serverManager;

    


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
        this._serverManager = new ServerManager();
        
    }

    public UUID register_user() throws UserAlreadyExistsException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, SignatureException, IOException, ClassNotFoundException, InvalidSignatureException, UserDoesNotExistException {
        /*Specification: registers the user on the _serverManager, initializing the required data structures to
        securely store the passwords.*/
        byte[] result = _serverManager.register(_publicKey);
        MessageManager receiveManager = verifySignature(result);
        this._userID = UUID.fromString(new String(receiveManager.getContent("UUID")));
        return _userID;
    }

    public void save_password (UUID userID, byte[] domain, byte[] username, byte[] password) throws UserDoesNotExistException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, InvalidAlgorithmParameterException, ClassNotFoundException, InvalidNonceException, InvalidSignatureException, WrongUserIDException {
        /*Specification: stores the triple (domain, username, password) on the _serverManager. This corresponds
        to an insertion if the (domain, username) pair is not already known by the _serverManager, or to an update otherwise.
        */

        byte[] result = _serverManager.requestNonce(userID);
        MessageManager mm = verifySignature(result);
    	BigInteger nonce = new BigInteger(mm.getContent("Nonce"));
        MessageManager content = new MessageManager(nonce,userID, _privateKey, this._publicKey);
        content.putHashedContent("domain",domain);
        content.putHashedContent("username",username);
        content.putCipheredContent("password",password);

        result = _serverManager.put(content.generateMessage());
        mm = verifySignature(result);
        if(!mm.getContent("Status").equals("ACK")){

        }
    }


    public byte[] retrieve_password(UUID userID, byte[] domain, byte[] username) throws UserDoesNotExistException, InvalidRequestException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, SignatureException, IOException, InvalidAlgorithmParameterException, ClassNotFoundException, InvalidNonceException, WrongUserIDException, InvalidSignatureException {
        /*Specification: retrieves the password associated with the given (domain, username) pair. The behavior of
        what should happen if the (domain, username) pair does not exist is unspecified
        */

        byte[] result = _serverManager.requestNonce(userID);
        MessageManager mm = verifySignature(result);
        BigInteger nonce = new BigInteger(mm.getContent("Nonce"));
    	MessageManager content = new MessageManager(nonce,userID, _privateKey,this._publicKey);
    	content.putHashedContent("domain", domain);
    	content.putHashedContent("username", username);
    	
        byte[] passMsg = _serverManager.get(content.generateMessage());
        MessageManager receiveManager = verifySignature(passMsg);
        return receiveManager.getContent("Password");

    }

    public void close(){
        /*  concludes the current session of commands with the client library. */
    	//System.exit(0);

    }


}
