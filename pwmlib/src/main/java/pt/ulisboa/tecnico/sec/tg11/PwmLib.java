package pt.ulisboa.tecnico.sec.tg11;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.Message;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.PWMInterface;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.print.DocFlavor;
import java.io.IOException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.UUID;

/**
 * Created by trosado on 01/03/17.
 */
public class PwmLib {
    private final String CLIENT_PUBLIC_KEY = "privatekey";
    private char[] ksPassword;
    private KeyStore ks = null;
    private UUID userID = null;
    private PWMInterface server = null;
    private Key publicKey;



    public void init(KeyStore ks,char[] password) throws RemoteException, NotBoundException, KeyStoreException {
        /*Specification: initializes the library before its first use.
        This method should receive a reference to a key store that must contain the private and public key
        of the user, as well as any other parameters needed to access this key store (e.g., its password)
        and to correctly initialize the cryptographic primitives used at the client side.
        These keys maintained by the key store will be the ones used in the following session of commands
        issued at the client side, until a close() function is called.
        */
        this.ks = ks;
        this.ksPassword = password;
        this.publicKey = ks.getCertificate(CLIENT_PUBLIC_KEY).getPublicKey();
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        server = (PWMInterface) registry.lookup("PWMServer");
    }

    public UUID register_user() throws UserAlreadyExistsException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, RemoteException {
        /*Specification: registers the user on the server, initializing the required data structures to
        securely store the passwords.*/
        //System.out.println("register_user -> client_public_key: " + ks.getKey(CLIENT_PUBLIC_KEY,ksPassword));
        this.userID = server.register(ks.getCertificate(CLIENT_PUBLIC_KEY).getPublicKey());
        return userID;
    }

    public void save_password (UUID userID, byte[] domain, byte[] username, byte[] password) throws RemoteException, UserDoesNotExistException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        /*Specification: stores the triple (domain, username, password) on the server. This corresponds
        to an insertion if the (domain, username) pair is not already known by the server, or to an update otherwise.
        */

        //System.out.println("save_password -> UserID: " + userID);
        //System.out.println("save_password -> domain: " + new String(domain));
    	Message m = new Message();
        m.addContent("domain", domain, publicKey);
    	m.addContent("username", username, publicKey);
    	m.addContent("password", password, publicKey);
        server.put(userID ,domain,username,password);
    }


    public byte[] retrieve_password(UUID userID, byte[] domain, byte[] username) throws RemoteException, UserDoesNotExistException, PasswordDoesNotExistException {
        /*Specification: retrieves the password associated with the given (domain, username) pair. The behavior of
        what should happen if the (domain, username) pair does not exist is unspecified
        */

        return server.get(userID,domain,username);

    }

    public void close(){
        /*  concludes the current session of commands with the client library. */

    }

}
