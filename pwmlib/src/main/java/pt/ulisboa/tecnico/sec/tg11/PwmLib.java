package pt.ulisboa.tecnico.sec.tg11;

import pt.tecnico.ulisboa.sec.tg11.PWInterface.PWMInterface;
import pt.tecnico.ulisboa.sec.tg11.PWInterface.exceptions.*;
import pt.tecnico.ulisboa.sec.tg11.PWInterface.exceptions.PasswordDoesNotExistException;
import pt.tecnico.ulisboa.sec.tg11.PWInterface.exceptions.UserAlreadyExistsException;
import pt.tecnico.ulisboa.sec.tg11.PWInterface.exceptions.UserDoesNotExistException;

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
    private final String CLIENT_PUBLIC_KEY = "CLIENT_PUBLIC_KEY";
    private char[] ksPassword;
    private KeyStore ks = null;
    private UUID userID = null;
    private PWMInterface server = null;


    public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, NotBoundException, UserAlreadyExistsException, PasswordDoesNotExistException,  KeyStoreException, UserDoesNotExistException {
        test();

    }

    public static void test() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, NotBoundException, UserAlreadyExistsException, UserDoesNotExistException, PasswordDoesNotExistException, UnrecoverableKeyException {
        PwmLib _pwmlib = new PwmLib();
        KeyStore _keystore;
        String _keystorepw;
        UUID _userID;

        _keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        _keystorepw = "example";

        // get user password and file input stream
        char[] _password = _keystorepw.toCharArray();

        _keystore.load(null, _password);

        _pwmlib.init(_keystore, _keystorepw.toCharArray());

        _userID = _pwmlib.register_user();

        String domain = "www.google.pt";
        String username = "testUser";
        String password = "testPass";
        String password2 = "testPass2";

        //System.out.println("Teste main -> UserID: " + _userID);
        _pwmlib.save_password(_userID,domain.getBytes(),username.getBytes(),password.getBytes());
        byte [] pw = _pwmlib.retrieve_password(_userID,domain.getBytes(), username.getBytes());
        //System.out.println("Teste main -> PasswordObtida: " + new String(pw));

        _pwmlib.save_password(_userID,domain.getBytes(),username.getBytes(),password2.getBytes());
        pw = _pwmlib.retrieve_password(_userID,domain.getBytes(), username.getBytes());
        //System.out.println("Teste main -> PasswordObtida2: " + new String(pw));
    }


    public void init(KeyStore ks,char[] password) throws RemoteException, NotBoundException {
        /*Specification: initializes the library before its first use.
        This method should receive a reference to a key store that must contain the private and public key
        of the user, as well as any other parameters needed to access this key store (e.g., its password)
        and to correctly initialize the cryptographic primitives used at the client side.
        These keys maintained by the key store will be the ones used in the following session of commands
        issued at the client side, until a close() function is called.
        */
        this.ks = ks;
        this.ksPassword = password;
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        server = (PWMInterface) registry.lookup("PWMServer");
    }

    public UUID register_user() throws UserAlreadyExistsException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, RemoteException {
        /*Specification: registers the user on the server, initializing the required data structures to
        securely store the passwords.*/
        //System.out.println("register_user -> client_public_key: " + ks.getKey(CLIENT_PUBLIC_KEY,ksPassword));
        this.userID = server.register(ks.getKey(CLIENT_PUBLIC_KEY,ksPassword));
        return userID;
    }

    public void save_password (UUID userID, byte[] domain, byte[] username, byte[] password) throws  RemoteException, UserDoesNotExistException {
        /*Specification: stores the triple (domain, username, password) on the server. This corresponds
        to an insertion if the (domain, username) pair is not already known by the server, or to an update otherwise.
        */

        //System.out.println("save_password -> UserID: " + userID);
        //System.out.println("save_password -> domain: " + new String(domain));
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
