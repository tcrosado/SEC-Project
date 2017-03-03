package pt.ulisboa.tecnico.sec.tg11;

import javax.print.DocFlavor;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.*;
import java.util.UUID;

/**
 * Created by trosado on 01/03/17.
 */
public class PwmLib {
    private final String CLIENT_PUBLIC_KEY = "CLIENT_PUBLIC_KEY";
    private char[] ksPassword;
    private KeyStore ks = null;
    private UUID userID = null;
    private ServerInterface server = null;


    public static void main(String[] args){



    }


    public void init(KeyStore ks,char[] password) {
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
        server = (ServerInterface) registry.lookup("PWMServer");
    }

    public UUID register_user(){
        /*Specification: registers the user on the server, initializing the required data structures to
        securely store the passwords.*/
        try {
            this.userID = server.register(ks.getKey(CLIENT_PUBLIC_KEY,ksPassword));
            return userID;
        } catch (RemoteException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }
    }

    public void save_password (byte[] domain, byte[] username, byte[] password){
        /*Specification: stores the triple (domain, username, password) on the server. This corresponds
        to an insertion if the (domain, username) pair is not already known by the server, or to an update otherwise.
        */

        try {
            server.put(ks.getKey(CLIENT_PUBLIC_KEY,ksPassword),domain,username,password);
        } catch (RemoteException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }


    }


    public byte[] retrieve_password(byte[] domain, byte[] username){
        /*Specification: retrieves the password associated with the given (domain, username) pair. The behavior of
        what should happen if the (domain, username) pair does not exist is unspecified
        */

        try {
            return server.get(ks.getKey(CLIENT_PUBLIC_KEY,this.ksPassword),domain,username);
        } catch (RemoteException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }
    }

    public void close(){
        /*  concludes the current session of commands with the client library. */

    }

}
