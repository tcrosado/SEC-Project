package pt.ulisboa.tecnico.sec.tg11;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.*;

/**
 * Created by trosado on 01/03/17.
 */
public class PwmLib {
    private KeyStore ks;



    public static void main(String[] args){



        String text = "RMI Test Message";
        ServerInterface server = null;

        try {



            Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
            server = (ServerInterface) registry.lookup("PWMServer");
            System.out.println("Connected to Server");
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (server != null) {
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
                keyGen.initialize(1024, random);

                KeyPair keypair = keyGen.genKeyPair();

                server.put(keypair.getPublic(),new byte[],new byte[0],new byte[0]);

            } catch (RemoteException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            }
            System.out.println("Finished");
        }
    }

    public String test(){


        return "This";
    }



    public void init(KeyStore ks) {
        /*Specification: initializes the library before its first use.
        This method should receive a reference to a key store that must contain the private and public key
        of the user, as well as any other parameters needed to access this key store (e.g., its password)
        and to correctly initialize the cryptographic primitives used at the client side.
        These keys maintained by the key store will be the ones used in the following session of commands
        issued at the client side, until a close() function is called.
        */

    }

    public void register_user(){
        /*Specification: registers the user on the server, initializing the required data structures to
        securely store the passwords.*/

    }

    public void save_password (byte[] domain, byte[] username, byte[] password){
        /*Specification: stores the triple (domain, username, password) on the server. This corresponds
        to an insertion if the (domain, username) pair is not already known by the server, or to an update otherwise.
        */
    }


    public byte[] retrieve_password(byte[] domain, byte[] username){
        /*Specification: retrieves the password associated with the given (domain, username) pair. The behavior of
        what should happen if the (domain, username) pair does not exist is unspecified
        */

        byte [] example = new byte[10];

        return example;
    }

    public void close(){
        /*  concludes the current session of commands with the client library. */

    }

}
