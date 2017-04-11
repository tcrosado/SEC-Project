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
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Created by trosado on 11/04/17.
 */
public class ServerManager implements PWMInterface{
    private final int REPLICAS = 4;
    private static final String PATH_TO_SERVER_CERT = "./src/main/resources/server.cer";

    private AbstractMap<String,PWMInterface> _serverList = null;
    private AbstractMap<String,Key> _serverKey;

    public ServerManager() throws FileNotFoundException, CertificateException, RemoteException, NotBoundException {

        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        this._serverList = new HashMap<String, PWMInterface>();
        this._serverKey = new HashMap<String, Key>();

        for(int i=1;i<=REPLICAS;i++){
            String serverName = "PWMServer"+i;
            _serverKey.put(serverName,getCertificate(i));
            _serverList.put(serverName,(PWMInterface) registry.lookup(serverName));
        }
    }


    public byte[] register(Key key) throws RemoteException, UserAlreadyExistsException {

        


        return new byte[0];
    }

    public byte[] requestNonce(UUID uuid) throws RemoteException {
        return new byte[0];
    }

    public byte[] put(byte[] bytes) throws RemoteException, UserDoesNotExistException, InvalidNonceException, InvalidSignatureException, WrongUserIDException {
        return new byte[0];
    }

    public byte[] get(byte[] bytes) throws RemoteException, UserDoesNotExistException, InvalidRequestException, InvalidNonceException, WrongUserIDException, InvalidSignatureException {
        return new byte[0];
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
        mm.setPublicKey((Key) _serverList.get(serverName));
        mm.verifySignature();
        return mm;
    }
}
