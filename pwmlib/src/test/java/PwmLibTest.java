import org.junit.*;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.MessageManager;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.PWMInterface;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.*;
import pt.ulisboa.tecnico.sec.tg11.PwmLib;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static org.hamcrest.CoreMatchers.instanceOf;

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
import java.util.UUID;

/**
 * Created by trosado on 01/03/17.
 */
public class PwmLibTest {

    private static final String PATH_TO_RSAKEYSTORE = "./src/main/resources/keystore.jks";
    private static final String CLIENT_PUBLIC_KEY = "privatekey";
    private static KeyStore _keystore;
    private static PwmLib _pwmlib;
    private static String _keystorepw;
    private static UUID _userID;
    private static Key _privateKey;
    private static Key _publicKey;
    private static PWMInterface _server;
    @BeforeClass
    public static void setUp() throws Exception {

        /* http://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html */
    	
    	
        _keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        _keystorepw = "1234567";

        // get user password and file input stream
        char[] password = _keystorepw.toCharArray();

        _keystore.load(new FileInputStream(PATH_TO_RSAKEYSTORE), password);

        _pwmlib = new PwmLib();
        _pwmlib.init(_keystore,password);

        _userID = _pwmlib.register_user();
        _privateKey = (PrivateKey) _keystore.getKey(CLIENT_PUBLIC_KEY, password);
        _publicKey = _keystore.getCertificate(CLIENT_PUBLIC_KEY).getPublicKey();
        
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        _server = (PWMInterface) registry.lookup("PWMServer");
       
    }

    @AfterClass
    public static void tearDown() throws Exception {
        _pwmlib.close();
    }


    @Test
    public void save_password() throws UserDoesNotExistException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, SignatureException, IOException, InvalidAlgorithmParameterException, ClassNotFoundException, InvalidNonceException, InvalidSignatureException {
        String domain = "www.google.pt";
        String username = "testUser";
        String password = "testPass";

        _pwmlib.save_password(_userID,domain.getBytes(),username.getBytes(),password.getBytes());
    }

    @Test
    public void retrieve_password() throws UserDoesNotExistException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, SignatureException, IOException, InvalidAlgorithmParameterException, ClassNotFoundException, InvalidNonceException, InvalidSignatureException, InvalidRequestException {
        String domain = "www.google.pt";
        String username = "testUser";
        String password = "testPass";
        byte [] pw = _pwmlib.retrieve_password(_userID,domain.getBytes(), username.getBytes());
        BigInteger nonce =_server.requestNonce(_userID);
        MessageManager eminem = new MessageManager(nonce,_userID, _privateKey, _publicKey);
        byte[] result = eminem.getDecypheredMessage(pw);

        Assert.assertArrayEquals(password.getBytes(),result);
    }

    @Test
    public void retrive_altered_password() throws UserDoesNotExistException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, SignatureException, IOException, InvalidAlgorithmParameterException, ClassNotFoundException, InvalidNonceException, InvalidSignatureException, InvalidRequestException {
        String domain = "www.google.pt";
        String username = "testUser";
        String password = "testPass";
        _pwmlib.save_password(_userID,domain.getBytes(),username.getBytes(),password.getBytes());
        
        String password2 = "testPass2";
        _pwmlib.save_password(_userID,domain.getBytes(),username.getBytes(),password2.getBytes());
        
        byte [] pw = _pwmlib.retrieve_password(_userID,domain.getBytes(), username.getBytes());
        BigInteger nonce =_server.requestNonce(_userID);
        MessageManager eminem = new MessageManager(nonce,_userID, _privateKey, _publicKey);
        byte[] result = eminem.getDecypheredMessage(pw);
        
        Assert.assertArrayEquals(password2.getBytes(),result);
    }
    
    @Test(expected = InvalidRequestException.class)
    public void unexisting_pass() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, SignatureException, InvalidAlgorithmParameterException, ClassNotFoundException, UserDoesNotExistException, InvalidRequestException, IOException, InvalidNonceException{
    	
    	String domain = "www.google.pt";
    	String username = "juanito";
    	
    	_pwmlib.retrieve_password(_userID, domain.getBytes(), username.getBytes());
    	
    }
    
    @Test(expected = UserAlreadyExistsException.class)
    public void wrong_register() throws UnrecoverableKeyException, InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, SignatureException, ClassNotFoundException, UserAlreadyExistsException, IOException, InvalidSignatureException, UserDoesNotExistException{
    	_pwmlib.register_user();
    }
}