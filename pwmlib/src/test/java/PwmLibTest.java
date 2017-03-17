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
    private static final String PATH_TO_RSAKEYSTORE2 = "./src/main/resources/user2.jks";
    private static final String CLIENT_PUBLIC_KEY = "privatekey";
    private static KeyStore _keystore;
    private static PwmLib _pwmlib;
    private static String _keystorepw;
    private static UUID _userID;
    private static Key _privateKey;
    private static Key _publicKey;
    private static PWMInterface _server;
    private static UUID _userID2;
    private static PwmLib _pwmlib2;
    private static KeyStore _keystore2;
    private static Key _privateKey2;
    private static Key _publicKey2;
    
    @BeforeClass
    public static void setUp() throws Exception {

        /* http://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html */
    	
    	
        _keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        _keystore2 = KeyStore.getInstance(KeyStore.getDefaultType());
        _keystorepw = "1234567";

        // get user password and file input stream
        char[] password = _keystorepw.toCharArray();

        _keystore.load(new FileInputStream(PATH_TO_RSAKEYSTORE), password);
        _keystore2.load(new FileInputStream(PATH_TO_RSAKEYSTORE2), password);

        _pwmlib = new PwmLib();
        _pwmlib2 = new PwmLib();
        _pwmlib.init(_keystore,password);
        _pwmlib2.init(_keystore2,password);

        _userID = _pwmlib.register_user();
        _privateKey = (PrivateKey) _keystore.getKey(CLIENT_PUBLIC_KEY, password);
        _publicKey = _keystore.getCertificate(CLIENT_PUBLIC_KEY).getPublicKey();
        
        _userID2 = _pwmlib2.register_user();
        _privateKey2 = (PrivateKey) _keystore2.getKey(CLIENT_PUBLIC_KEY, password);
        _publicKey2 = _keystore2.getCertificate(CLIENT_PUBLIC_KEY).getPublicKey();
        
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
    public void retrieve_password() throws UserDoesNotExistException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, SignatureException, IOException, InvalidAlgorithmParameterException, ClassNotFoundException, InvalidNonceException, InvalidSignatureException, InvalidRequestException, WrongUserIDException {
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
    public void retrive_altered_password() throws UserDoesNotExistException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, SignatureException, IOException, InvalidAlgorithmParameterException, ClassNotFoundException, InvalidNonceException, InvalidSignatureException, InvalidRequestException, WrongUserIDException {
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
    public void unexisting_pass() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, SignatureException, InvalidAlgorithmParameterException, ClassNotFoundException, UserDoesNotExistException, InvalidRequestException, IOException, InvalidNonceException, WrongUserIDException, InvalidSignatureException{
    	
    	String domain = "www.google.pt";
    	String username = "juanito";
    	
    	_pwmlib.retrieve_password(_userID, domain.getBytes(), username.getBytes());
    	
    }
    
    @Test(expected = UserAlreadyExistsException.class)
    public void wrong_register() throws UnrecoverableKeyException, InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, SignatureException, ClassNotFoundException, UserAlreadyExistsException, IOException, InvalidSignatureException, UserDoesNotExistException{
    	_pwmlib.register_user();
    }
    
    @Test(expected = WrongUserIDException.class)
    public void retrieve_invalid_user() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, SignatureException, InvalidAlgorithmParameterException, ClassNotFoundException, UserDoesNotExistException, InvalidRequestException, IOException, InvalidNonceException, WrongUserIDException, InvalidSignatureException{
    	UUID u = UUID.randomUUID();
    	_pwmlib.retrieve_password(u, "domain".getBytes(), "username".getBytes());
    }
    
    @Test(expected = InvalidSignatureException.class)
    public void impersonate_request() throws InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, SignatureException, InvalidAlgorithmParameterException, ClassNotFoundException, UserDoesNotExistException, IOException, InvalidNonceException, InvalidSignatureException, InvalidRequestException, WrongUserIDException{
    	byte[] domain = "www.google.pt".getBytes();
    	byte[] username = "juanito".getBytes();
    	byte[] password = "mypass".getBytes();
    	
    	_pwmlib.save_password(_userID, domain, username, password);
    	_pwmlib2.retrieve_password(_userID, domain, username);
    	
    }
}