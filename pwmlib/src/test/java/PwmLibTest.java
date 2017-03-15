import org.junit.*;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.*;
import pt.ulisboa.tecnico.sec.tg11.PwmLib;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static org.hamcrest.CoreMatchers.instanceOf;

import java.io.FileInputStream;
import java.io.IOException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.*;
import java.util.UUID;

/**
 * Created by trosado on 01/03/17.
 */
public class PwmLibTest {

    private static final String PATH_TO_KEYSTORE = "./src/main/resources/keystore.jks";
    private static KeyStore _keystore;
    private static PwmLib _pwmlib;
    private static String _keystorepw;
    private static UUID _userID;

    @BeforeClass
    public static void setUp() throws Exception {

        /* http://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html */

        _keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        _keystorepw = "1234567";

        // get user password and file input stream
        char[] password = _keystorepw.toCharArray();

        _keystore.load(new FileInputStream(PATH_TO_KEYSTORE), password);

        _pwmlib = new PwmLib();
        _pwmlib.init(_keystore,_keystorepw.toCharArray());

        _userID = _pwmlib.register_user();

    }

    @AfterClass
    public static void tearDown() throws Exception {
        _pwmlib.close();
    }

    /*
    @Test
    public void testeverything() throws RemoteException, NotBoundException, UnrecoverableKeyException, UserAlreadyExistsException, NoSuchAlgorithmException, KeyStoreException, UserDoesNotExistException, PasswordDoesNotExistException {

        _pwmlib = new PwmLib();
        _pwmlib.init(_keystore, _keystorepw.toCharArray());

        _userID = _pwmlib.register_user();

        String domain = "www.google.pt";
        String username = "testUser";
        String password = "testPass";
        String password2 = "testPass2";

        System.out.println("Testeverything -> UserID: " + _userID);
        _pwmlib.save_password(_userID,domain.getBytes(),username.getBytes(),password.getBytes());
        byte [] pw = _pwmlib.retrieve_password(_userID,domain.getBytes(), username.getBytes());

        System.out.println("Testeverything -> PasswordEnviada: " + password);
        System.out.println("Testeverything -> PasswordObtida: " + new String(pw));
        Assert.assertEquals(password, new String(pw));

        _pwmlib.save_password(_userID,domain.getBytes(),username.getBytes(),password2.getBytes());
        pw = _pwmlib.retrieve_password(_userID,domain.getBytes(), username.getBytes());

        System.out.println("Testeverything -> PasswordEnviada: " + password2);
        System.out.println("Testeverything -> PasswordObtida: " + new String(pw));
        Assert.assertEquals(password2, new String(pw));
    }


    @Test
    public void register_user() throws RegisterUser418, UserAlreadyExistsException, pt.tecnico.ulisboa.sec.tg11.PWInterface.exceptions.UserAlreadyExistsException {

        //_userID = _pwmlib.register_user();
        System.out.println("UserID: " + _userID);
        Assert.assertNotNull(_userID);
        System.out.println("Teste1 ");
    }
   */

    /*@Test
    public void save_password() throws UserDoesNotExistException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, SignatureException, IOException {
        String domain = "www.google.pt";
        String username = "testUser";
        String password = "testPass";
        _pwmlib.save_password(_userID,domain.getBytes(),username.getBytes(),password.getBytes());
    }

    @Test
    public void retrieve_password() throws UserDoesNotExistException, PasswordDoesNotExistException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, SignatureException, IOException {
        String domain = "www.google.pt";
        String username = "testUser";
        String password = "testPass";
        byte [] pw = _pwmlib.retrieve_password(_userID,domain.getBytes(), username.getBytes());
        Assert.assertArrayEquals(pw, password.getBytes());

    }*/

    @Test
    public void retrive_altered_password() throws UserDoesNotExistException, PasswordDoesNotExistException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, SignatureException, IOException, InvalidAlgorithmParameterException, ClassNotFoundException {
        String domain = "www.google.pt";
        String username = "testUser";
        String password = "testPass";
        _pwmlib.save_password(_userID,domain.getBytes(),username.getBytes(),password.getBytes());
        String password2 = "testPass2";
        _pwmlib.save_password(_userID,domain.getBytes(),username.getBytes(),password2.getBytes());
        byte [] pw = _pwmlib.retrieve_password(_userID,domain.getBytes(), username.getBytes());
        Assert.assertArrayEquals(pw, password2.getBytes());
    }
}