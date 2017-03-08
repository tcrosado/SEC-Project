import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


import pt.ulisboa.tecnico.sec.tg11.PwmLib;
import pt.tecnico.ulisboa.sec.tg11.PWInterface.exceptions.*;

import static org.hamcrest.CoreMatchers.instanceOf;

import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.UUID;

/**
 * Created by trosado on 01/03/17.
 */
public class PwmLibTest {

    private PwmLib _pwmlib;
    private KeyStore _keystore;
    private String _keystorepw;
    private UUID _userID;

    @Before
    public void setUp() throws Exception {

        /* http://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html */

        _keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        _keystorepw = "example";

        // get user password and file input stream
        char[] password = _keystorepw.toCharArray();

        _keystore.load(null, password);

    }

    @After
    public void tearDown() throws Exception {
        _pwmlib.close();
    }

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








/*
    @Test
    public void register_user() throws RegisterUser418, UserAlreadyExistsException, pt.tecnico.ulisboa.sec.tg11.PWInterface.exceptions.UserAlreadyExistsException {

        //_userID = _pwmlib.register_user();
        System.out.println("UserID: " + _userID);
        Assert.assertNotNull(_userID);
        System.out.println("Teste1 ");
    }

    @Test
    public void save_password() throws SavePassword418 {
        String domain = "www.google.pt";
        String username = "testUser";
        String password = "testPass";
        //System.out.println("Teste 2 -> UserID: " + _userID);
        _pwmlib.save_password(_userID,domain.getBytes(),username.getBytes(),password.getBytes());
    }

    @Test
    public void retrieve_password() throws RetrievePassword418, RemoteException {
        String domain = "www.google.pt";
        String username = "testUser";
        String password = "testPass";
        byte [] pw = _pwmlib.retrieve_password(_userID,domain.getBytes(), username.getBytes());
        Assert.assertEquals(pw, password.getBytes());
    }

    @Test
    public void retrive_altered_password() throws SavePassword418, RetrievePassword418, RemoteException {
        String domain = "www.google.pt";
        String username = "testUser";
        String password = "testPass";
        _pwmlib.save_password(_userID,domain.getBytes(),username.getBytes(),password.getBytes());
        String password2 = "testPass2";
        _pwmlib.save_password(_userID,domain.getBytes(),username.getBytes(),password2.getBytes());
        byte [] pw = _pwmlib.retrieve_password(_userID,domain.getBytes(), username.getBytes());
        Assert.assertEquals(pw, password2.getBytes());
    }

    */
}