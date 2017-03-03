import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import pt.ulisboa.tecnico.sec.tg11.PwmLib;
import pt.ulisboa.tecnico.sec.tg11.ServerInterface;
import static org.hamcrest.CoreMatchers.instanceOf;

import java.security.KeyStore;
import java.util.UUID;

/**
 * Created by trosado on 01/03/17.
 */
public class PwmLibTest {

    private PwmLib _pwmlib;
    private KeyStore _keystore;
    private String _keystorepw;

    @Before
    public void setUp() throws Exception {

        /* http://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html */

        _keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        _keystorepw = "example";
        _pwmlib = new PwmLib();
        _pwmlib.init(_keystore, _keystorepw.toCharArray());
    }

    @After
    public void tearDown() throws Exception {
        _pwmlib.close();
    }

    @Test
    public void register_user() {
        UUID userID = _pwmlib.register_user();
        Assert.assertNotNull(userID);
    }

    @Test
    public void save_password(){
        String domain = "www.google.pt";
        String username = "testUser";
        String password = "testPass";
        _pwmlib.save_password(domain.getBytes(),username.getBytes(),password.getBytes());
    }

    @Test
    public void retrieve_password() {
        String domain = "www.google.pt";
        String username = "testUser";
        String password = "testPass";
        byte [] pw = _pwmlib.retrieve_password(domain.getBytes(), username.getBytes());
        Assert.assertEquals(pw, password.getBytes());
    }

    @Test
    public void retrive_altered_password() {
        String domain = "www.google.pt";
        String username = "testUser";
        String password = "testPass";
        _pwmlib.save_password(domain.getBytes(),username.getBytes(),password.getBytes());
        String password2 = "testPass2";
        _pwmlib.save_password(domain.getBytes(),username.getBytes(),password2.getBytes());
        byte [] pw = _pwmlib.retrieve_password(domain.getBytes(), username.getBytes());
        Assert.assertEquals(pw, password2.getBytes());
    }

}