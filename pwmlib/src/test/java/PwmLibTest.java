import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Created by trosado on 01/03/17.
 */
public class PwmLibTest {

    private PwmLib test;

    @Before
    public void setUp() throws Exception {
        test = new PwmLib();

    }

    @Test
    public void TestingTest() throws Exception {
        Assert.assertEquals("This",test.test());
    }

}