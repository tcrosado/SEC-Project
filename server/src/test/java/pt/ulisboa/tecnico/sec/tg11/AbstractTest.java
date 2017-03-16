package pt.ulisboa.tecnico.sec.tg11;

import org.junit.After;
import org.junit.Before;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.PWMInterface;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public abstract class AbstractTest {

		PWMInterface _serverRemote;
		KeyPair keypair;
		Server serverObject;
	@Before
	public void setUp() throws Exception {
		serverObject = new Server();
		serverObject.setUp();


		String text = "RMI Test Message";

		try {
			Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
			_serverRemote = (PWMInterface) registry.lookup("PWMServer");
		} catch (Exception e) {
			e.printStackTrace();
		}


		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);
		keypair = keyPairGenerator.genKeyPair();

	}

	@After
	public void tearDown() throws Exception {
		serverObject.shutdown();
	}
}
