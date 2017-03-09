package pt.ulisboa.tecnico.sec.tg11;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.PWMInterface;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.*;

import java.rmi.Remote;
import java.rmi.RemoteException;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public abstract class AbstractTest {

		PWMInterface serverRemote;
		KeyPair keypair;
		Server serverObject;
	@Before
	public void setUp() throws Exception {
		serverObject = new Server();
		serverObject.setUp();


		String text = "RMI Test Message";

		try {
			Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
			serverRemote = (PWMInterface) registry.lookup("PWMServer");
			System.out.println("Connected to Server");
		} catch (Exception e) {
			e.printStackTrace();
		}

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(1024, random);

		keypair = keyGen.genKeyPair();
	}

	@After
	public void tearDown() throws Exception {
		serverObject.shutdown();
	}
}
