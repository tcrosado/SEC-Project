package pt.ulisboa.tecnico.sec.tg11;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import pt.ulisboa.tecnico.sec.tg11.exceptions.UserAlreadyExistsException;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public abstract class AbstractTest {
		ServerInterface server;
		KeyPair keypair;
		Registry reg;

	@Before
	public void setUp() throws Exception {
		try {
			reg = LocateRegistry.createRegistry(1099);
		} catch (Exception e) {
			System.out.println("ERROR: Could not create the registry.");
			e.printStackTrace();
		}
		Server serverObject = new Server();
		System.out.println("Waiting...");
		try {
			reg.rebind("PWMServer", (ServerInterface) UnicastRemoteObject.exportObject(serverObject, 1099));
		} catch (Exception e) {
			System.out.println("ERROR: Failed to register the server object.");
			e.printStackTrace();
		}

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(1024, random);

		keypair = keyGen.genKeyPair();
	}

	@After
	public void tearDown() throws Exception {
		System.out.print("tearDown");
		reg.unbind("PWMServer");
		UnicastRemoteObject.unexportObject(reg, true);
	}
}
