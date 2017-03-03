package pt.ulisboa.tecnico.sec.tg11;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import pt.ulisboa.tecnico.sec.tg11.exceptions.UserAlreadyExistsException;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public class ServerTest {
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
			reg.rebind("PWMServer", (ServerInterface) UnicastRemoteObject.exportObject(serverObject, 0));
		} catch (Exception e) {
			System.out.println("ERROR: Failed to register the server object.");
			e.printStackTrace();
		}

		Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
		server = (ServerInterface) registry.lookup("PWMServer");
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(1024, random);

		keypair = keyGen.genKeyPair();
	}

	@After
	public void tearDown() throws Exception {
		reg.unbind("PWMServer");
	}


	@Test
	public void registerUser() throws RemoteException, UserAlreadyExistsException {
		server.register(keypair.getPublic());

	}

	@Test (expected = UserAlreadyExistsException.class)
	public void registerDuplicateUser() throws RemoteException, UserAlreadyExistsException {
		server.register(keypair.getPublic());
		server.register(keypair.getPublic());
	}


	@Test
	public void testPut() throws RemoteException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password = "testPass";
		server.put(keypair.getPublic(),domain.getBytes(),username.getBytes(),password.getBytes());
	}


	@Test
	public void testUpdatePasswordPut() throws RemoteException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password2 = "testPass2";
		String password = "testPass";
		server.put(keypair.getPublic(),domain.getBytes(),username.getBytes(),password.getBytes());
		server.put(keypair.getPublic(),domain.getBytes(),username.getBytes(),password2.getBytes());
	}

	@Test
	public void testCreateUsernamePut() throws RemoteException {
		String domain = "www.google.pt";
		String username = "testUser";
		String username2 = "testUser2";
		String password = "testPass";
		server.put(keypair.getPublic(),domain.getBytes(),username.getBytes(),password.getBytes());
		server.put(keypair.getPublic(),domain.getBytes(),username2.getBytes(),password.getBytes());
	}


	@Test (expected = LoginNotFoundException.class)
	public void testNonExistentGet() throws RemoteException {
		byte[] result = server.get(keypair.getPublic(),new byte[0],new byte[0]);
	}


	@Test
	public void testGet() throws RemoteException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password = "testPass";
		server.put(keypair.getPublic(),domain.getBytes(),username.getBytes(),password.getBytes());
		byte[] result = server.get(keypair.getPublic(),domain.getBytes(),username.getBytes());
		assertArrayEquals(password.getBytes(),result);
	}

	@Test
	public void testGetUpdated() throws RemoteException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password = "testPass";
		String password2 = "pass";
		server.put(keypair.getPublic(),domain.getBytes(),username.getBytes(),password.getBytes());
		byte[] result = server.get(keypair.getPublic(),domain.getBytes(),username.getBytes());
		assertArrayEquals(password.getBytes(),result);

		server.put(keypair.getPublic(),domain.getBytes(),username.getBytes(),password2.getBytes());
		result = server.get(keypair.getPublic(),domain.getBytes(),username.getBytes());
		assertArrayEquals(password2.getBytes(),result);
	}

}
