package pt.ulisboa.tecnico.sec.tg11;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import pt.ulisboa.tecnico.sec.tg11.exceptions.PasswordDoesNotExistException;
import pt.ulisboa.tecnico.sec.tg11.exceptions.UserAlreadyExistsException;
import pt.ulisboa.tecnico.sec.tg11.exceptions.UserDoesNotExistException;


import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.UUID;

public class ServerTest extends AbstractTest{

	UUID userID;

	@Before
	public void setUp() throws Exception {
		super.setUp();
		userID = server.register(keypair.getPublic());
	}


	@Test
	public void testPut() throws RemoteException, UserDoesNotExistException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password = "testPass";
		server.put(userID,domain.getBytes(),username.getBytes(),password.getBytes());
	}


	@Test
	public void testUpdatePasswordPut() throws RemoteException, UserDoesNotExistException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password2 = "testPass2";
		String password = "testPass";
		server.put(userID,domain.getBytes(),username.getBytes(),password.getBytes());
		server.put(userID,domain.getBytes(),username.getBytes(),password2.getBytes());
	}

	@Test
	public void testCreateUsernamePut() throws RemoteException, UserDoesNotExistException {
		String domain = "www.google.pt";
		String username = "testUser";
		String username2 = "testUser2";
		String password = "testPass";
		server.put(userID,domain.getBytes(),username.getBytes(),password.getBytes());
		server.put(userID,domain.getBytes(),username2.getBytes(),password.getBytes());
	}


	@Test (expected = UserDoesNotExistException.class)
	public void testNonExistentGet() throws RemoteException, UserDoesNotExistException, PasswordDoesNotExistException {
		byte[] result = server.get(userID,new byte[0],new byte[0]);
	}


	@Test
	public void testGet() throws RemoteException, UserDoesNotExistException, PasswordDoesNotExistException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password = "testPass";
		server.put(userID,domain.getBytes(),username.getBytes(),password.getBytes());
		byte[] result = server.get(userID,domain.getBytes(),username.getBytes());
		assertArrayEquals(password.getBytes(),result);
	}

	@Test
	public void testGetUpdated() throws RemoteException, UserDoesNotExistException, PasswordDoesNotExistException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password = "testPass";
		String password2 = "pass";
		server.put(userID,domain.getBytes(),username.getBytes(),password.getBytes());
		byte[] result = server.get(userID,domain.getBytes(),username.getBytes());
		assertArrayEquals(password.getBytes(),result);

		server.put(userID,domain.getBytes(),username.getBytes(),password2.getBytes());
		result = server.get(userID,domain.getBytes(),username.getBytes());
		assertArrayEquals(password2.getBytes(),result);
	}

}
