package pt.ulisboa.tecnico.sec.tg11;

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

import static org.junit.Assert.assertArrayEquals;

public class RegisterTest extends AbstractTest{

	@Test
	public void registerUser() throws RemoteException, UserAlreadyExistsException {
		serverRemote.register(keypair.getPublic());

	}

	@Test (expected = UserAlreadyExistsException.class)
	public void registerDuplicateUser() throws RemoteException, UserAlreadyExistsException {
		serverRemote.register(keypair.getPublic());
		serverRemote.register(keypair.getPublic());
	}

}
