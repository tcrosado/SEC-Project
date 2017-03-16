package pt.ulisboa.tecnico.sec.tg11;

import org.junit.Test;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.UserAlreadyExistsException;

import java.rmi.RemoteException;

import static org.junit.Assert.assertArrayEquals;

public class RegisterTest extends AbstractTest{

	@Test
	public void registerUser() throws RemoteException, UserAlreadyExistsException {
		_serverRemote.register(keypair.getPublic());

	}

	@Test (expected = UserAlreadyExistsException.class)
	public void registerDuplicateUser() throws RemoteException, UserAlreadyExistsException {
		_serverRemote.register(keypair.getPublic());
		_serverRemote.register(keypair.getPublic());
	}

}
