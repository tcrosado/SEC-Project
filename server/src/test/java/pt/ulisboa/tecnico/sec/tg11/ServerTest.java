package pt.ulisboa.tecnico.sec.tg11;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.MessageManager;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.UUID;

public class ServerTest extends AbstractTest{

	UUID _userID;
	BigInteger _nonce;
	@Before
	public void setUp() throws Exception {
		super.setUp();
		_userID = _serverRemote.register(keypair.getPublic());
		_nonce = _serverRemote.requestNonce(_userID);


	}


	@Test
	public void testPut() throws IOException, UserDoesNotExistException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, SignatureException, ClassNotFoundException, InvalidNonceException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password = "testPass";

		MessageManager manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		manager.putCipheredContent("password",password.getBytes());
		_serverRemote.put(manager.generateMessage());
	}


	@Test
	public void testUpdatePasswordPut() throws IOException, UserDoesNotExistException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, SignatureException, ClassNotFoundException, InvalidNonceException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password2 = "testPass2";
		String password = "testPass";

		MessageManager manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		manager.putCipheredContent("password",password.getBytes());
		_serverRemote.put(manager.generateMessage());

		_nonce = _serverRemote.requestNonce(_userID);
		manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		manager.putCipheredContent("password",password2.getBytes());
		_serverRemote.put(manager.generateMessage());
	}

	@Test
	public void testCreateUsernamePut() throws IOException, UserDoesNotExistException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, SignatureException, ClassNotFoundException, InvalidNonceException {
		String domain = "www.google.pt";
		String username = "testUser";
		String username2 = "testUser2";
		String password = "testPass";

		MessageManager manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		manager.putCipheredContent("password",password.getBytes());
		_serverRemote.put(manager.generateMessage());


		_nonce = _serverRemote.requestNonce(_userID);
		manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username2.getBytes());
		manager.putCipheredContent("password",password.getBytes());
		_serverRemote.put(manager.generateMessage());
	}


	@Test (expected = PasswordDoesNotExistException.class)
	public void testNonExistentGet() throws IOException, UserDoesNotExistException, PasswordDoesNotExistException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, SignatureException, ClassNotFoundException, InvalidNonceException {
		byte[] empty = new byte[0];
		MessageManager manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",empty);
		manager.putHashedContent("username",empty);
		_serverRemote.get(manager.generateMessage());

	}


	@Test
	public void testGet() throws IOException, UserDoesNotExistException, PasswordDoesNotExistException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException, ClassNotFoundException, InvalidNonceException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password = "testPass";


		MessageManager manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		manager.putCipheredContent("password",password.getBytes());
		_serverRemote.put(manager.generateMessage());

		_nonce = _serverRemote.requestNonce(_userID);
		manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		byte[] result =_serverRemote.get(manager.generateMessage());
		assertArrayEquals(password.getBytes(),result);
	}

	@Test
	public void testGetUpdated() throws IOException, UserDoesNotExistException, PasswordDoesNotExistException, NoSuchPaddingException, SignatureException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, ClassNotFoundException, InvalidNonceException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password = "testPass";
		String password2 = "pass";

		MessageManager manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		manager.putCipheredContent("password",password.getBytes());
		_serverRemote.put(manager.generateMessage());


		_nonce = _serverRemote.requestNonce(_userID);
		manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		byte[] result =_serverRemote.get(manager.generateMessage());

		assertArrayEquals(password.getBytes(),result);

		_nonce = _serverRemote.requestNonce(_userID);
		manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		manager.putCipheredContent("password",password2.getBytes());
		_serverRemote.put(manager.generateMessage());

		_nonce = _serverRemote.requestNonce(_userID);
		manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		result = _serverRemote.get(manager.generateMessage());
		assertArrayEquals(password2.getBytes(),result);
	}


	@Test(expected = InvalidNonceException.class)
	public void replayAttackTest() throws IOException, UserDoesNotExistException, PasswordDoesNotExistException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException, ClassNotFoundException, InvalidNonceException {
			String domain = "www.google.pt";
			String username = "testUser";
			String password = "testPass";


			MessageManager manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
			manager.putHashedContent("domain",domain.getBytes());
			manager.putHashedContent("username",username.getBytes());
			manager.putCipheredContent("password",password.getBytes());
			_serverRemote.put(manager.generateMessage());
			_serverRemote.put(manager.generateMessage());
	}

	@Test(expected = InvalidSignatureException.class)
	public void tamperMessage() throws BadPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, SignatureException, ClassNotFoundException, UserDoesNotExistException, InvalidNonceException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password = "testPass";

		MessageManager manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		manager.putCipheredContent("password",password.getBytes());
		byte[] msg = manager.generateMessage();
		int index = new String(msg).indexOf("username");
		msg[index]='U';

		_serverRemote.put(msg);
	}
}
