package pt.ulisboa.tecnico.sec.tg11;

import static org.junit.Assert.*;

import org.junit.Assert;
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

		byte[] msg = _serverRemote.register(keypair.getPublic());
		MessageManager mm = verifyMessage(msg);


		_userID = UUID.fromString(new String(mm.getContent("UUID")));
		byte[] result =  _serverRemote.requestNonce(_userID);

		mm = verifyMessage(result);
		_nonce = new BigInteger(mm.getContent("Nonce"));

	}


	@Test
	public void testPut() throws IOException, UserDoesNotExistException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, SignatureException, ClassNotFoundException, InvalidNonceException, InvalidSignatureException, WrongUserIDException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password = "testPass";

		MessageManager manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		manager.putCipheredContent("password",password.getBytes());
		byte[] msg = _serverRemote.put(manager.generateMessage());

		MessageManager receiveManager = verifyMessage(msg);
		Assert.assertEquals("ACK",new String(receiveManager.getContent("Status")));

	}


	@Test
	public void testUpdatePasswordPut() throws IOException, UserDoesNotExistException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, SignatureException, ClassNotFoundException, InvalidNonceException, InvalidSignatureException, WrongUserIDException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password2 = "testPass2";
		String password = "testPass";

		MessageManager manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		manager.putCipheredContent("password",password.getBytes());
		byte[] msg = _serverRemote.put(manager.generateMessage());

		MessageManager receiveManager = verifyMessage(msg);
		Assert.assertEquals("ACK",new String(receiveManager.getContent("Status")));


		byte[] result =  _serverRemote.requestNonce(_userID);
		receiveManager = verifyMessage(result);
		_nonce = new BigInteger(receiveManager.getContent("Nonce"));


		manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		manager.putCipheredContent("password",password2.getBytes());
		byte[] newPut = _serverRemote.put(manager.generateMessage());

		receiveManager = verifyMessage(newPut);
		Assert.assertEquals("ACK",new String(receiveManager.getContent("Status")));
	}

	@Test
	public void testCreateUsernamePut() throws IOException, UserDoesNotExistException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, SignatureException, ClassNotFoundException, InvalidNonceException, InvalidSignatureException, WrongUserIDException {
		String domain = "www.google.pt";
		String username = "testUser";
		String username2 = "testUser2";
		String password = "testPass";

		MessageManager manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		manager.putCipheredContent("password",password.getBytes());
		byte[] msg = _serverRemote.put(manager.generateMessage());

		MessageManager receiveManager = verifyMessage(msg);
		Assert.assertEquals("ACK",new String(receiveManager.getContent("Status")));


		byte[] result =  _serverRemote.requestNonce(_userID);
		MessageManager mm = verifyMessage(result);
		_nonce = new BigInteger(mm.getContent("Nonce"));

		manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username2.getBytes());
		manager.putCipheredContent("password",password.getBytes());
		byte[] newPut = _serverRemote.put(manager.generateMessage());

		receiveManager = verifyMessage(newPut);
		Assert.assertEquals("ACK",new String(receiveManager.getContent("Status")));
	}


	@Test (expected = InvalidRequestException.class)
	public void testNonExistentGet() throws IOException, UserDoesNotExistException, InvalidRequestException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, SignatureException, ClassNotFoundException, InvalidNonceException, InvalidSignatureException, WrongUserIDException {
		byte[] empty = new byte[0];
		MessageManager manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",empty);
		manager.putHashedContent("username",empty);
		_serverRemote.get(manager.generateMessage());

	}


	@Test
	public void testGet() throws IOException, UserDoesNotExistException, InvalidRequestException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException, ClassNotFoundException, InvalidNonceException, InvalidSignatureException, WrongUserIDException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password = "testPass";


		MessageManager manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		manager.putCipheredContent("password",password.getBytes());
		byte[] putResult = _serverRemote.put(manager.generateMessage());

		MessageManager receiveManager = verifyMessage(putResult);
		Assert.assertEquals("ACK",new String(receiveManager.getContent("Status")));

		byte[] result =  _serverRemote.requestNonce(_userID);
		MessageManager mm = verifyMessage(result);
		_nonce = new BigInteger(mm.getContent("Nonce"));


		manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		byte[] passResult =_serverRemote.get(manager.generateMessage());
		receiveManager = verifyMessage(passResult);


		byte[] retrieved = manager.getDecypheredMessage(receiveManager.getContent("Password"));
		assertArrayEquals(password.getBytes(),retrieved);
	}

	@Test
	public void testGetUpdated() throws IOException, UserDoesNotExistException, InvalidRequestException, NoSuchPaddingException, SignatureException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, ClassNotFoundException, InvalidNonceException, InvalidSignatureException, WrongUserIDException {
		String domain = "www.google.pt";
		String username = "testUser";
		String password = "testPass";
		String password2 = "pass";

		MessageManager manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		manager.putCipheredContent("password",password.getBytes());
		_serverRemote.put(manager.generateMessage());


		byte[] result =  _serverRemote.requestNonce(_userID);
		MessageManager mm = verifyMessage(result);
		_nonce = new BigInteger(mm.getContent("Nonce"));



		manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		byte[] result2 =_serverRemote.get(manager.generateMessage());
		//FIXME
		MessageManager received = verifyMessage(result2);
		byte[] retrieved = manager.getDecypheredMessage(received.getContent("Password"));



		assertArrayEquals(password.getBytes(),retrieved);


		byte[] result3 =  _serverRemote.requestNonce(_userID);
		MessageManager manager1 = verifyMessage(result3);
		_nonce = new BigInteger(manager1.getContent("Nonce"));


		manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		manager.putCipheredContent("password",password2.getBytes());
		_serverRemote.put(manager.generateMessage());


		byte[] result4 =  _serverRemote.requestNonce(_userID);
		MessageManager manager2 = verifyMessage(result4);
		_nonce = new BigInteger(manager2.getContent("Nonce"));



		manager = new MessageManager(_nonce,_userID,keypair.getPrivate(),keypair.getPublic());
		manager.putHashedContent("domain",domain.getBytes());
		manager.putHashedContent("username",username.getBytes());
		result4 = _serverRemote.get(manager.generateMessage());
		mm = verifyMessage(result4);
		retrieved = manager.getDecypheredMessage(mm.getContent("Password"));
		assertArrayEquals(password2.getBytes(),retrieved);
	}


	@Test(expected = InvalidNonceException.class)
	public void replayAttackTest() throws IOException, UserDoesNotExistException, InvalidRequestException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException, ClassNotFoundException, InvalidNonceException, InvalidSignatureException, WrongUserIDException {
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
	public void tamperMessage() throws BadPaddingException, InvalidSignatureException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, SignatureException, ClassNotFoundException, UserDoesNotExistException, InvalidNonceException, WrongUserIDException {
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

	private MessageManager verifyMessage(byte[] msg) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IllegalBlockSizeException, BadPaddingException, InvalidSignatureException, ClassNotFoundException {
		MessageManager mm = new MessageManager(msg);
		mm.setPublicKey(_serverPublicKey);
		mm.verifySignature();
		return mm;
	}
}
