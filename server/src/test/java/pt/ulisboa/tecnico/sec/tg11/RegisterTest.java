package pt.ulisboa.tecnico.sec.tg11;

import org.junit.Assert;
import org.junit.Test;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.MessageManager;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.InvalidSignatureException;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.UserAlreadyExistsException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import static org.junit.Assert.assertArrayEquals;

public class RegisterTest extends AbstractTest{

	@Test
	public void registerUser() throws IOException, UserAlreadyExistsException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IllegalBlockSizeException, BadPaddingException, InvalidSignatureException, ClassNotFoundException {

		byte[] msg = _serverRemote.register(keypair.getPublic());
		MessageManager mm = new MessageManager(msg);
		mm.setPublicKey(_serverPublicKey);
		mm.verifySignature();

		Assert.assertNotNull(mm.getContent("UUID"));
	}

	@Test (expected = UserAlreadyExistsException.class)
	public void registerDuplicateUser() throws IOException, UserAlreadyExistsException, BadPaddingException, ClassNotFoundException, NoSuchAlgorithmException, IllegalBlockSizeException, SignatureException, InvalidKeyException, InvalidSignatureException, NoSuchPaddingException {
		byte[] msg = _serverRemote.register(keypair.getPublic());
		MessageManager mm = new MessageManager(msg);
		mm.setPublicKey(_serverPublicKey);
		mm.verifySignature();

		Assert.assertNotNull(mm.getContent("UUID"));

		_serverRemote.register(keypair.getPublic());
	}

}
