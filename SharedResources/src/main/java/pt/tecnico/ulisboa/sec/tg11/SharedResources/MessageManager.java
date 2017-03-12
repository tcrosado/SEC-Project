package pt.tecnico.ulisboa.sec.tg11.SharedResources;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.InvalidSignatureException;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MessageManager {
	
	Message _msg;
	Key _orgPrivateKey;
	Key _destPublicKey;

	public MessageManager(byte[] message,Key originPrivateKey) throws IOException, ClassNotFoundException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException, InvalidSignatureException {
		_orgPrivateKey = originPrivateKey;
		byte[] msg = decipherValue(message,_orgPrivateKey);
		ByteArrayInputStream b = new ByteArrayInputStream(msg);
		ObjectInputStream obj = new ObjectInputStream(b);
		_msg = (Message) obj.readObject();
		verifySignature();

	}
	
	public MessageManager(Key originPrivateKey, Key destinationPublicKey){
		_orgPrivateKey = originPrivateKey;
		_destPublicKey = destinationPublicKey;
		_msg = new Message();
	}

	public MessageManager(UUID userid, Key privateKey, Key destinationPublicKey){
		_orgPrivateKey = privateKey;
		_destPublicKey = destinationPublicKey;
		_msg = new Message(userid);
	}

	public byte[] cipherValue(byte[] value, Key key) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{
			
		Cipher c = Cipher.getInstance("RSA");
	    c.init(Cipher.ENCRYPT_MODE, key);

	    byte[] v  = c.doFinal(value);
	     
	    return v;
	}
	
	public byte[] decipherValue(byte[] value, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
		Cipher d = Cipher.getInstance("RSA");
	    d.init(Cipher.DECRYPT_MODE, key);
	    byte[] v = d.doFinal(value);
	    
	    return v;
	}

	public byte[] getMessage() throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, SignatureException {
		generateSignature();
		ByteArrayOutputStream b  = new ByteArrayOutputStream();
		ObjectOutputStream obj = new ObjectOutputStream(b);
		obj.writeObject(_msg);

		return this.cipherValue(b.toByteArray(),_destPublicKey);
	}

	public void putContent(String key, byte[] value) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {
		_msg.addContent(key,this.cipherValue(value,_orgPrivateKey));
	}

	public byte[] getContent(String key){
		return _msg.getContent(key);
	}


	private byte[] serializeContent() throws IOException {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		ObjectOutputStream obj = new ObjectOutputStream(b);
		obj.writeObject(_msg.getAllContent());
		obj.writeObject(_msg.getNonce());
		obj.writeObject(_msg.getTimestamp());
		obj.writeObject(_msg.getUserId());
		return b.toByteArray();
	}
	
	public void generateSignature() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
		
		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign((PrivateKey) _orgPrivateKey);
		sign.update(serializeContent());
		_msg.setSignature(sign.sign());
	}

	
	public void verifySignature() throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, IOException, InvalidSignatureException {
		
		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initVerify((PublicKey) _destPublicKey);
		sign.update(serializeContent());

		if(sign.verify(_msg.getSignature()))
			return;
		else
			throw new InvalidSignatureException(_msg.getSignature());
	}
}
