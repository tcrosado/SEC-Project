package pt.tecnico.ulisboa.sec.tg11.SharedResources;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.InvalidSignatureException;

import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class RSAMessageManager {
	
	private Message _msg;
	private Key _srcPrivateKey;
	private Key _destPublicKey;
	private Key _srcPublicKey;
	
	
	//RECEIVES MESSAGE
	public RSAMessageManager(byte[] message,Key srcPrivateKey) throws IOException, ClassNotFoundException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException, InvalidSignatureException {
		_srcPrivateKey = srcPrivateKey;
		byte[] msg = rsaDecipherValue(message,_srcPrivateKey);
		ByteArrayInputStream b = new ByteArrayInputStream(msg);
		ObjectInputStream obj = new ObjectInputStream(b);
		_msg = (Message) obj.readObject();
	}
	
	//SERVER SEND MESSAGE
	public RSAMessageManager(Key srcPrivateKey, Key destPublicKey) throws BadPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
		_srcPrivateKey = srcPrivateKey;
		_destPublicKey = destPublicKey;
		_msg = new Message(_destPublicKey);
	}
	
	//CLIENT SEND MESSAGE
	public RSAMessageManager(UUID userid, Key srcPrivateKey, Key srcPublicKey, Key destPublicKey) throws BadPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
		_srcPublicKey = srcPublicKey;
		_srcPrivateKey = srcPrivateKey;
		_destPublicKey = destPublicKey;
		_msg = new Message(userid,_destPublicKey);
	}

	private byte[] rsaCipherValue(byte[] value, Key key) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{
			
		Cipher c = Cipher.getInstance("RSA");
	    c.init(Cipher.ENCRYPT_MODE, key);
	    
	    byte[] v  = c.doFinal(value);
	     
	    return v;
	}
	
	private byte[] rsaDecipherValue(byte[] value, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
		Cipher d = Cipher.getInstance("RSA");
	    d.init(Cipher.DECRYPT_MODE, key);
	    
	    byte[] v = d.doFinal(value);
	    
	    return v;
	}

	public byte[] generateMessage() throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, SignatureException {
		generateSignature();
		ByteArrayOutputStream b  = new ByteArrayOutputStream();
		ObjectOutputStream obj = new ObjectOutputStream(b);
		obj.writeObject(_msg);
		obj.flush();
		obj.close();
		return this.rsaCipherValue(b.toByteArray(),_destPublicKey);
	}

	public void putContent(String key, byte[] value) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {
		
		_msg.addContent(key, value);
	}

	public byte[] getContent(String key){
		return _msg.getContent(key);
	}

	public UUID getUserID(){
		return _msg.getUserID();
	}

	private byte[] serializeContent() throws IOException {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		ObjectOutputStream obj = new ObjectOutputStream(b);
		obj.writeObject(_msg.getAllContent());
		obj.writeObject(_msg.getNonce());
		obj.writeObject(_msg.getTimestamp());
		obj.writeObject(_msg.getUserID());
		obj.flush();
		obj.close();
		return b.toByteArray();
	}

	
	public void generateSignature() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
		
		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign((PrivateKey) _srcPrivateKey);
		sign.update(serializeContent());
		_msg.setSignature(sign.sign());
	}

	
	public void verifySignature(Key key) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, IOException, InvalidSignatureException {
		
		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initVerify((PublicKey) key);
		sign.update(serializeContent());

		if(sign.verify(_msg.getSignature()))
			return;
		else
			throw new InvalidSignatureException(_msg.getSignature());
	}
}
