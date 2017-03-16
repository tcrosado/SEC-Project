package pt.tecnico.ulisboa.sec.tg11.SharedResources;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.InvalidSignatureException;

import java.io.*;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
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

public class MessageManager {
	
	private Message _msg;
	private Key _srcPrivateKey;
	private Key _srcPublicKey;


	//RECEIVES MESSAGE
	public MessageManager(byte[] message) throws IOException, ClassNotFoundException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException, InvalidSignatureException {

		ByteArrayInputStream b = new ByteArrayInputStream(message);
		ObjectInputStream obj = new ObjectInputStream(b);
		_msg = (Message) obj.readObject();
	}
	
	//SERVER SEND MESSAGE
	public MessageManager(BigInteger nonce,Key srcPrivateKey,Key srcPublicKey) throws BadPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
		_srcPrivateKey = srcPrivateKey;
		_srcPublicKey = srcPublicKey;
		_msg = new Message(nonce);
	}
	
	//CLIENT SEND MESSAGE
	public MessageManager(BigInteger nonce,UUID userid, Key srcPrivateKey, Key srcPublicKey) throws BadPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
		_srcPrivateKey = srcPrivateKey;
		_srcPublicKey = srcPublicKey;
		_msg = new Message(userid,nonce);

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

	public byte[] generateMessage() throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, SignatureException, ClassNotFoundException {
		generateSignature();
		ByteArrayOutputStream b  = new ByteArrayOutputStream();
		ObjectOutputStream obj = new ObjectOutputStream(b);
		obj.writeObject(_msg);
		obj.flush();
		obj.close();
		return b.toByteArray();
	}
	
	public byte[] getDecypheredMessage(byte[] value) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		return this.rsaDecipherValue(value, this._srcPrivateKey);
	}

	public void putPlainTextContent(String key, byte[] value) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, InvalidAlgorithmParameterException, IOException {
		
		_msg.addContent(key, value);
	}
	
	public void putCipheredContent(String key, byte[] value) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException{
		
		_msg.addContent(key, this.rsaCipherValue(value, this._srcPublicKey));
	}
	
	public void putHashedContent(String key, byte[] value) throws NoSuchAlgorithmException{
		
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(value);
		
		_msg.addContent(key, digest);
	}
	
	public byte[] getContent(String key){
		return _msg.getContent(key);
	}

	public UUID getUserID(){
		return _msg.getUserID();
	}

	private byte[] serializeContent() throws IOException, IllegalBlockSizeException, ClassNotFoundException, BadPaddingException, InvalidKeyException {
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

	
	public void generateSignature() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {
		
		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign((PrivateKey) _srcPrivateKey);
		sign.update(serializeContent());
		_msg.setSignature(sign.sign());
	}

	
	public void verifySignature() throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, IOException, InvalidSignatureException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {
		
		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initVerify((PublicKey) _srcPublicKey);
		sign.update(serializeContent());

		if(sign.verify(_msg.getSignature()))
			return;
		else
			throw new InvalidSignatureException();
	}
	
	public BigInteger getNonce(){
		return _msg.getNonce();
	}
	public void setPublicKey(Key pub){
		_srcPublicKey = pub;
	}
	
}
