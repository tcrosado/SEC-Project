package pt.tecnico.ulisboa.sec.tg11.SharedResources;

import com.sun.org.apache.xalan.internal.xsltc.cmdline.getopt.GetOptsException;
import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.GenericException;
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
	public MessageManager(byte[] message) throws InvalidSignatureException, GenericException {

		ByteArrayInputStream b = new ByteArrayInputStream(message);
		ObjectInputStream obj = null;
		try {
			obj = new ObjectInputStream(b);
			_msg = (Message) obj.readObject();
		} catch (IOException e) {
			throw new GenericException(e);
		} catch (ClassNotFoundException e) {
			throw new GenericException(e);
		}
	}
	
	//SERVER SEND MESSAGE
	public MessageManager(BigInteger nonce,Key srcPrivateKey,Key srcPublicKey){
		_srcPrivateKey = srcPrivateKey;
		_srcPublicKey = srcPublicKey;
		_msg = new Message(nonce);
	}
	
	//CLIENT SEND MESSAGE
	public MessageManager(BigInteger nonce,UUID userid, Key srcPrivateKey, Key srcPublicKey){
		_srcPrivateKey = srcPrivateKey;
		_srcPublicKey = srcPublicKey;
		_msg = new Message(userid,nonce);

	}

	private byte[] rsaCipherValue(byte[] value, Key key) throws GenericException {
		Cipher c = null;
		try {
			c = Cipher.getInstance("RSA");
			c.init(Cipher.ENCRYPT_MODE, key);
			byte[] v  = c.doFinal(value);
			return v;
		} catch (Exception e) {
			throw new GenericException(e);
		}


	}
	
	private byte[] rsaDecipherValue(byte[] value, Key key) throws GenericException {
		Cipher d = null;
		try {
			d = Cipher.getInstance("RSA");
			d.init(Cipher.DECRYPT_MODE, key);
			byte[] v = d.doFinal(value);
			return v;
		} catch (Exception e) {
			throw new GenericException(e);
		}

	}

	public byte[] generateMessage() throws GenericException {
		try {
			generateSignature();
			ByteArrayOutputStream b = new ByteArrayOutputStream();
			ObjectOutputStream obj = new ObjectOutputStream(b);
			obj.writeObject(_msg);
			obj.flush();
			obj.close();
			return b.toByteArray();
		} catch (Exception e) {
			throw new GenericException(e);
		}
	}
	
	public byte[] getDecypheredMessage(byte[] value) throws GenericException {
		return this.rsaDecipherValue(value, this._srcPrivateKey);
	}

	public void putPlainTextContent(String key, byte[] value) throws GenericException {
		_msg.addContent(key, value);
	}
	
	public void putCipheredContent(String key, byte[] value) throws GenericException{
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

	private byte[] serializeContent() throws GenericException{
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		try {
			ObjectOutputStream obj = new ObjectOutputStream(b);
			obj.writeObject(_msg.getAllContent());
			obj.writeObject(_msg.getNonce());
			obj.writeObject(_msg.getTimestamp());
			obj.writeObject(_msg.getUserID());
			obj.flush();
			obj.close();
		}catch (IOException e){
			throw new GenericException(e);
		}
		return b.toByteArray();
	}

	
	public void generateSignature() throws GenericException {

		Signature sign = null;
		try {
			sign = Signature.getInstance("SHA256withRSA");
			sign.initSign((PrivateKey) _srcPrivateKey);
			sign.update(serializeContent());
			_msg.setSignature(sign.sign());
		} catch (Exception e) {
			throw new GenericException(e);
		}
	}

	
	public void verifySignature() throws GenericException, InvalidSignatureException {

		Signature sign = null;
		try {
			sign = Signature.getInstance("SHA256withRSA");

		sign.initVerify((PublicKey) _srcPublicKey);
		sign.update(serializeContent());

		if(sign.verify(_msg.getSignature()))
			return;
		else
			throw new InvalidSignatureException();

		} catch (NoSuchAlgorithmException e) {
			throw new GenericException(e);
		} catch (SignatureException e) {
			throw new GenericException(e);
		} catch (InvalidKeyException e) {
			throw new GenericException(e);
		}
	}
	
	public BigInteger getNonce(){
		return _msg.getNonce();
	}
	public void setPublicKey(Key pub){
		_srcPublicKey = pub;
	}
	
}
