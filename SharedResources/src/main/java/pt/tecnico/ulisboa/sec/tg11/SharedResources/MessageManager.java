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

public class MessageManager {
	
	private Message _msg;
	private Key _srcPrivateKey;
	private Key _srcPublicKey;
	private Key _symmetricKey;
	private static final int AES_KEYLENGTH = 128;


	//RECEIVES MESSAGE
	public MessageManager(byte[] message) throws IOException, ClassNotFoundException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException, InvalidSignatureException {

		ByteArrayInputStream b = new ByteArrayInputStream(message);
		ObjectInputStream obj = new ObjectInputStream(b);
		_msg = (Message) obj.readObject();
	}
	
	//SERVER SEND MESSAGE
	public MessageManager(Key srcPrivateKey,Key srcPublicKey) throws BadPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
		_srcPrivateKey = srcPrivateKey;
		_srcPublicKey = srcPublicKey;
		_msg = new Message();
	}
	
	//CLIENT SEND MESSAGE
	public MessageManager(UUID userid, Key srcPrivateKey, Key symmetricKey) throws BadPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
		_srcPrivateKey = srcPrivateKey;
		_symmetricKey = symmetricKey;
		_msg = new Message(userid);

	}

	private byte[] rsaCipherValue(byte[] value) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{
			
		Cipher c = Cipher.getInstance("RSA");
	    c.init(Cipher.ENCRYPT_MODE, _symmetricKey);
	    
	    byte[] v  = c.doFinal(value);
	     
	    return v;
	}
	
	private byte[] rsaDecipherValue(byte[] value) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
		Cipher d = Cipher.getInstance("RSA");
	    d.init(Cipher.DECRYPT_MODE, _symmetricKey);
	    
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

	public void putContent(String key, byte[] value) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {
		
		_msg.addContent(key, this.rsaCipherValue(value));
	}

	public byte[] getContent(String key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException{
		return this.rsaCipherValue(_msg.getContent(key));
	}
	
	public byte[] getCypheredContent(String key){
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
			throw new InvalidSignatureException(_msg.getSignature());
	}

	public void setPublicKey(Key pub){
		_srcPublicKey = pub;
	}
	
private byte[] aesCipherValue(byte[] value) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		
		Cipher aesCipherForEncryption = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		
		byte[] iv = generateIV();
		
		aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, _symmetricKey, new IvParameterSpec(iv));
			
		byte[] byteCipherText = aesCipherForEncryption.doFinal(value);
		
		ByteArrayOutputStream result = new ByteArrayOutputStream();
		
		result.write(iv);
		result.write(byteCipherText);
		
		return result.toByteArray();
	}
	
	private byte[] aesDecipherValue(byte[] value) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException{
		
		Cipher aesCipherForDecryption = Cipher.getInstance("AES/CBC/PKCS5PADDING"); // Must specify the mode explicitly as most JCE providers default to ECB mode!!				
		
		ByteArrayInputStream b = new ByteArrayInputStream(value);
		
		byte[] iv = new byte[AES_KEYLENGTH/8];
		
		b.read(iv, 0, AES_KEYLENGTH/8);
		
		byte[] message = new byte[value.length-(AES_KEYLENGTH/8)];
		
		b.read(message, AES_KEYLENGTH/8, value.length-(AES_KEYLENGTH/8));
		
		aesCipherForDecryption.init(Cipher.DECRYPT_MODE, _symmetricKey,new IvParameterSpec(iv));
		byte[] byteDecryptedText = aesCipherForDecryption.doFinal(message);
		
		return byteDecryptedText;
	}
	
	public byte[] generateIV(){

		byte[] iv = new byte[AES_KEYLENGTH / 8];	// Save the IV bytes or send it in plaintext with the encrypted data so you can decrypt the data later
		SecureRandom prng = new SecureRandom();
		prng.nextBytes(iv);
		
		return iv;
	}
}
