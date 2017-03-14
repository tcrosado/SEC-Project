package pt.tecnico.ulisboa.sec.tg11.SharedResources;

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
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions.InvalidSignatureException;

public class AESMessageManager {
	
	private Message _msg;
	private Key _srcPrivateKey;
	private Key _destPublicKey;
	private Key _srcPublicKey;
	private Key _sessionKey;
    private UUID _userID;
	private static final int AES_KEYLENGTH = 128;
	
	//CLIENT SEND FIRST MESSAGE
	public AESMessageManager(UUID userid, Key sessionKey, Key srcPrivateKey, Key destinationPublicKey, Key srcPublicKey){
		_userID = userid;
        _sessionKey = sessionKey;
		_srcPublicKey = srcPublicKey;
		_srcPrivateKey = srcPrivateKey;
		_destPublicKey = destinationPublicKey;
		_msg = new Message(userid);
	}

    //RECEIVES MESSAGE
    public AESMessageManager(byte[] message, Key sessionKey) throws IOException, ClassNotFoundException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException, InvalidSignatureException, InvalidAlgorithmParameterException {
        _sessionKey = sessionKey;
        byte[] msg = aesDecipherValue(message);
        ByteArrayInputStream b = new ByteArrayInputStream(msg);
        ObjectInputStream obj = new ObjectInputStream(b);
        _msg = (Message) obj.readObject();
    }


    public byte[] generateMessage() throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, SignatureException, InvalidAlgorithmParameterException {
		generateSignature();
		ByteArrayOutputStream b  = new ByteArrayOutputStream();
		ObjectOutputStream obj = new ObjectOutputStream(b);
		obj.writeObject(_msg);


		return this.aesCipherValue(b.toByteArray());
	}

	public void putContent(String key, byte[] value) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, InvalidAlgorithmParameterException, IOException {

		_msg.addContent(key,this.aesCipherValue(value));
	}

    public byte[] getContent(String key){
        return _msg.getContent(key);
    }

    public UUID getUserID(){
        return _msg.getUserID();
    }
	
	private byte[] aesCipherValue(byte[] value) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		
		Cipher aesCipherForEncryption = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		
		byte[] iv = generateIV();
		
		aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, _sessionKey, new IvParameterSpec(iv));
			
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
		
		aesCipherForDecryption.init(Cipher.DECRYPT_MODE, _sessionKey,new IvParameterSpec(iv));
		byte[] byteDecryptedText = aesCipherForDecryption.doFinal(message);
		
		return byteDecryptedText;
	}
	
	public byte[] generateIV(){

		byte[] iv = new byte[AES_KEYLENGTH / 8];	// Save the IV bytes or send it in plaintext with the encrypted data so you can decrypt the data later
		SecureRandom prng = new SecureRandom();
		prng.nextBytes(iv);
		
		return iv;
	}
	
	public Key generateSymmetricKey() throws NoSuchAlgorithmException{
		
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128);
		
		_sessionKey =  kgen.generateKey();
		
		return _sessionKey;
		
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
	
	private byte[] serializeContent() throws IOException {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		ObjectOutputStream obj = new ObjectOutputStream(b);
		obj.writeObject(_msg.getAllContent());
		obj.writeObject(_msg.getNonce());
		obj.writeObject(_msg.getTimestamp());
		obj.writeObject(_msg.getUserID());
		return b.toByteArray();
	}
}
