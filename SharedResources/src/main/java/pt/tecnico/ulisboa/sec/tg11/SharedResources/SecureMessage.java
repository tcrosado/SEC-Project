package pt.tecnico.ulisboa.sec.tg11.SharedResources;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class SecureMessage {
	
	Message _msg;
	
	public SecureMessage(Message m){
		_msg = m;
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
	
	public Timestamp generateTimeStamp(){
		return new Timestamp(Calendar.getInstance().getTimeInMillis());
	}
	
	public SecureRandom generateNonce(){
		return new SecureRandom();
	}
	
	public void cipherMessageContent(Key key) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {

		Map<String, byte[]> aux_content = new HashMap<String, byte[]>();
		Map<String, byte[]> content = _msg.getAllContent();
		
		for (Map.Entry<String, byte[]> entry : content.entrySet()) {
			String k = entry.getKey();
			byte[] value = entry.getValue();
			byte[] v = cipherValue(value, key);
			aux_content.put(k, v);
		}
		
		_msg.setAllContent(aux_content);
	}
	
	public byte[] generateSignature(Key key, byte[] value) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		
		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign((PrivateKey) key);
		sign.update(value);
		
		byte[] result = sign.sign();
		return result;
	}
	
	public boolean verifySignature(Key key, byte[] signature, byte[] value) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException{
		
		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initVerify((PublicKey) key);
		sign.update(value);
		
		boolean verifies = sign.verify(signature);
		return verifies;
	}
}
