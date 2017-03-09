package pt.tecnico.ulisboa.sec.tg11.SharedResources;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;

public class Message {
	
	private Map<String, byte[]> _content;
	private Timestamp _timestamp;
	private UUID _userid;
	
	public Message(){
		_content = new HashMap<String, byte[]>();
		_timestamp = new Timestamp(Calendar.getInstance().getTimeInMillis());		
		
	}
	
	public Message(UUID uid){
		_userid = uid;
	}
	
	public UUID getUserId(){
		return _userid;
	}
	
	public void addContent(String name, byte[] value, Key publicKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException{
		
		byte[] v = cipherValue(value, publicKey);
		_content.put(name, v);
	}
	
	public byte[] getContent(String name, Key privateKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		
		byte[] v = decipherValue(_content.get(name), privateKey);
		return v;
	}
	
	public Timestamp getTimestamp(){
		return _timestamp;
	}
	
	public byte[] cipherValue(byte[] value, Key publicKey) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{
		
		Cipher c = Cipher.getInstance("RSA");
	    c.init(Cipher.ENCRYPT_MODE, publicKey);

	    byte[] v  = c.doFinal(value);
	     
	    return v;
	}
	
	public byte[] decipherValue(byte[] value, Key privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
		Cipher d = Cipher.getInstance("RSA");
	    d.init(Cipher.DECRYPT_MODE, privateKey);
	    byte[] v = d.doFinal(value);
	    
	    return v;
	}

}
