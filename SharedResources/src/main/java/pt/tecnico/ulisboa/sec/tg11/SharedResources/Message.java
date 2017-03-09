package pt.tecnico.ulisboa.sec.tg11.SharedResources;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.*;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Message {
	
	private Map<String, byte[]> _content;
	private Timestamp _timestamp;
	private UUID _userid;
	private byte[] _hmac;
	private SecureRandom _nonce;
	
	public Message(){
		_nonce = new SecureRandom();
		_content = new HashMap<String, byte[]>();
		_timestamp = new Timestamp(Calendar.getInstance().getTimeInMillis());
	}
	
	public Message(UUID uid){
		_userid = uid;
		_nonce = new SecureRandom();
		_content = new HashMap<String, byte[]>();
		_timestamp = new Timestamp(Calendar.getInstance().getTimeInMillis());
	}
	
	public UUID getUserId(){
		return _userid;
	}
	
	public void addContent(String name, byte[] value, Key publicKey){
		_content.put(name, value);
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

	public void cipherContent(Key publicKey) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {

		Map<String, byte[]> content = new HashMap<String, byte[]>();
		for (Map.Entry<String, byte[]> entry : _content.entrySet()) {
			String key = entry.getKey();
			byte[] value = entry.getValue();
			byte[] v = cipherValue(value, publicKey);
			content.put(key, v);
		}
		_content = content;
	}

	public void generateHMac(Key privateKey) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		SecretKeySpec keySpec = new SecretKeySpec(privateKey.getEncoded(), "HmacSHA1");

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(keySpec);

		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(byteStream);
		out.writeObject(_content);
		out.writeObject(_timestamp);
		out.writeObject(_nonce);

		byte[] result = mac.doFinal(byteStream.toByteArray());
		_hmac = result;
	}

	public boolean verifyHMac(Key publicKey){
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(publicKey,);
	}

	public void buildFinalMessage(Key publicKey, Key privateKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
		cipherContent(publicKey);
		generateHMac(privateKey);
	}
}
