package pt.tecnico.ulisboa.sec.tg11.SharedResources;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class SecureMessage {
	
	Message _msg;
	Key _orgPrivateKey;
	Key _destPublicKey;
	
	public SecureMessage(Key originPrivateKey,Key destinationPublicKey){
		_orgPrivateKey = originPrivateKey;
		_destPublicKey = destinationPublicKey;
		_msg = new Message();
	}

	public SecureMessage(UUID userid,Key privateKey,Key destinationPublicKey){
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

	public byte[] getMessage() throws IOException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
		ByteArrayOutputStream b  = new ByteArrayOutputStream();
		ObjectOutputStream obj = new ObjectOutputStream(b);
		obj.writeObject(_msg);

		return this.cipherValue(b.toByteArray(),_destPublicKey);
	}

	public void putContent(String key, byte[] value) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {
		_msg.addContent(key,this.cipherValue(value,_orgPrivateKey));
	}

	
	public byte[] generateHMac(Key key) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		
		SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "HmacSHA1");

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(keySpec);

		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(byteStream);
		out.writeObject(_msg.getAllContent());
		out.writeObject(_msg.getTimestamp());
		out.writeObject(_msg.getNonce());

		byte[] result = mac.doFinal(byteStream.toByteArray());
		return result;
	}
}
