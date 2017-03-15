package pt.tecnico.ulisboa.sec.tg11.SharedResources;


import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

class Message implements Serializable{
	
	private Map<String, byte[]> _content;
	private byte[] _timestamp;
	private UUID _userid;
	private byte[] _nonce;

	private byte[] _signature;

	byte[] getSignature() {
		return _signature;
	}

	 void setSignature(byte[] _signature) {
		this._signature = _signature;
	}


	private Message(){}

	Message(Key destPublicKey) throws IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

		Cipher c = Cipher.getInstance("RSA");
		c.init(Cipher.ENCRYPT_MODE, destPublicKey);

		Calendar cal = Calendar.getInstance();
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ObjectOutputStream obj = new ObjectOutputStream(out);
		obj.writeObject(new BigInteger(64, new SecureRandom()));
		System.out.print("Size: "+ out.toByteArray().length);
		_nonce = c.doFinal(out.toByteArray());
		_content = new HashMap<String, byte[]>();

		out.flush();
		DataOutputStream d = new DataOutputStream(out);
		d.writeLong(Calendar.getInstance().getTimeInMillis());

		_timestamp = c.doFinal(out.toByteArray());

	}
	
	Message(UUID uid,Key destPublicKey) throws BadPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
		this(destPublicKey);
		_userid = uid;
	}
	
	UUID getUserID(){
		return _userid;
	}
	
	void addContent(String name, byte[] value){
		_content.put(name, value);
	}
	
	byte[] getContent(String name){
		
		return _content.get(name);
	}
	
	Timestamp getTimestamp(Key privateKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, ClassNotFoundException {
		Cipher c = null;
		try {
			c = Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
		c.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] result = c.doFinal(_timestamp);
		ByteArrayInputStream b = new ByteArrayInputStream(result);
		DataInputStream d = new DataInputStream(b);
		return new Timestamp(d.readLong());
	}

	Map<String, byte[]> getAllContent(){
		return _content;
	}
	
	void setAllContent(Map<String, byte[]> c){
		_content = c;
	}
	
	BigInteger getNonce(Key privateKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, ClassNotFoundException {
		Cipher c = null;
		try {
			c = Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}

		c.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] result = c.doFinal(_nonce);
		ByteArrayInputStream b = new ByteArrayInputStream(result);
		ObjectInputStream obj = new ObjectInputStream(b);
		return (BigInteger) obj.readObject();
	}

	byte[] getNonce(){
		return _nonce;
	}

	byte[] getTimestamp(){
		return _timestamp;
	}

}
