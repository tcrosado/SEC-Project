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
	private SecureRandom _nonce;
	
	public Message(){
		Calendar cal = Calendar.getInstance();
		_nonce = new SecureRandom();
		_content = new HashMap<String, byte[]>();
		_timestamp = new Timestamp(Calendar.getInstance().getTimeInMillis());
	}
	
	public Message(UUID uid){
		this();
		_userid = uid;
	}
	
	public UUID getUserId(){
		return _userid;
	}
	
	public void addContent(String name, byte[] value){
		_content.put(name, value);
	}
	
	public byte[] getContent(String name){
		
		return _content.get(name);
	}
	
	public Timestamp getTimestamp(){
		return _timestamp;
	}

	public Map<String, byte[]> getAllContent(){
		return _content;
	}
	
	void setAllContent(Map<String, byte[]> c){
		_content = c;
	}
	
	SecureRandom getNonce(){
		return _nonce;
	}

	/*public void buildFinalMessage(Key publicKey, Key privateKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
		cipherContent(publicKey);
		generateHMac(privateKey);
	}*/
}
