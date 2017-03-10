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
	private SecureMessage security = new SecureMessage(this);
	
	public Message(){
		_nonce = security.generateNonce();
		_content = new HashMap<String, byte[]>();
		_timestamp = security.generateTimeStamp();
	}
	
	public Message(UUID uid){
		_userid = uid;
		_nonce = security.generateNonce();
		_content = new HashMap<String, byte[]>();
		_timestamp = security.generateTimeStamp();
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
	
	public void setTimestamp(Timestamp t){
		_timestamp = t;
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
