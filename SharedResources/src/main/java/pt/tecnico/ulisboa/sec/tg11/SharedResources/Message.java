package pt.tecnico.ulisboa.sec.tg11.SharedResources;


import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

class Message implements Serializable{
	
	private Map<String, byte[]> _content;
	private Timestamp _timestamp;
	private UUID _userid;
	private BigInteger _nonce;

	private byte[] _signature;

	byte[] getSignature() {
		return _signature;
	}

	 void setSignature(byte[] _signature) {
		this._signature = _signature;
	}



	Message() {

		Calendar cal = Calendar.getInstance();
		_nonce = new BigInteger(64, new SecureRandom());
		_content = new HashMap<String, byte[]>();

		_timestamp = new Timestamp(Calendar.getInstance().getTimeInMillis());

	}
	
	Message(UUID uid){
		this();
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
	
	Timestamp getTimestamp() {
		return _timestamp;
	}

	Map<String, byte[]> getAllContent(){
		return _content;
	}
	
	void setAllContent(Map<String, byte[]> c){
		_content = c;
	}
	
	BigInteger getNonce(){
		return _nonce;
	}


}
