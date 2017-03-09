package pt.tecnico.ulisboa.sec.tg11.SharedResources;

import java.sql.Timestamp;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class Message {
	
	private Map<String, String> _content;
	private Timestamp _timestamp;
	private UUID _userid;
	
	public Message(){
		_content = new HashMap<String, String>();
		_timestamp = new Timestamp(Calendar.getInstance().getTimeInMillis());
	}
	
	public Message(UUID uid){
		_userid = uid;
	}
	
	public UUID getUserId(){
		return _userid;
	}
	
	public void addContent(String name, String value){
		
		_content.put(name, value);
	}
	
	public String getContent(String name){
		return _content.get(name);
	}
	
	public Timestamp getTimestamp(){
		return _timestamp;
	}

}
