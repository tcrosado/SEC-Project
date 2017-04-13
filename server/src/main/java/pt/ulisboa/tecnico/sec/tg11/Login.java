package pt.ulisboa.tecnico.sec.tg11;

import com.sun.tools.corba.se.idl.constExpr.Times;

import java.sql.Time;
import java.sql.Timestamp;

public class Login {
	
	private byte[] _username;
	private byte[] _domain;
	private byte[] _password;
	private Timestamp _ts;
	
	public Login(byte[] username, byte[] domain, byte[] password, Timestamp ts){
		
		_username = username;
		_domain = domain;
		_password = password;
		_ts = ts;
	}


	Timestamp getTimestamp(){return _ts;}

	byte[] getUsername(){
		return _username;
	}
	
	byte[] getDomain(){
		return _domain;
	}
	
	byte[] getPassword(){
		return _password;
	}
	
	void setUsername(byte[] user){
		_username = user;
	}
	
	void setDomain(byte[] domain){
		_domain = domain;
	}
	
	void setPassword(byte[] password){
		_password = password;
	}
}
