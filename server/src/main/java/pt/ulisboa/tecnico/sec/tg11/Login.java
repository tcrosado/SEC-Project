package pt.ulisboa.tecnico.sec.tg11;

public class Login {
	
	private byte[] _username;
	private byte[] _domain;
	private byte[] _password;
	
	public Login(byte[] username, byte[] domain, byte[] password){
		
		_username = username;
		_domain = domain;
		_password = password;
	}
	
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
