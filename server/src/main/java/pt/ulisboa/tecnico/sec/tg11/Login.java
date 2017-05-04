package pt.ulisboa.tecnico.sec.tg11;


import java.sql.Timestamp;

public class Login {
	
	private byte[] _username;
	private byte[] _domain;
	private byte[] _password;
	private Timestamp _physicalTs;
	private Integer _logicalTs;
	
	public Login(byte[] username, byte[] domain, byte[] password, Integer logicalTs,Timestamp physicalTs){
		
		_username = username;
		_domain = domain;
		_password = password;
		_physicalTs = physicalTs;
		_logicalTs = logicalTs;
	}


	Timestamp getPhysicalTimestamp(){return _physicalTs;}

	Integer getLogicalTimestamp() {
		return _logicalTs;
	}


	public void setPhysicalTs(Timestamp _physicalTs) {
		this._physicalTs = _physicalTs;
	}

	public void setLogicalTs(Integer _logicalTs) {
		this._logicalTs = _logicalTs;
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
