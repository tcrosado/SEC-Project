package pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions;

import java.math.BigInteger;
import java.util.UUID;

public class WrongUserIDException extends Exception {
	
	UUID _uid;
	
	public WrongUserIDException(UUID uuid){
		_uid = uuid;
	}
	
	@Override
	public String getMessage() {
		return "This userID does not exist: "+_uid;
	}
}
