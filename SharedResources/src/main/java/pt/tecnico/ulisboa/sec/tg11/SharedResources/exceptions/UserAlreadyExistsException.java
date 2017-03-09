package pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions;

import java.security.Key;
import java.util.UUID;

public class UserAlreadyExistsException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private Key _publickey;

	public UserAlreadyExistsException(Key publicKey) {
		publicKey = publicKey;

	}

	@Override
	public String getMessage() {
		return "The publickey '" + _publickey.toString() + "has already been registered.";
	}
}
