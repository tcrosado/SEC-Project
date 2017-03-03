package pt.ulisboa.tecnico.sec.tg11.exceptions;

import java.util.UUID;

public class UserAlreadyExistsException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private UUID userId;

	public UserAlreadyExistsException(UUID user) {
		userId = user;
	}

	@Override
	public String getMessage() {
		return "The user '" + userId + "' already exists.";
	}
	
}
