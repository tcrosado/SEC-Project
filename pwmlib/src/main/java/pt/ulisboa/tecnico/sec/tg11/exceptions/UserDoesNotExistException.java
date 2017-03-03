package pt.ulisboa.tecnico.sec.tg11.exceptions;

import java.util.UUID;

public class UserDoesNotExistException extends Exception {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private UUID userId;

	public UserDoesNotExistException(UUID user) {
		userId = user;
	}

	@Override
	public String getMessage() {
		return "The user '" + userId + "' does not exist.";
	}
}
