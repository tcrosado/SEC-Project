package pt.tecnico.ulisboa.sec.tg11.PWInterface.exceptions;

import java.util.UUID;

public class PasswordDoesNotExistException extends Exception {

	/**
	 *
	 */
	private static final long serialVersionUID = 1L;

	private UUID userID;
	private byte[] domain;
	private byte[] username;


	public PasswordDoesNotExistException(UUID userID, byte[] domain, byte[] username) {
		userID = userID;
	}
	
	public UUID getUserId() {
		return userID;

	}
	@Override
	public String getMessage() {
		return "The username/domain tuple of userid:  '" + userID + "' does not exists.";
	}
	
}
