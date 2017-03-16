package pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions;

import java.util.UUID;

public class InvalidRequestException extends Exception {

	/**
	 *
	 */
	private static final long serialVersionUID = 1L;

	private UUID userID;
	private byte[] domain;
	private byte[] username;


	public InvalidRequestException(UUID userID, byte[] domain, byte[] username) {
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
