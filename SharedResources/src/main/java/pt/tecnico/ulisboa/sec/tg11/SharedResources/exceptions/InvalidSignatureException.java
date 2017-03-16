package pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions;

/**
 * Created by trosado on 12/03/17.
 */
public class InvalidSignatureException extends Exception {

	
	@Override
	public String getMessage() {
		return "Impossible to verify signature.";
	}
}
