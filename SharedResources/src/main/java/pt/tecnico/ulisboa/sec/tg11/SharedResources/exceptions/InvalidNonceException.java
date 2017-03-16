package pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions;

import java.math.BigInteger;

public class InvalidNonceException extends Exception {
	
	BigInteger _nonce;
	
	public InvalidNonceException(BigInteger nonce){
		_nonce = nonce;
	}
	
	@Override
	public String getMessage() {
		return "Invalid nonce: "+_nonce;
	}
}
