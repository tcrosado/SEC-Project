package pt.ulisboa.tecnico.sec.tg11.exceptions;

import java.util.UUID;

public class RegisterUser418 extends Exception {

	/**
	 *
	 */
	private static final long serialVersionUID = 1L;

	public RegisterUser418(){};

	@Override
	public String getMessage() {
		return "The register server method has tea-potted ";
	}
}
