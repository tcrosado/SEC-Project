package pt.ulisboa.tecnico.sec.tg11.exceptions;

import java.util.UUID;

public class SavePassword418 extends Exception {

	/**
	 *
	 */
	private static final long serialVersionUID = 1L;

	public SavePassword418(){};

	@Override
	public String getMessage() {
		return "The SavePassword server method has tea-potted ";
	}
}
