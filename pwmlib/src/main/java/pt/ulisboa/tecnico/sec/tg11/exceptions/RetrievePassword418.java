package pt.ulisboa.tecnico.sec.tg11.exceptions;

public class RetrievePassword418 extends Exception {

	/**
	 *
	 */
	private static final long serialVersionUID = 1L;

	public RetrievePassword418(){};

	@Override
	public String getMessage() {
		return "The RetrievePassword server method has tea-potted ";
	}
}
