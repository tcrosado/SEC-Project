package pt.ulisboa.tecnico.sec.tg11.exceptions;

/**
 * Created by tiago on 21/04/2017.
 */
public class ActionFailedException extends Exception {
    @Override
    public String getMessage() {
        return "Action Failed";
    }
}
