package pt.tecnico.ulisboa.sec.tg11.SharedResources.exceptions;

/**
 * Created by trosado on 29/03/17.
 */
public class GenericException extends Exception {
    Exception _exception;
    public GenericException(Exception e) {
        _exception = e;
    }

    @Override
    public String getMessage() {
        return _exception.getMessage();
    }
}
