package vn.iotstar.jwtnimbus.exception;

/** Email da duoc dang ky. Tra ve HTTP 409. */
public class EmailAlreadyUsedException extends RuntimeException {

    public EmailAlreadyUsedException(String message) {
        super(message);
    }
}
