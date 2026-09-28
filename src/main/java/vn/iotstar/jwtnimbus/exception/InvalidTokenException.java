package vn.iotstar.jwtnimbus.exception;

/** JWT sai dinh dang, sai thuat toan, thieu claim bat buoc hoac khong doc duoc. */
public class InvalidTokenException extends TokenException {

    public InvalidTokenException(String message) {
        super(message);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
