package vn.iotstar.jwtnimbus.exception;

/** Khong the ky JWT (loi crypto noi bo). Loi phia server, tra ve HTTP 500. */
public class TokenGenerationException extends TokenException {

    public TokenGenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}
