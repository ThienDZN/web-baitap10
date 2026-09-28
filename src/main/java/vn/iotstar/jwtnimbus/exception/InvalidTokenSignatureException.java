package vn.iotstar.jwtnimbus.exception;

/**
 * Chu ky JWT khong hop le (sai secret hoac token bi sua).
 *
 * <p>Tuong ung {@code io.jsonwebtoken.SignatureException} trong bai giang, va tuong ung
 * ket qua {@code SignedJWT.verify(verifier) == false} cua Nimbus.
 */
public class InvalidTokenSignatureException extends TokenException {

    public InvalidTokenSignatureException(String message) {
        super(message);
    }

    public InvalidTokenSignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
