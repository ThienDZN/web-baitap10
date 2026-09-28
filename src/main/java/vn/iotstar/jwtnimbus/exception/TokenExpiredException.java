package vn.iotstar.jwtnimbus.exception;

/**
 * JWT da het han ({@code exp} nho hon thoi diem hien tai).
 *
 * <p>Tuong ung {@code io.jsonwebtoken.ExpiredJwtException} trong bai giang. Voi Nimbus,
 * exception nay duoc nem ra tu {@code DefaultJWTClaimsVerifier}
 * ({@code com.nimbusds.jwt.proc.ExpiredJWTException}) va duoc chuyen thanh kieu cua ung dung.
 */
public class TokenExpiredException extends TokenException {

    public TokenExpiredException(String message) {
        super(message);
    }

    public TokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
