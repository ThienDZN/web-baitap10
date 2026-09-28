package vn.iotstar.jwtnimbus.exception;

/**
 * Lop cha cho moi loi lien quan den JWT.
 *
 * <p>Trong bai giang (dung JJWT), cac loi nay duoc nem truc tiep boi thu vien
 * ({@code io.jsonwebtoken.SignatureException}, {@code io.jsonwebtoken.ExpiredJwtException}).
 * Voi Nimbus, {@code SignedJWT.verify(...)} tra ve {@code boolean} chu khong nem exception,
 * nen tang service chu dong phan loai loi va nem ra cac exception duoi day. Nho vay tang web
 * khong phu thuoc truc tiep vao kieu exception cua thu vien JWT.
 */
public class TokenException extends RuntimeException {

    public TokenException(String message) {
        super(message);
    }

    public TokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
