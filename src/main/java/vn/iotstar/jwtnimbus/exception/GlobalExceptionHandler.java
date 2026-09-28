package vn.iotstar.jwtnimbus.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Tuong ung "Buoc 10: Nem Exception" trong bai giang.
 *
 * <p>Bang anh xa loi -&gt; ma HTTP giu nguyen nhu bai giang:
 * <pre>
 * Loi xac thuc                          Ngoai le (bai giang)     HTTP   Ngoai le (project nay)
 * ------------------------------------  -----------------------  -----  ---------------------------------------
 * Thong tin dang nhap khong hop le      BadCredentialsException  401    BadCredentialsException
 * Tai khoan bi khoa                     AccountStatusException   403    AccountStatusException
 * Khong duoc phep truy cap tai nguyen   AccessDeniedException    403    AccessDeniedException
 * JWT khong hop le (sai chu ky)         SignatureException       401    InvalidTokenSignatureException
 * JWT da het han                        ExpiredJwtException      401    TokenExpiredException
 * JWT sai dinh dang / sai thuat toan    (khong co trong bai)     401    InvalidTokenException
 * </pre>
 *
 * <p>Nguyen tac: khong tra {@code ex.getMessage()} cua loi 500 ra ngoai (co the lo chi tiet noi bo);
 * chi ghi log day du o server.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // ------------------------- Loi JWT (Nimbus) -------------------------

    @ExceptionHandler(InvalidTokenSignatureException.class)
    public ProblemDetail handleInvalidTokenSignature(InvalidTokenSignatureException ex) {
        log.warn("JWT sai chu ky: {}", ex.getMessage());
        return problem(HttpStatus.UNAUTHORIZED, "Unauthorized", "The JWT signature is invalid");
    }

    @ExceptionHandler(TokenExpiredException.class)
    public ProblemDetail handleTokenExpired(TokenExpiredException ex) {
        log.warn("JWT het han: {}", ex.getMessage());
        return problem(HttpStatus.UNAUTHORIZED, "Unauthorized", "The JWT token has expired");
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ProblemDetail handleInvalidToken(InvalidTokenException ex) {
        log.warn("JWT khong hop le: {}", ex.getMessage());
        return problem(HttpStatus.UNAUTHORIZED, "Unauthorized", "The JWT token is invalid");
    }

    @ExceptionHandler(TokenGenerationException.class)
    public ProblemDetail handleTokenGeneration(TokenGenerationException ex) {
        log.error("Khong the tao JWT", ex);
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error",
                "Khong the tao token, vui long thu lai sau.");
    }

    // ------------------------- Loi xac thuc / phan quyen -------------------------

    @ExceptionHandler(BadCredentialsException.class)
    public ProblemDetail handleBadCredentials(BadCredentialsException ex) {
        log.warn("Dang nhap that bai");
        return problem(HttpStatus.UNAUTHORIZED, "Unauthorized", "The username or password is incorrect");
    }

    @ExceptionHandler(AccountStatusException.class)
    public ProblemDetail handleAccountStatus(AccountStatusException ex) {
        log.warn("Tai khoan khong kha dung: {}", ex.getMessage());
        return problem(HttpStatus.FORBIDDEN, "Forbidden", "The account is locked");
    }

    @ExceptionHandler(AuthenticationException.class)
    public ProblemDetail handleAuthentication(AuthenticationException ex) {
        log.warn("Xac thuc that bai: {}", ex.getMessage());
        return problem(HttpStatus.UNAUTHORIZED, "Unauthorized", "Xac thuc that bai");
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ProblemDetail handleAccessDenied(AccessDeniedException ex) {
        log.warn("Tu choi truy cap: {}", ex.getMessage());
        return problem(HttpStatus.FORBIDDEN, "Forbidden", "You are not authorized to access this resource");
    }

    // ------------------------- Loi nghiep vu / dau vao -------------------------

    @ExceptionHandler(EmailAlreadyUsedException.class)
    public ProblemDetail handleEmailAlreadyUsed(EmailAlreadyUsedException ex) {
        log.warn("Dang ky trung email: {}", ex.getMessage());
        return problem(HttpStatus.CONFLICT, "Conflict", "Email nay da duoc dang ky");
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new LinkedHashMap<>();
        for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
            errors.putIfAbsent(fieldError.getField(), fieldError.getDefaultMessage());
        }

        ProblemDetail errorDetail = problem(HttpStatus.BAD_REQUEST, "Bad Request",
                "Du lieu gui len khong hop le");
        errorDetail.setProperty("errors", errors);
        return errorDetail;
    }

    // ------------------------- Loi giao thuc HTTP -------------------------
    // Phai bat rieng cac loi nay TRUOC nhanh Exception.class, neu khong chung se bi doi
    // thanh 500 (xem docs/SECURITY-REVIEW.md muc 8). Day la loi phia client, khong phai loi he thong,
    // nen chi ghi log muc WARN va KHONG in stack trace (tranh lam ngap log tu endpoint cong khai).

    @ExceptionHandler({NoResourceFoundException.class, NoHandlerFoundException.class})
    public ProblemDetail handleNotFound(Exception ex) {
        log.warn("Khong tim thay tai nguyen: {}", ex.getMessage());
        return problem(HttpStatus.NOT_FOUND, "Not Found", "Khong tim thay tai nguyen yeu cau.");
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ProblemDetail handleMethodNotSupported(HttpRequestMethodNotSupportedException ex) {
        log.warn("Sai phuong thuc HTTP: {}", ex.getMessage());
        return problem(HttpStatus.METHOD_NOT_ALLOWED, "Method Not Allowed",
                "Phuong thuc HTTP khong duoc ho tro cho duong dan nay.");
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ProblemDetail handleMediaTypeNotSupported(HttpMediaTypeNotSupportedException ex) {
        log.warn("Content-Type khong duoc ho tro: {}", ex.getMessage());
        return problem(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "Unsupported Media Type",
                "Content-Type khong duoc ho tro. Hay dung application/json.");
    }

    @ExceptionHandler({
            HttpMessageNotReadableException.class,
            MethodArgumentTypeMismatchException.class,
            MissingServletRequestParameterException.class
    })
    public ProblemDetail handleUnreadableRequest(Exception ex) {
        log.warn("Khong doc duoc yeu cau: {}", ex.getMessage());
        return problem(HttpStatus.BAD_REQUEST, "Bad Request",
                "Khong doc duoc du lieu gui len. Kiem tra lai dinh dang JSON.");
    }

    // ------------------------- Loi con lai -------------------------

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleUnexpected(Exception ex) {
        log.error("Loi khong mong doi", ex);
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error",
                "Unknown internal server error.");
    }

    private ProblemDetail problem(HttpStatus status, String title, String description) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(status, description);
        problemDetail.setTitle(title);
        problemDetail.setType(URI.create("about:blank"));
        // Giu ten property "description" giong bai giang de client/tai lieu de doi chieu.
        problemDetail.setProperty("description", description);
        return problemDetail;
    }
}
