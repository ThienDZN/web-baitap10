package vn.iotstar.jwtnimbus.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.net.URI;

/**
 * Tra ve JSON chuan RFC 9457 ({@code ProblemDetail}) khi request bi tu choi truoc khi vao controller.
 *
 * <p>Mac dinh Spring Security tra ve trang HTML/redirect, khong phu hop voi REST API. Class nay
 * dam bao: thieu token -&gt; 401, khong du quyen -&gt; 403, dung dinh dang voi
 * {@code GlobalExceptionHandler}.
 */
@Component
public class RestSecurityErrorHandler implements AuthenticationEntryPoint, AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    public RestSecurityErrorHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        writeProblem(response, HttpStatus.UNAUTHORIZED,
                "Unauthorized", "Ban can dang nhap (Authorization: Bearer <token>) de truy cap tai nguyen nay.");
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        writeProblem(response, HttpStatus.FORBIDDEN,
                "Forbidden", "Ban khong co quyen truy cap tai nguyen nay.");
    }

    private void writeProblem(HttpServletResponse response, HttpStatus status,
                              String title, String detail) throws IOException {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(status, detail);
        problemDetail.setTitle(title);
        problemDetail.setType(URI.create("about:blank"));
        problemDetail.setProperty("description", detail);

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        objectMapper.writeValue(response.getOutputStream(), problemDetail);
    }
}
