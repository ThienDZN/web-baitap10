package vn.iotstar.jwtnimbus;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test tich hop toan bo luong JWT: dang ky -&gt; dang nhap -&gt; goi API bang Bearer token,
 * cung nhu bang ma loi HTTP tuong ung voi bang trong bai giang (slide 30).
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "security.jwt.secret-key=3cfa76ef14937c1c0ea519f8fc057a80fcd04a7420f8e8bcd0a7567c272e007b",
        "security.jwt.expiration-time=3600000",
        "security.jwt.issuer=jwt-nimbus-integration-test"
})
class JwtNimbusIntegrationTest {

    private static final String SECRET =
            "3cfa76ef14937c1c0ea519f8fc057a80fcd04a7420f8e8bcd0a7567c272e007b";
    private static final String OTHER_SECRET =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    /** Phai khop security.jwt.issuer trong @TestPropertySource o tren. */
    private static final String ISSUER = "jwt-nimbus-integration-test";

    private static final AtomicInteger SEQUENCE = new AtomicInteger();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    // ------------------------------ tien ich ------------------------------

    private static String uniqueEmail() {
        return "user" + SEQUENCE.incrementAndGet() + "." + System.nanoTime() + "@example.test";
    }

    private String signup(String email, String password, String fullName) throws Exception {
        String body = objectMapper.writeValueAsString(
                java.util.Map.of("email", email, "password", password, "fullName", fullName));

        return mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    private String login(String email, String password) throws Exception {
        String body = objectMapper.writeValueAsString(
                java.util.Map.of("email", email, "password", password));

        MvcResult result = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode json = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(json.path("tokenType").asText()).isEqualTo("Bearer");
        assertThat(json.path("expiresIn").asLong()).isEqualTo(3_600_000L);
        return json.path("token").asText();
    }

    /** Ky mot token bang secret tuy y - dung de tao token het han / sai chu ky. */
    private static String sign(JWTClaimsSet claims, String secret) throws Exception {
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        signedJWT.sign(new MACSigner(secret));
        return signedJWT.serialize();
    }

    // ------------------------------ dang ky ------------------------------

    @Test
    @DisplayName("POST /auth/signup tra ve 200 va KHONG lam lo password")
    void signupDoesNotLeakPassword() throws Exception {
        String email = uniqueEmail();
        String response = signup(email, "MatKhau@123", "Nguyen Van A");

        JsonNode json = objectMapper.readTree(response);
        assertThat(json.path("email").asText()).isEqualTo(email);
        assertThat(json.path("fullName").asText()).isEqualTo("Nguyen Van A");
        assertThat(json.path("role").asText()).isEqualTo("USER");

        // Diem khac biet quan trong so voi bai giang: khong duoc tra ve password (hash).
        assertThat(json.has("password")).isFalse();
        assertThat(response).doesNotContain("$2a$").doesNotContain("$2b$");
    }

    @Test
    @DisplayName("Dang ky trung email -> 409")
    void signupWithDuplicateEmailConflicts() throws Exception {
        String email = uniqueEmail();
        signup(email, "MatKhau@123", "Nguyen Van A");

        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(java.util.Map.of(
                                "email", email, "password", "MatKhau@123", "fullName", "Nguoi Khac"))))
                .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("Du lieu dang ky khong hop le -> 400 kem chi tiet loi")
    void signupWithInvalidBodyIsRejected() throws Exception {
        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(java.util.Map.of(
                                "email", "khong-phai-email", "password", "123", "fullName", ""))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors").exists());
    }

    // ------------------------------ dang nhap ------------------------------

    @Test
    @DisplayName("Sai mat khau -> 401")
    void loginWithWrongPasswordIsUnauthorized() throws Exception {
        String email = uniqueEmail();
        signup(email, "MatKhau@123", "Nguyen Van A");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(java.util.Map.of(
                                "email", email, "password", "sai-mat-khau"))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Email khong ton tai -> 401 (khong lo email nao da dang ky)")
    void loginWithUnknownEmailIsUnauthorized() throws Exception {
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(java.util.Map.of(
                                "email", uniqueEmail(), "password", "MatKhau@123"))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Dang nhap bang chu HOA/thuong deu duoc (email duoc chuan hoa)")
    void loginIsCaseInsensitiveForEmail() throws Exception {
        String email = uniqueEmail();
        signup(email, "MatKhau@123", "Nguyen Van A");

        String token = login(email.toUpperCase(java.util.Locale.ROOT), "MatKhau@123");
        assertThat(token).isNotBlank();
    }

    // ------------------------------ API duoc bao ve ------------------------------

    @Test
    @DisplayName("GET /users/me khong co token -> 401")
    void protectedEndpointWithoutTokenIsUnauthorized() throws Exception {
        mockMvc.perform(get("/users/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /users/me va /users voi token hop le -> 200")
    void protectedEndpointsWithValidTokenAreOk() throws Exception {
        String email = uniqueEmail();
        signup(email, "MatKhau@123", "Nguyen Van A");
        String token = login(email, "MatKhau@123");

        mockMvc.perform(get("/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.password").doesNotExist());

        mockMvc.perform(get("/users").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].password").doesNotExist());
    }

    @Test
    @DisplayName("Token bi sua -> 401 (loi chu ky)")
    void tamperedTokenIsUnauthorized() throws Exception {
        String email = uniqueEmail();
        signup(email, "MatKhau@123", "Nguyen Van A");
        String token = login(email, "MatKhau@123");

        String tampered = token.substring(0, token.lastIndexOf('.') + 1)
                + (token.endsWith("A") ? "B" : "A");

        mockMvc.perform(get("/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + tampered))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.description").value("The JWT signature is invalid"));
    }

    @Test
    @DisplayName("Token ky bang secret khac -> 401")
    void tokenSignedWithWrongSecretIsUnauthorized() throws Exception {
        String token = sign(new JWTClaimsSet.Builder()
                .subject("ke.tan.cong@example.test")
                .issuer(ISSUER)
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build(), OTHER_SECRET);

        mockMvc.perform(get("/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Token het han -> 401 voi thong bao het han")
    void expiredTokenIsUnauthorized() throws Exception {
        String token = sign(new JWTClaimsSet.Builder()
                .subject("user@example.test")
                .issuer(ISSUER)
                .issueTime(Date.from(Instant.now().minusSeconds(7200)))
                .expirationTime(Date.from(Instant.now().minusSeconds(3600)))
                .build(), SECRET);

        mockMvc.perform(get("/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.description").value("The JWT token has expired"));
    }

    @Test
    @DisplayName("Token sai issuer -> 401")
    void tokenWithWrongIssuerIsUnauthorized() throws Exception {
        String token = sign(new JWTClaimsSet.Builder()
                .subject("user@example.test")
                .issuer("ke-gia-mao")
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build(), SECRET);

        mockMvc.perform(get("/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Token hop le nhung nguoi dung khong ton tai -> 401")
    void tokenForUnknownUserIsUnauthorized() throws Exception {
        String token = sign(new JWTClaimsSet.Builder()
                .subject("khong.ton.tai@example.test")
                .issuer(ISSUER)
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build(), SECRET);

        mockMvc.perform(get("/users/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Header Authorization sai dinh dang -> 401")
    void malformedAuthorizationHeaderIsUnauthorized() throws Exception {
        String email = uniqueEmail();
        signup(email, "MatKhau@123", "Nguyen Van A");
        String token = login(email, "MatKhau@123");

        mockMvc.perform(get("/users/me").header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isUnauthorized());
    }

    // ------------------------------ view ------------------------------

    @Test
    @DisplayName("Trang /login va /register truy cap duoc khong can token")
    void publicViewsAreAccessible() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Dang nhap")));

        mockMvc.perform(get("/register"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Dang ky")));

        mockMvc.perform(get("/user/profile"))
                .andExpect(status().isOk());
    }

    // ------------------------------ ma loi giao thuc HTTP ------------------------------
    // Cac test nay bao ve loi hoi quy: nhanh @ExceptionHandler(Exception.class) tung bien
    // 404/405/415/400 thanh 500 (xem docs/SECURITY-REVIEW.md muc 8).

    @Test
    @DisplayName("Duong dan khong ton tai -> 404, khong bi doi thanh 500")
    void unknownPathIsNotFound() throws Exception {
        String email = uniqueEmail();
        signup(email, "MatKhau@123", "Nguyen Van A");
        String token = login(email, "MatKhau@123");

        mockMvc.perform(get("/khong-ton-tai").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("Sai phuong thuc HTTP -> 405, khong bi doi thanh 500")
    void wrongHttpMethodIsMethodNotAllowed() throws Exception {
        mockMvc.perform(put("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isMethodNotAllowed());
    }

    @Test
    @DisplayName("Content-Type khong duoc ho tro -> 415, khong bi doi thanh 500")
    void unsupportedMediaTypeIsRejected() throws Exception {
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("email=a@example.test&password=MatKhau@123"))
                .andExpect(status().isUnsupportedMediaType());
    }

    @Test
    @DisplayName("Body JSON hong -> 400, khong bi doi thanh 500")
    void malformedJsonBodyIsBadRequest() throws Exception {
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{khong-phai-json"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Thieu body -> 400, khong bi doi thanh 500")
    void missingBodyIsBadRequest() throws Exception {
        mockMvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("H2 console KHONG truy cap duoc an danh khi dung cau hinh mac dinh")
    void h2ConsoleIsNotPublicByDefault() throws Exception {
        mockMvc.perform(get("/h2-console"))
                .andExpect(status().isUnauthorized());
    }
}
