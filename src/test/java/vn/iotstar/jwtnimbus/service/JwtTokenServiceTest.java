package vn.iotstar.jwtnimbus.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import vn.iotstar.jwtnimbus.exception.InvalidTokenException;
import vn.iotstar.jwtnimbus.exception.InvalidTokenSignatureException;
import vn.iotstar.jwtnimbus.exception.TokenExpiredException;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test don vi cho {@link JwtTokenService} - khong can khoi dong Spring context.
 *
 * <p>Cac test duoi day kiem chung dung nhung hanh vi de sai cua Nimbus da duoc xac minh thuc nghiem:
 * {@code verify()} tra ve boolean, khong tu kiem tra {@code exp}, va chap nhan token thieu {@code exp}
 * neu khong cau hinh {@code requiredClaims}.
 */
class JwtTokenServiceTest {

    private static final String SECRET =
            "3cfa76ef14937c1c0ea519f8fc057a80fcd04a7420f8e8bcd0a7567c272e007b";
    private static final String OTHER_SECRET =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final long EXPIRATION_MS = 3_600_000L;
    private static final String ISSUER = "jwt-nimbus-test";

    private final JwtTokenService tokenService = new JwtTokenService(SECRET, EXPIRATION_MS, ISSUER);

    private static UserDetails userDetails(String email) {
        return User.withUsername(email)
                .password("khong-dung-trong-test-nay")
                .authorities("ROLE_USER")
                .build();
    }

    /** Ky mot token bang secret chi dinh, de tao tinh huong sai chu ky / het han. */
    private static String sign(JWTClaimsSet claims, String secret) throws Exception {
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        signedJWT.sign(new MACSigner(secret));
        return signedJWT.serialize();
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    // ------------------------------ luong hop le ------------------------------

    @Test
    @DisplayName("Token sinh ra co 3 phan va doc lai duoc dung subject")
    void generatedTokenIsReadable() {
        String token = tokenService.generateToken(userDetails("user@example.test"));

        assertThat(token).isNotBlank();
        assertThat(token.split("\\.")).hasSize(3);
        assertThat(tokenService.extractUsername(token)).isEqualTo("user@example.test");
        assertThat(tokenService.isTokenValid(token, userDetails("user@example.test"))).isTrue();
        assertThat(tokenService.getExpirationTime()).isEqualTo(EXPIRATION_MS);
    }

    @Test
    @DisplayName("Token sinh ra dung HS256, co exp va issuer")
    void generatedTokenHasExpectedHeaderAndClaims() throws Exception {
        String token = tokenService.generateToken(userDetails("user@example.test"));

        SignedJWT parsed = SignedJWT.parse(token);
        assertThat(parsed.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);

        JWTClaimsSet claims = parsed.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo(ISSUER);
        assertThat(claims.getSubject()).isEqualTo("user@example.test");
        assertThat(claims.getIssueTime()).isNotNull();
        assertThat(claims.getExpirationTime()).isAfter(new Date());
        assertThat(claims.getStringListClaim("authorities")).containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("isTokenValid tra ve false khi subject khac")
    void tokenIsNotValidForAnotherUser() {
        String token = tokenService.generateToken(userDetails("user@example.test"));

        assertThat(tokenService.isTokenValid(token, userDetails("khac@example.test"))).isFalse();
    }

    @Test
    @DisplayName("Claim bo sung duoc dua vao token")
    void extraClaimsAreIncluded() throws Exception {
        String token = tokenService.generateToken(
                java.util.Map.of("fullName", "Nguyen Van A"), userDetails("user@example.test"));

        assertThat(SignedJWT.parse(token).getJWTClaimsSet().getStringClaim("fullName"))
                .isEqualTo("Nguyen Van A");
    }

    // ------------------------------ sai chu ky ------------------------------

    @Test
    @DisplayName("Token bi sua payload -> InvalidTokenSignatureException")
    void tamperedTokenIsRejected() {
        String token = tokenService.generateToken(userDetails("user@example.test"));
        String tampered = token.substring(0, token.lastIndexOf('.') + 1)
                + (token.endsWith("A") ? "B" : "A");

        assertThatThrownBy(() -> tokenService.extractUsername(tampered))
                .isInstanceOf(InvalidTokenSignatureException.class);
        assertThat(tokenService.isTokenValid(tampered, userDetails("user@example.test"))).isFalse();
    }

    @Test
    @DisplayName("Token ky bang secret khac -> InvalidTokenSignatureException")
    void tokenSignedWithAnotherSecretIsRejected() throws Exception {
        String token = sign(new JWTClaimsSet.Builder()
                .subject("user@example.test")
                .issuer(ISSUER)
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build(), OTHER_SECRET);

        assertThatThrownBy(() -> tokenService.extractUsername(token))
                .isInstanceOf(InvalidTokenSignatureException.class);
    }

    // ------------------------------ het han ------------------------------

    @Test
    @DisplayName("Token het han -> TokenExpiredException (Nimbus KHONG tu kiem tra exp khi verify)")
    void expiredTokenIsRejected() throws Exception {
        String token = sign(new JWTClaimsSet.Builder()
                .subject("user@example.test")
                .issuer(ISSUER)
                .issueTime(Date.from(Instant.now().minusSeconds(7200)))
                .expirationTime(Date.from(Instant.now().minusSeconds(3600)))
                .build(), SECRET);

        // Bang chung: chu ky VAN hop le, loi nam o claim exp.
        assertThat(SignedJWT.parse(token).verify(new com.nimbusds.jose.crypto.MACVerifier(SECRET)))
                .isTrue();

        assertThatThrownBy(() -> tokenService.extractUsername(token))
                .isInstanceOf(TokenExpiredException.class);
        assertThat(tokenService.isTokenValid(token, userDetails("user@example.test"))).isFalse();
    }

    // ------------------------------ token khong hop le ------------------------------

    @Test
    @DisplayName("Token thieu claim exp -> InvalidTokenException")
    void tokenWithoutExpirationIsRejected() throws Exception {
        String token = sign(new JWTClaimsSet.Builder()
                .subject("user@example.test")
                .issuer(ISSUER)
                .build(), SECRET);

        assertThatThrownBy(() -> tokenService.extractUsername(token))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    @DisplayName("Token sai issuer -> InvalidTokenException (iss duoc kiem tra, khong chi duoc ghi)")
    void tokenWithWrongIssuerIsRejected() throws Exception {
        String token = sign(new JWTClaimsSet.Builder()
                .subject("user@example.test")
                .issuer("ke-gia-mao")
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build(), SECRET);

        assertThatThrownBy(() -> tokenService.extractUsername(token))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    @DisplayName("Token thieu issuer -> InvalidTokenException khi da cau hinh issuer")
    void tokenWithoutIssuerIsRejected() throws Exception {
        String token = sign(new JWTClaimsSet.Builder()
                .subject("user@example.test")
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build(), SECRET);

        assertThatThrownBy(() -> tokenService.extractUsername(token))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    @DisplayName("Token alg=none (tan cong algorithm confusion) -> InvalidTokenException")
    void noneAlgorithmTokenIsRejected() {
        String header = base64Url("{\"alg\":\"none\"}");
        String payload = base64Url("{\"sub\":\"attacker@example.test\",\"exp\":9999999999}");

        assertThatThrownBy(() -> tokenService.extractUsername(header + "." + payload + "."))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    @DisplayName("Token rac -> InvalidTokenException")
    void garbageTokenIsRejected() {
        assertThatThrownBy(() -> tokenService.extractUsername("khong-phai-jwt"))
                .isInstanceOf(InvalidTokenException.class);
        assertThatThrownBy(() -> tokenService.extractUsername(""))
                .isInstanceOf(InvalidTokenException.class);
        assertThatThrownBy(() -> tokenService.extractUsername(null))
                .isInstanceOf(InvalidTokenException.class);
    }

    // ------------------------------ cau hinh sai ------------------------------

    @Test
    @DisplayName("Secret ngan hon 256 bit -> tu choi khoi dong")
    void shortSecretIsRejected() {
        assertThatThrownBy(() -> new JwtTokenService("secret-qua-ngan", EXPIRATION_MS, ISSUER))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("256 bit");
    }

    @Test
    @DisplayName("Khong cau hinh secret -> tu sinh khoa ngau nhien (khong dung khoa mac dinh trong source)")
    void missingSecretIsGeneratedInsteadOfUsingADefault(@TempDir Path tempDir) throws Exception {
        // Khong con khoa mac dinh nao trong source: neu co, bat ky ai doc source deu ky duoc token gia mao.
        String legacyDefaultSecret =
                "3cfa76ef14937c1c0ea519f8fc057a80fcd04a7420f8e8bcd0a7567c272e007b";

        // Dung thu muc tam de `mvn test` khong tao file khoa trong thu muc du an.
        Path secretFile = tempDir.resolve("generated-secret");
        JwtTokenService serviceWithGeneratedKey =
                new JwtTokenService("", EXPIRATION_MS, ISSUER, secretFile.toString());

        assertThat(secretFile).exists();
        assertThat(secretFile.toFile().length()).isPositive();

        // Token cua chinh no van hoat dong binh thuong.
        String ownToken = serviceWithGeneratedKey.generateToken(userDetails("user@example.test"));
        assertThat(serviceWithGeneratedKey.extractUsername(ownToken)).isEqualTo("user@example.test");

        // Nhung token ky bang khoa mac dinh cu (da tung nam trong application.properties) bi tu choi.
        String forgedWithLegacyDefault = sign(new JWTClaimsSet.Builder()
                .subject("user@example.test")
                .issuer(ISSUER)
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build(), legacyDefaultSecret);

        assertThatThrownBy(() -> serviceWithGeneratedKey.extractUsername(forgedWithLegacyDefault))
                .isInstanceOf(InvalidTokenSignatureException.class);
    }

    @Test
    @DisplayName("expiration-time khong duong -> tu choi khoi dong")
    void nonPositiveExpirationIsRejected() {
        assertThatThrownBy(() -> new JwtTokenService(SECRET, 0L, ISSUER))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("Khong dung List.of() rong cho authorities")
    void authoritiesClaimIsAlwaysPresent() throws Exception {
        String token = tokenService.generateToken(userDetails("user@example.test"));

        List<String> authorities = SignedJWT.parse(token).getJWTClaimsSet()
                .getStringListClaim("authorities");
        assertThat(authorities).isNotEmpty();
    }
}
