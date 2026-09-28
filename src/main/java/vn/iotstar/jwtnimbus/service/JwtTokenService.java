package vn.iotstar.jwtnimbus.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.ExpiredJWTException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import vn.iotstar.jwtnimbus.exception.InvalidTokenException;
import vn.iotstar.jwtnimbus.exception.InvalidTokenSignatureException;
import vn.iotstar.jwtnimbus.exception.TokenException;
import vn.iotstar.jwtnimbus.exception.TokenExpiredException;
import vn.iotstar.jwtnimbus.exception.TokenGenerationException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;

/**
 * Tao va xac thuc JWT bang thu vien <strong>Nimbus JOSE+JWT</strong>.
 *
 * <p>Tuong ung class {@code JwtService} (dung JJWT) trong bai giang - "Buoc 4".
 *
 * <h2>Bang doi chieu JJWT -&gt; Nimbus</h2>
 * <pre>
 * JJWT                                              Nimbus JOSE+JWT
 * ------------------------------------------------  ------------------------------------------
 * Jwts.builder()                                    new JWTClaimsSet.Builder()
 * .signWith(key, Jwts.SIG.HS256)                    new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims); jwt.sign(new MACSigner(secret))
 * .compact()                                        signedJWT.serialize()
 * Jwts.parser().verifyWith(key).build()             SignedJWT.parse(token); signedJWT.verify(new MACVerifier(secret))
 *   .parseSignedClaims(token).getPayload()          signedJWT.getJWTClaimsSet()
 * Decoders.BASE64.decode(secret)                    secretKey.getBytes(StandardCharsets.UTF_8)
 * Keys.hmacShaKeyFor(bytes)                         new MACSigner(byte[]) / new MACVerifier(byte[])
 * (JJWT tu kiem tra exp khi parse)                  DefaultJWTClaimsVerifier (Nimbus KHONG tu kiem tra exp)
 * </pre>
 *
 * <h2>Luu y bao mat da kiem chung thuc nghiem voi nimbus-jose-jwt 10.10</h2>
 * <ul>
 *   <li>{@code SignedJWT.verify(...)} <strong>chi</strong> kiem tra chu ky, KHONG kiem tra {@code exp}.
 *       Token het han van verify = {@code true}. Vi vay phai goi {@link DefaultJWTClaimsVerifier}
 *       (hoac tu so sanh {@code exp}) truoc khi tin bat ky claim nao.</li>
 *   <li>{@code DefaultJWTClaimsVerifier} mac dinh <strong>khong</strong> bat buoc phai co claim {@code exp}.
 *       Vi vay service nay truyen {@code requiredClaims = {"exp"}} de bat buoc token phai co han.</li>
 *   <li>{@code SignedJWT.verify(...)} tra ve {@code boolean} (khong nem exception khi sai chu ky),
 *       nen phai tu kiem tra gia tri tra ve.</li>
 *   <li>Token phai co {@code exp} va (neu cau hinh {@code security.jwt.issuer}) {@code iss} phai khop
 *       chinh xac; {@code DefaultJWTClaimsVerifier} kiem tra {@code iss} qua {@code exactMatchClaims}.</li>
 *   <li>{@code DefaultJWTClaimsVerifier} cho phep lech gio 60 giay ({@code maxClockSkew} mac dinh),
 *       nen token thuc te con dung duoc them 60 giay sau {@code exp}. Project nay khong doi gia tri nay.</li>
 * </ul>
 */
@Service
public class JwtTokenService {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenService.class);

    /** "alg": "HS256" trong header - giong bai giang. */
    public static final JWSAlgorithm ALGORITHM = JWSAlgorithm.HS256;

    /** HS256 yeu cau khoa >= 256 bit = 32 byte (Nimbus nem KeyLengthException neu ngan hon). */
    private static final int MIN_SECRET_BYTES = 32;

    private static final String CLAIM_AUTHORITIES = "authorities";
    private static final String CLAIM_EXPIRATION = "exp";

    /** Ten file luu khoa sinh tu dong khi chua dat JWT_SECRET_KEY (da co trong .gitignore). */
    public static final String GENERATED_SECRET_FILE = ".jwt-secret-key";

    /** Khoa bi mat duoi dang byte. Khong luu dang String de han che lo khoa trong heap dump/log. */
    private final byte[] secret;

    private final long expirationMillis;

    private final String issuer;

    private final DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier;

    /**
     * Constructor chinh cho Spring. Danh dau {@link Autowired} vi class co them mot constructor
     * tien dung cho test (Spring can biet ro constructor nao de dung de inject).
     */
    @Autowired
    public JwtTokenService(
            @Value("${security.jwt.secret-key:}") String secretKey,
            @Value("${security.jwt.expiration-time}") long expirationMillis,
            @Value("${security.jwt.issuer:}") String issuer,
            @Value("${security.jwt.secret-file:" + GENERATED_SECRET_FILE + "}") String secretFilePath) {

        this.secret = resolveSecret(secretKey, secretFilePath);
        if (expirationMillis <= 0) {
            throw new IllegalStateException(
                    "security.jwt.expiration-time phai la so duong (millisecond).");
        }
        this.expirationMillis = expirationMillis;
        this.issuer = issuer;

        // Bat buoc token phai co 'exp', va neu co cau hinh issuer thi 'iss' phai khop chinh xac.
        // Xem javadoc cua class.
        JWTClaimsSet.Builder exactMatchClaims = new JWTClaimsSet.Builder();
        if (StringUtils.hasText(issuer)) {
            exactMatchClaims.issuer(issuer);
        }
        this.claimsVerifier = new DefaultJWTClaimsVerifier<>(
                exactMatchClaims.build(), Set.of(CLAIM_EXPIRATION));

        log.info("JwtTokenService khoi tao: alg={}, expiration={} ms, issuer={}",
                ALGORITHM.getName(), expirationMillis, StringUtils.hasText(issuer) ? issuer : "(none)");
    }

    /** Constructor tien dung cho test/demo: dung vi tri file khoa mac dinh. */
    public JwtTokenService(String secretKey, long expirationMillis, String issuer) {
        this(secretKey, expirationMillis, issuer, GENERATED_SECRET_FILE);
    }

    /**
     * Lay khoa ky tu cau hinh, hoac tu sinh khoa ngau nhien neu chua cau hinh.
     *
     * <p><strong>Khong</strong> co khoa mac dinh nao duoc nhung san trong source: neu co, bat ky ai
     * doc duoc source deu ky duoc token gia mao. Vi vay:
     * <ol>
     *   <li>Neu dat {@code JWT_SECRET_KEY} -&gt; dung gia tri do (phai >= 32 byte).</li>
     *   <li>Neu khong dat -&gt; dung file {@code security.jwt.secret-file} (mac dinh
     *       {@value #GENERATED_SECRET_FILE}) trong thu muc lam viec; chua co thi sinh khoa ngau nhien
     *       256 bit va luu lai (quyen chi chu so huu). Nho vay token van con hieu luc sau khi restart,
     *       nhung moi may co khoa rieng.</li>
     *   <li>Neu khong ghi duoc file -&gt; dung khoa ngau nhien trong bo nho (token mat hieu luc khi restart).</li>
     * </ol>
     */
    private byte[] resolveSecret(String secretKey, String secretFilePath) {
        if (StringUtils.hasText(secretKey)) {
            byte[] configured = secretKey.getBytes(StandardCharsets.UTF_8);
            if (configured.length < MIN_SECRET_BYTES) {
                throw new IllegalStateException(
                        "security.jwt.secret-key phai dai it nhat " + MIN_SECRET_BYTES
                                + " byte (256 bit) cho HS256; hien tai chi co " + configured.length
                                + " byte. Tao khoa moi bang: openssl rand -hex 32");
            }
            return configured;
        }

        Path secretFile = Path.of(secretFilePath).toAbsolutePath();
        try {
            if (Files.exists(secretFile)) {
                byte[] stored = Files.readString(secretFile, StandardCharsets.UTF_8)
                        .trim().getBytes(StandardCharsets.UTF_8);
                if (stored.length >= MIN_SECRET_BYTES) {
                    log.warn("Chua dat JWT_SECRET_KEY - dang dung khoa sinh tu dong trong {}.",
                            secretFile);
                    return stored;
                }
                log.warn("File {} khong hop le (qua ngan) - se sinh khoa moi.", secretFile);
            }

            String generated = generateSecretHex();
            Files.writeString(secretFile, generated, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
            restrictToOwner(secretFile);
            log.warn("Chua dat JWT_SECRET_KEY - da sinh khoa ngau nhien 256 bit va luu tai {}. "
                    + "Khi trien khai that hay dat bien moi truong JWT_SECRET_KEY.", secretFile);
            return generated.getBytes(StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException e) {
            log.warn("Khong ghi duoc file khoa ({}). Dung khoa ngau nhien trong bo nho: "
                    + "token se het hieu luc khi restart. Chi tiet: {}", secretFile, e.getMessage());
            return generateSecretHex().getBytes(StandardCharsets.UTF_8);
        }
    }

    private static String generateSecretHex() {
        byte[] key = new byte[MIN_SECRET_BYTES];
        new SecureRandom().nextBytes(key);
        return HexFormat.of().formatHex(key);
    }

    private static void restrictToOwner(Path path) {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (IOException | UnsupportedOperationException e) {
            // He thong file khong ho tro POSIX (vi du Windows) - bo qua.
            log.debug("Khong dat duoc quyen chi chu so huu cho {}: {}", path, e.getMessage());
        }
    }

    /** Tao token voi cac claim mac dinh. */
    public String generateToken(UserDetails userDetails) {
        return generateToken(Map.of(), userDetails);
    }

    /**
     * Tao token HS256.
     *
     * @param extraClaims claim bo sung (khong duoc ghi de {@code sub}/{@code exp}/{@code iat})
     * @param userDetails nguoi dung da xac thuc
     * @return chuoi JWT compact {@code header.payload.signature}
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        Instant issuedAt = Instant.now();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .subject(userDetails.getUsername())
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(issuedAt.plusMillis(expirationMillis)))
                .claim(CLAIM_AUTHORITIES, userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList());

        if (StringUtils.hasText(issuer)) {
            builder.issuer(issuer);
        }
        // Claim nghiep vu: khong dat du lieu nhay cam (JWT chi duoc ky, KHONG duoc ma hoa).
        extraClaims.forEach(builder::claim);

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(ALGORITHM), builder.build());
        try {
            // Tao signer moi cho moi lan ky: tranh moi lo ngai chia se doi tuong crypto giua cac thread.
            signedJWT.sign(new MACSigner(secret));
        } catch (JOSEException e) {
            throw new TokenGenerationException("Khong the ky JWT", e);
        }
        return signedJWT.serialize();
    }

    /**
     * Lay username ({@code sub}) tu token, dong thoi xac thuc chu ky va thoi han.
     *
     * @throws TokenException neu token sai dinh dang, sai chu ky hoac het han
     */
    public String extractUsername(String token) {
        return parseAndValidate(token).getSubject();
    }

    /** Thoi han cua token tinh bang millisecond (tra ve client qua {@code expiresIn}). */
    public long getExpirationTime() {
        return expirationMillis;
    }

    /**
     * Kiem tra token co hop le voi nguoi dung tuong ung hay khong (khong nem exception).
     * Dung khi chi can ket qua true/false.
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            String subject = parseAndValidate(token).getSubject();
            return subject != null && subject.equalsIgnoreCase(userDetails.getUsername());
        } catch (TokenException e) {
            log.debug("JWT khong hop le: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Parse + xac thuc chu ky + kiem tra thoi han.
     *
     * <p>Thu tu kiem tra rat quan trong: <strong>phai xac thuc chu ky truoc</strong>, chi doc claim
     * sau khi chu ky da hop le. Neu doc claim truoc thi ke tan cong co the dua claim gia mao vao
     * mot token khong duoc ky.
     */
    private JWTClaimsSet parseAndValidate(String token) {
        if (!StringUtils.hasText(token)) {
            throw new InvalidTokenException("JWT rong");
        }

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(token);
        } catch (ParseException e) {
            throw new InvalidTokenException("JWT khong dung dinh dang", e);
        }

        // Chong "algorithm confusion": chi chap nhan dung thuat toan da cau hinh (HS256).
        // Voi token alg=none hoac RS256, request bi tu choi ngay tai day.
        if (!ALGORITHM.equals(signedJWT.getHeader().getAlgorithm())) {
            throw new InvalidTokenException(
                    "Thuat toan JWT khong duoc phep: " + signedJWT.getHeader().getAlgorithm());
        }

        boolean signatureValid;
        try {
            signatureValid = signedJWT.verify(new MACVerifier(secret));
        } catch (JOSEException e) {
            throw new InvalidTokenException("Khong the xac thuc chu ky JWT", e);
        }
        if (!signatureValid) {
            throw new InvalidTokenSignatureException("Chu ky JWT khong hop le");
        }

        JWTClaimsSet claims;
        try {
            claims = signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new InvalidTokenException("Khong doc duoc payload cua JWT", e);
        }

        try {
            // Kiem tra exp (bat buoc), iss (neu cau hinh), nbf va cac claim yeu cau.
            // maxClockSkew mac dinh cua Nimbus la 60 giay, project khong thay doi gia tri nay.
            claimsVerifier.verify(claims, null);
        } catch (ExpiredJWTException e) {
            throw new TokenExpiredException("JWT da het han", e);
        } catch (BadJWTException e) {
            throw new InvalidTokenException("JWT khong hop le: " + e.getMessage(), e);
        }

        return claims;
    }
}
