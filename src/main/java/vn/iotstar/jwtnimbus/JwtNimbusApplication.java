package vn.iotstar.jwtnimbus;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Bai tap vi du JWT - Spring Boot 3 / Spring Security 6.
 *
 * <p>Khac biet so voi bai giang: chu ky va xac thuc JWT duoc thuc hien bang thu vien
 * <strong>Nimbus JOSE+JWT</strong> (`com.nimbusds:nimbus-jose-jwt`) thay cho JJWT
 * (`io.jsonwebtoken`). Xem docs/NIMBUS-VS-JJWT.md.
 */
@SpringBootApplication
public class JwtNimbusApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtNimbusApplication.class, args);
    }
}
