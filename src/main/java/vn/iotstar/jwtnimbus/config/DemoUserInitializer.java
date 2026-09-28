package vn.iotstar.jwtnimbus.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import vn.iotstar.jwtnimbus.entity.User;
import vn.iotstar.jwtnimbus.repository.UserRepository;

import java.util.Locale;

/**
 * Tao tai khoan demo khi {@code app.demo-user.enabled=true} VA {@code app.demo-user.password} duoc dat.
 *
 * <p>Mat khau KHONG duoc luu trong source. Truyen qua bien moi truong:
 * <pre>
 * DEMO_USER_ENABLED=true DEMO_USER_PASSWORD='MatKhauCuaBan@123' mvn spring-boot:run
 * </pre>
 * Neu khong dat, hay dang ky tai khoan qua trang {@code /register} hoac {@code POST /auth/signup}.
 */
@Component
@ConditionalOnProperty(name = "app.demo-user.enabled", havingValue = "true")
public class DemoUserInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoUserInitializer.class);

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final String email;

    private final String password;

    private final String fullName;

    public DemoUserInitializer(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            @Value("${app.demo-user.email}") String email,
            @Value("${app.demo-user.password:}") String password,
            @Value("${app.demo-user.full-name}") String fullName) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.email = email;
        this.password = password;
        this.fullName = fullName;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!StringUtils.hasText(password)) {
            log.warn("app.demo-user.enabled=true nhung app.demo-user.password trong. "
                    + "Dat bien moi truong DEMO_USER_PASSWORD de tao tai khoan demo.");
            return;
        }

        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
        if (userRepository.existsByEmail(normalizedEmail)) {
            log.info("Tai khoan demo {} da ton tai, bo qua.", normalizedEmail);
            return;
        }

        User user = new User();
        user.setEmail(normalizedEmail);
        user.setFullName(fullName);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole("USER");
        userRepository.save(user);

        log.info("Da tao tai khoan demo: {}", normalizedEmail);
    }
}
