package vn.iotstar.jwtnimbus.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import vn.iotstar.jwtnimbus.repository.UserRepository;

/**
 * Tuong ung "Buoc 5: Khoi tao ApplicationConfiguration" trong bai giang.
 *
 * <p>Diem khac so voi bai giang: bai giang khai bao them mot bean
 * {@code AuthenticationProvider} ({@code DaoAuthenticationProvider}) ben canh {@code UserDetailsService}.
 * Cach do lam Spring Security in canh bao luc khoi dong:
 * <pre>
 * Global AuthenticationManager configured with an AuthenticationProvider bean.
 * UserDetailsService beans will not be used by Spring Security for automatically
 * configuring username/password login.
 * </pre>
 * Vi da co bean {@link UserDetailsService} va bean {@code PasswordEncoder}, Spring Security
 * tu tao {@code DaoAuthenticationProvider} tuong ung. Bo bean thua giup log khoi dong sach
 * va hanh vi khong doi (da duoc kiem chung lai bang test tich hop).
 */
@Configuration
public class ApplicationConfiguration {

    private final UserRepository userRepository;

    public ApplicationConfiguration(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Bean
    UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("Khong tim thay nguoi dung: " + username));
    }

    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        // BCrypt voi strength mac dinh 10.
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
