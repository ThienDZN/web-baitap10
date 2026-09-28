package vn.iotstar.jwtnimbus.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import vn.iotstar.jwtnimbus.entity.User;
import vn.iotstar.jwtnimbus.exception.EmailAlreadyUsedException;
import vn.iotstar.jwtnimbus.models.LoginUserModel;
import vn.iotstar.jwtnimbus.models.RegisterUserModel;
import vn.iotstar.jwtnimbus.repository.UserRepository;

import java.util.Locale;

/**
 * Dang ky / dang nhap - tuong ung "Buoc 4" trong bai giang.
 *
 * <p>Khac biet: email duoc chuan hoa (trim + lowercase) o ca dang ky va dang nhap de tranh
 * tao hai tai khoan chi khac nhau chu hoa/thuong, va de dang nhap khong phu thuoc chu hoa/thuong.
 */
@Service
public class AuthenticationService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    public AuthenticationService(
            UserRepository userRepository,
            AuthenticationManager authenticationManager,
            PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User signup(RegisterUserModel input) {
        String email = normalizeEmail(input.getEmail());
        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyUsedException("Email da duoc su dung: " + email);
        }

        User user = new User();
        user.setFullName(input.getFullName().trim());
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(input.getPassword()));
        user.setRole("USER");

        return userRepository.save(user);
    }

    /**
     * Xac thuc thong tin dang nhap.
     *
     * <p>{@code AuthenticationManager} se nem {@code BadCredentialsException} neu sai thong tin,
     * hoac {@code DisabledException}/{@code LockedException}/{@code AccountExpiredException}
     * neu tai khoan bi khoa. Cac exception nay duoc xu ly tap trung o GlobalExceptionHandler.
     */
    public User authenticate(LoginUserModel input) {
        String email = normalizeEmail(input.getEmail());
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, input.getPassword()));

        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Khong tim thay nguoi dung: " + email));
    }

    private String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }
}
