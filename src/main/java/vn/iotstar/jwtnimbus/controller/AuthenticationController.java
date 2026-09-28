package vn.iotstar.jwtnimbus.controller;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import vn.iotstar.jwtnimbus.entity.User;
import vn.iotstar.jwtnimbus.models.LoginResponse;
import vn.iotstar.jwtnimbus.models.LoginUserModel;
import vn.iotstar.jwtnimbus.models.RegisterUserModel;
import vn.iotstar.jwtnimbus.models.UserResponse;
import vn.iotstar.jwtnimbus.service.AuthenticationService;
import vn.iotstar.jwtnimbus.service.JwtTokenService;

/**
 * Tuong ung "Buoc 8: Tao class @RestController" (slide 26) trong bai giang.
 *
 * <p>{@code POST /auth/signup} - tao tai khoan; {@code POST /auth/login} - dang nhap va sinh JWT.
 *
 * <p>Khac biet: response dung DTO {@link UserResponse} thay vi tra entity {@code User}
 * (bai giang tra ve ca truong {@code password}).
 */
@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private final JwtTokenService jwtTokenService;

    private final AuthenticationService authenticationService;

    public AuthenticationController(JwtTokenService jwtTokenService,
                                    AuthenticationService authenticationService) {
        this.jwtTokenService = jwtTokenService;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/signup")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterUserModel registerUser) {
        User registeredUser = authenticationService.signup(registerUser);
        return ResponseEntity.ok(UserResponse.from(registeredUser));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticate(@Valid @RequestBody LoginUserModel loginUser) {
        User authenticatedUser = authenticationService.authenticate(loginUser);

        String jwtToken = jwtTokenService.generateToken(authenticatedUser);

        return ResponseEntity.ok(new LoginResponse(jwtToken, jwtTokenService.getExpirationTime()));
    }
}
