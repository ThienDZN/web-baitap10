package vn.iotstar.jwtnimbus.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import vn.iotstar.jwtnimbus.entity.User;
import vn.iotstar.jwtnimbus.models.UserResponse;
import vn.iotstar.jwtnimbus.service.UserService;

import java.util.List;

/**
 * Tuong ung "Buoc 8: Tao class @RestController" (slide 27) trong bai giang.
 *
 * <p>{@code GET /users/me} tra ve nguoi dung da xac thuc tu token;
 * {@code GET /users} tra ve danh sach nguoi dung. Ca hai deu yeu cau Bearer token hop le.
 */
@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponse> authenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        User currentUser = (User) authentication.getPrincipal();

        return ResponseEntity.ok(UserResponse.from(currentUser));
    }

    @GetMapping({"", "/"})
    public ResponseEntity<List<UserResponse>> allUsers() {
        List<UserResponse> users = userService.allUsers().stream()
                .map(UserResponse::from)
                .toList();

        return ResponseEntity.ok(users);
    }
}
