package vn.iotstar.jwtnimbus.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Controller tra ve view Thymeleaf - tuong ung "Buoc 10: Render in Ajax" (slide 34).
 *
 * <p>Bai giang dat ten la {@code AuthController} voi {@code @RequestMapping("/")}.
 * O day tach rieng controller view khoi {@code @RestController} API cho ro rang.
 */
@Controller
public class ViewController {

    @GetMapping("/")
    public String index() {
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String register() {
        return "register";
    }

    @GetMapping("/user/profile")
    public String profile() {
        return "profile";
    }
}
