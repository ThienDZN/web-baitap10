package vn.iotstar.jwtnimbus.models;

import jakarta.validation.constraints.NotBlank;

/**
 * Model dang nhap - tuong ung "Buoc 3: Tao Models" trong bai giang.
 *
 * <p>Getter/setter viet tuong minh (khong dung Lombok) de build duoc trong moi IDE.
 */
public class LoginUserModel {

    @NotBlank(message = "email khong duoc de trong")
    private String email;

    @NotBlank(message = "password khong duoc de trong")
    private String password;

    public LoginUserModel() {
    }

    public LoginUserModel(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    /** Khong in password ra log. */
    @Override
    public String toString() {
        return "LoginUserModel{email='" + email + "'}";
    }
}
