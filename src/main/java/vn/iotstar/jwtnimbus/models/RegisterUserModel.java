package vn.iotstar.jwtnimbus.models;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Model dang ky - tuong ung "Buoc 3: Tao Models" trong bai giang.
 *
 * <p>Getter/setter duoc viet tuong minh (khong dung Lombok) de project build duoc trong moi IDE,
 * ke ca Eclipse/STS khi chua cai Lombok. Xem docs/ARCHITECTURE.md.
 */
public class RegisterUserModel {

    @NotBlank(message = "email khong duoc de trong")
    @Email(message = "email khong dung dinh dang")
    @Size(max = 100, message = "email toi da 100 ky tu")
    private String email;

    @NotBlank(message = "password khong duoc de trong")
    @Size(min = 8, max = 72, message = "password phai tu 8 den 72 ky tu")
    private String password;

    @NotBlank(message = "fullName khong duoc de trong")
    @Size(max = 100, message = "fullName toi da 100 ky tu")
    private String fullName;

    public RegisterUserModel() {
    }

    public RegisterUserModel(String email, String password, String fullName) {
        this.email = email;
        this.password = password;
        this.fullName = fullName;
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

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    /** Khong in password ra log. */
    @Override
    public String toString() {
        return "RegisterUserModel{email='" + email + "', fullName='" + fullName + "'}";
    }
}
