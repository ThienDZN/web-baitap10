package vn.iotstar.jwtnimbus.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * Entity nguoi dung - tuong ung "Buoc 2: Tao Entity" trong bai giang.
 *
 * <p>Khac biet co chu y so voi bai giang:
 * <ul>
 *   <li><strong>Khong dung Lombok</strong> ({@code @Data}/{@code @Getter}). Bai giang dung Lombok,
 *       nhung Eclipse/STS chi hieu Lombok khi da cai Lombok vao IDE; neu chua cai thi class sinh ra
 *       se thieu getter/setter, Jackson khong gan duoc du lieu va API tra 400.
 *       Viet tay getter/setter de project build dung trong moi IDE.</li>
 *   <li>Khong dung {@code @Data} vi no sinh {@code toString()} chua password hash, de ro ri vao log.</li>
 *   <li>{@code password} duoc danh dau {@link JsonIgnore} de khong bao gio bi serialize ra JSON.</li>
 *   <li>Co them cot {@code role} de tao {@link GrantedAuthority} that (bai giang tra ve
 *       {@code List.of()} - danh sach quyen rong).</li>
 *   <li>Dung {@code length} thay cho {@code columnDefinition = "nvarchar(...)"} de chay duoc
 *       tren ca H2 va MySQL, khong chi SQL Server.</li>
 * </ul>
 */
@Entity
@Table(name = "users")
public class User implements UserDetails {

    @Serial
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false)
    private Integer id;

    @Column(nullable = false, length = 100)
    private String fullName;

    @Column(unique = true, length = 100, nullable = false)
    private String email;

    @Column(length = 500)
    private String images;

    /** BCrypt hash cua mat khau. Khong bao gio tra ra ngoai. */
    @JsonIgnore
    @Column(nullable = false, length = 100)
    private String password;

    /** Vi du: USER, ADMIN. {@link #getAuthorities()} se them tien to ROLE_. */
    @Column(nullable = false, length = 20)
    private String role = "USER";

    @CreationTimestamp
    @Column(updatable = false, name = "created_at")
    private Date createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Date updatedAt;

    public User() {
    }

    // ------------------------------ getter / setter ------------------------------

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getImages() {
        return images;
    }

    public void setImages(String images) {
        this.images = images;
    }

    @Override
    @JsonIgnore
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    public Date getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Date updatedAt) {
        this.updatedAt = updatedAt;
    }

    // ------------------------------ UserDetails ------------------------------

    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role));
    }

    /** Spring Security dung email lam username (giong bai giang). */
    @Override
    @JsonIgnore
    public String getUsername() {
        return email;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isEnabled() {
        return true;
    }

    /** Khong bao gom password/password hash. */
    @Override
    public String toString() {
        return "User{id=" + id + ", email='" + email + "', fullName='" + fullName
                + "', role='" + role + "'}";
    }
}
