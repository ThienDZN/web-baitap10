package vn.iotstar.jwtnimbus.models;

/**
 * Response tra ve sau khi dang nhap thanh cong - tuong ung "Buoc 3: Tao Models".
 *
 * <p>{@code tokenType} duoc them vao de client biet cach gui token
 * ({@code Authorization: Bearer <token>}).
 *
 * <p>Getter/setter viet tuong minh (khong dung Lombok) de build duoc trong moi IDE.
 */
public class LoginResponse {

    private String token;

    private long expiresIn;

    private String tokenType = "Bearer";

    public LoginResponse() {
    }

    public LoginResponse(String token, long expiresIn) {
        this.token = token;
        this.expiresIn = expiresIn;
        this.tokenType = "Bearer";
    }

    public LoginResponse(String token, long expiresIn, String tokenType) {
        this.token = token;
        this.expiresIn = expiresIn;
        this.tokenType = tokenType;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }
}
