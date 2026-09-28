package vn.iotstar.jwtnimbus.models;

import vn.iotstar.jwtnimbus.entity.User;

import java.util.Date;

/**
 * Du lieu nguoi dung tra ra API.
 *
 * <p>Bai giang tra ve truc tiep entity {@code User}, tuc la tra ca {@code password} (hash)
 * trong response JSON (xem slide 28: response cua {@code /auth/signup} co truong {@code password}).
 * Day la ro ri thong tin. O day dung DTO chi gom truong an toan.
 */
public record UserResponse(
        Integer id,
        String fullName,
        String email,
        String images,
        String role,
        Date createdAt) {

    public static UserResponse from(User user) {
        return new UserResponse(
                user.getId(),
                user.getFullName(),
                user.getEmail(),
                user.getImages(),
                user.getRole(),
                user.getCreatedAt());
    }
}
