package vn.iotstar.jwtnimbus.service;

import org.springframework.stereotype.Service;
import vn.iotstar.jwtnimbus.entity.User;
import vn.iotstar.jwtnimbus.repository.UserRepository;

import java.util.List;

/** Tuong ung "Buoc 4: Khoi tao ... services" trong bai giang. */
@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public List<User> allUsers() {
        return userRepository.findAll();
    }
}
