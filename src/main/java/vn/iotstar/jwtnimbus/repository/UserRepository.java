package vn.iotstar.jwtnimbus.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import vn.iotstar.jwtnimbus.entity.User;

import java.util.Optional;

/** Tuong ung "Buoc 4: Khoi tao Interface Repository" trong bai giang. */
@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);
}
