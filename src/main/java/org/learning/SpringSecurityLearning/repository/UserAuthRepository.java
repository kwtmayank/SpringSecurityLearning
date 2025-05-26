package org.learning.SpringSecurityLearning.repository;

import org.learning.SpringSecurityLearning.entity.UserAuth;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface UserAuthRepository extends JpaRepository<UserAuth, Long> {
    Optional<UserAuth> findByUsername(String username);
}
