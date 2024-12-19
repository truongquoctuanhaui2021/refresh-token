package com.bigbird.refreshtoken.repository;

import com.bigbird.refreshtoken.entity.RefreshToken;
import com.bigbird.refreshtoken.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    Optional<RefreshToken> findByUsers(Users users);

    void deleteByUsers(Users users);
}
