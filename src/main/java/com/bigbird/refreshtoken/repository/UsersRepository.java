package com.bigbird.refreshtoken.repository;

import com.bigbird.refreshtoken.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsersRepository extends JpaRepository<Users, Long> {
    Optional<Users> findByUsername(String username);
    Boolean existsByUsername(String username);
}
