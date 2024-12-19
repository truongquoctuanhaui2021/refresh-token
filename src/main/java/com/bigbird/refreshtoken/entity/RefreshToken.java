package com.bigbird.refreshtoken.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "refresh_token")
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long refreshTokenId;

    @OneToOne
    @JoinColumn(name = "user_id", referencedColumnName = "userId")
    private Users users;

    private String token;

    private Instant expiryDate;
}
