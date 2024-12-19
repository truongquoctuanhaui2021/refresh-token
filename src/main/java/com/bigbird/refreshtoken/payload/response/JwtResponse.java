package com.bigbird.refreshtoken.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JwtResponse {
    private Long userId;
    private String username;
    private String role;
    private String accessToken;
    private String refreshToken;
}
