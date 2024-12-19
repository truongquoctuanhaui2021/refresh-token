package com.bigbird.refreshtoken.controller;

import com.bigbird.refreshtoken.payload.request.LoginRequest;
import com.bigbird.refreshtoken.payload.request.RefreshTokenRequest;
import com.bigbird.refreshtoken.payload.request.SignupRequest;
import com.bigbird.refreshtoken.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("${apiPrefix}/auth")
public class AuthController {
    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignupRequest signUpRequest) {
        return authService.signUp(signUpRequest);
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signin(@RequestBody LoginRequest loginRequest) {
        return authService.signIn(loginRequest);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        return ResponseEntity.ok(authService.generateNewToken(refreshTokenRequest));
    }
}
