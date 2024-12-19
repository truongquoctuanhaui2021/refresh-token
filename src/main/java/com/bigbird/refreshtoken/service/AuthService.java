package com.bigbird.refreshtoken.service;

import com.bigbird.refreshtoken.entity.RefreshToken;
import com.bigbird.refreshtoken.entity.Users;
import com.bigbird.refreshtoken.payload.request.LoginRequest;
import com.bigbird.refreshtoken.payload.request.RefreshTokenRequest;
import com.bigbird.refreshtoken.payload.request.SignupRequest;
import com.bigbird.refreshtoken.payload.response.JwtResponse;
import com.bigbird.refreshtoken.payload.response.MessageResponse;
import com.bigbird.refreshtoken.payload.response.RefreshTokenResponse;
import com.bigbird.refreshtoken.repository.RefreshTokenRepository;
import com.bigbird.refreshtoken.repository.UsersRepository;
import com.bigbird.refreshtoken.security.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UsersRepository usersRepository;

    public ResponseEntity<?> signUp(SignupRequest signUpRequest) {
        try {
            if (usersRepository.existsByUsername(signUpRequest.getUsername())) {
                return ResponseEntity.badRequest().body(new MessageResponse("Username is already"));
            }
            Users users = modelMapper.map(signUpRequest, Users.class);
            users.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
            usersRepository.save(users);
            return ResponseEntity.ok().body(new MessageResponse("User register successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new MessageResponse("Sign up request"));
        }
    }

    public ResponseEntity<?> signIn(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        Users userDetails = (Users) authentication.getPrincipal();
        String accessToken = jwtTokenProvider.generateJwtToken(userDetails);
        RefreshToken refreshToken = createRefreshToken(userDetails);
        return ResponseEntity.ok().body(
                new JwtResponse(
                        userDetails.getUserId(),
                        userDetails.getUsername(),
                        userDetails.getRole(),
                        accessToken,
                        refreshToken.getToken()
                )
        );
    }

    public RefreshTokenResponse generateNewToken(RefreshTokenRequest refreshTokenRequest) {
        RefreshToken refreshToken = verifyRefreshToken(refreshTokenRequest.getRefreshToken());
        Users users = refreshToken.getUsers();
        String token = jwtTokenProvider.generateJwtToken(users);
        RefreshToken newRefreshToken = createRefreshToken(users);
        return new RefreshTokenResponse(token, newRefreshToken.getToken());
    }

    private RefreshToken createRefreshToken(Users user) {
        RefreshToken refreshToken = new RefreshToken();
        Optional<RefreshToken> existsRefreshToken = refreshTokenRepository.findByUsers(user);
        if(existsRefreshToken.isPresent()){
            refreshToken = existsRefreshToken.get();
            if (refreshToken.getExpiryDate().isAfter(Instant.now())) {
                return refreshToken;
            }else{
                refreshToken.setToken(jwtTokenProvider.generateRefreshToken(user));
                refreshToken.setExpiryDate(Instant.now().plusMillis(604800000));
            }
        }else {
            refreshToken.setUsers(user);
            refreshToken.setToken(jwtTokenProvider.generateRefreshToken(user));
            refreshToken.setExpiryDate(Instant.now().plusMillis(604800000));
        }
        return refreshTokenRepository.save(refreshToken);
    }

    private RefreshToken verifyRefreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(refreshToken);
            throw new RuntimeException("Refresh token expired");
        }
        return refreshToken;
    }
}
