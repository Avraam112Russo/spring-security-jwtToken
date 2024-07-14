package com.n1nt3nd0.springsecurityexample.http.Rest;

import com.n1nt3nd0.springsecurityexample.dto.ErrorResponse;
import com.n1nt3nd0.springsecurityexample.dto.LoginRequest;
import com.n1nt3nd0.springsecurityexample.dto.LoginResponse;
import com.n1nt3nd0.springsecurityexample.model.UserEntity;
import com.n1nt3nd0.springsecurityexample.security.JwtUtil;
import com.n1nt3nd0.springsecurityexample.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class UserRestController {
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;
    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginReq)  {

        try {
            Authentication authentication =
                    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginReq.getEmail(), loginReq.getPassword()));
            String email = authentication.getName();
            UserEntity user = UserEntity.builder()
                    .email(email)
                    .password(loginReq.getPassword())
                    .build();
            String token = jwtUtil.createToken(user);
            LoginResponse loginRes = new LoginResponse(email,token);

            return ResponseEntity.ok(loginRes);

        }catch (BadCredentialsException e){
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST,"Invalid username or password");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }catch (Exception e){
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }
    @PostMapping("/auth/register")
    public ResponseEntity<?> register(@RequestBody UserEntity userEntity) {
        customUserDetailsService.registerUser(userEntity);
        return ResponseEntity.status(HttpStatus.CREATED).body("Success");
    }
    @GetMapping("/secure")
    public ResponseEntity<?> getSecurePage(){
        return ResponseEntity.ok("Welcome secure page");
    }
}
