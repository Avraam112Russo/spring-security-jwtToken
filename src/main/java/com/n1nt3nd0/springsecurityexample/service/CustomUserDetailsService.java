package com.n1nt3nd0.springsecurityexample.service;

import com.n1nt3nd0.springsecurityexample.model.UserEntity;
import com.n1nt3nd0.springsecurityexample.reposiotry.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findByEmail(username).orElseThrow(() -> new RuntimeException("User not found."));
        return User.builder()
                .username(userEntity.getEmail())
                .password(userEntity.getPassword())
                .authorities(Collections.singleton(new SimpleGrantedAuthority("USER")))
                .build();

    }
    public void registerUser(UserEntity userEntity) {
        UserEntity build = UserEntity.builder()
                .email(userEntity.getEmail())
                .password(passwordEncoder.encode(userEntity.getPassword()))
                .firstName(userEntity.getFirstName())
                .lastName(userEntity.getLastName())
                .build();
        userRepository.save(build);
        log.info("User {} registered successfully", build.getId());
    }
}
