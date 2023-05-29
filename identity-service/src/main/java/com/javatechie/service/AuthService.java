package com.javatechie.service;

import com.javatechie.entity.UserCredential;
import com.javatechie.repository.UserCredentialRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired
    private UserCredentialRepository repository;

    // to encrypt the password before getting saved to DB.
    @Autowired
    private PasswordEncoder passwordEncoder;

    // we wrote the implementation for generateToken/validateToken in a separate service and this is optional.
    @Autowired
    private JwtService jwtService;

    public String saveUser(UserCredential credential) {
        // we are receiving the password as a String from the UserCredential,
        // It's not recommended to save password in the DB in String format,
        // so we need to use PasswordEncoder to get the password encrypted before getting saved to DB.
        credential.setPassword(passwordEncoder.encode(credential.getPassword()));
        repository.save(credential);
        return "user added to the system";
    }

    public String generateToken(String username) {
        return jwtService.generateToken(username);
    }

    public void validateToken(String token) {
        jwtService.validateToken(token);
    }
}
