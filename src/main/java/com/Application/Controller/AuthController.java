package com.Application.Controller;

import com.Application.Entity.Role;
import com.Application.Entity.User;
import com.Application.Payload.JWTAuthResponse;
import com.Application.Payload.LoginDto;
import com.Application.Payload.SignUpDto;
import com.Application.Repository.RoleRepository;
import com.Application.Repository.UserRepository;
import com.Application.Security.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


import java.util.Collections;
import java.util.List;

@RestController
@RequestMapping("/api/auth")
public class AuthController {


    @Autowired

    private AuthenticationManager authenticationManager;


    @Autowired

    private UserRepository userRepository;


    @Autowired

    private RoleRepository roleRepository;


    @Autowired

    private PasswordEncoder passwordEncoder;


    @Autowired

    private JwtTokenProvider tokenProvider;


    @PostMapping("/signin")

    public ResponseEntity<JWTAuthResponse> authenticateUser(@RequestBody LoginDto loginDto) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginDto.getUsernameOrEmail(), loginDto.getPassword()));


        SecurityContextHolder.getContext().setAuthentication(authentication);


// get token form tokenProvider

        String token = tokenProvider.generateToken(authentication);


        return ResponseEntity.ok(new JWTAuthResponse(token));

    }


    @PostMapping("/signup")

    public ResponseEntity<?> registerUser(@RequestBody SignUpDto signUpDto) {


// add check for username exists in a DB
        if (userRepository.existsByUsername(signUpDto.getUsername())) {
            return new ResponseEntity<>("Username is already taken!", HttpStatus.BAD_REQUEST);
        }


// add check for email exists in DB
        if (userRepository.existsByEmail(signUpDto.getEmail())) {
            return new ResponseEntity<>("Email is already taken!", HttpStatus.BAD_REQUEST);

        }


        // create user object
        User user = new User();
        user.setName(signUpDto.getName());
        user.setUsername(signUpDto.getUsername());
        user.setEmail(signUpDto.getEmail());
        user.setPassword(passwordEncoder.encode(signUpDto.getPassword()));


        Role roles = roleRepository.findByName("ROLE_ADMIN").get();
        user.setRoles(Collections.singleton(roles));


        userRepository.save(user);


        return new ResponseEntity<>("User registered successfully", HttpStatus.OK);


    }
    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userRepository.findAll();
        return ResponseEntity.ok(users);
    }

}
