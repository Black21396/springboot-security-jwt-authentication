package net.fadi.jwt.user.service;

import lombok.RequiredArgsConstructor;
import net.fadi.jwt.config.JwtService;
import net.fadi.jwt.user.entity.*;
import net.fadi.jwt.user.repository.AppUserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final PasswordEncoder encoder;
    private final AppUserRepository userRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public AuthenticationResposne register(RegisterRequest request) {

        AppUser user = AppUser
                .builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(encoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        userRepository.save(user);

        // generate new token to the user
        String jwtToken = jwtService.generateToken(user);

        return new AuthenticationResposne(jwtToken);
    }

    public AuthenticationResposne authenticate(AuthenticationRequest request) {
        // check if user exist in db, if not throw automatic exception
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // get The user from db
        AppUser user = userRepository.findByEmail(request.getEmail()).get();

        // generate new token to the user
        String jwtToken = jwtService.generateToken(user);

        return new AuthenticationResposne(jwtToken);
    }
}
