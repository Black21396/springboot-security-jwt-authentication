package net.fadi.jwt.user.controller;

import lombok.RequiredArgsConstructor;
import net.fadi.jwt.user.entity.AuthenticationRequest;
import net.fadi.jwt.user.entity.AuthenticationResposne;
import net.fadi.jwt.user.entity.RegisterRequest;
import net.fadi.jwt.user.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/v1/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResposne> register(@RequestBody RegisterRequest request){
            return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResposne> register(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }
}
