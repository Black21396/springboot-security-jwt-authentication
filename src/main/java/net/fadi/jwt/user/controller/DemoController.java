package net.fadi.jwt.user.controller;

import org.apache.coyote.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// demo controller to check if jwt security works
@RestController
@RequestMapping("/api/v1/demo")
public class DemoController {

    @GetMapping("/message")
    public ResponseEntity<String> getMessage(){
        return ResponseEntity.ok("your jwt security work!");
    }
}