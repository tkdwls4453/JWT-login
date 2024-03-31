package com.example.jwtlogin.controller;

import com.example.jwtlogin.dto.JoinDto;
import com.example.jwtlogin.service.JoinService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@AllArgsConstructor
@RestController
public class MemberController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String join(@RequestBody JoinDto joinDto){
        joinService.join(joinDto);
        return "ok";
    }
}
