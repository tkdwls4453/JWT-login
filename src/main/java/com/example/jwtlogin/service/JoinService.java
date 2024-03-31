package com.example.jwtlogin.service;

import com.example.jwtlogin.domain.Member;
import com.example.jwtlogin.dto.JoinDto;
import com.example.jwtlogin.repository.MemberRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@AllArgsConstructor
@Service
public class JoinService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void join(JoinDto joinDto) {

        String username = joinDto.getUsername();
        String password = joinDto.getPassword();

        if (memberRepository.existsByUsername(username)){
            return;
        }

        Member member = Member.builder()
                .username(username)
                .password(bCryptPasswordEncoder.encode(password))
                .role("ROLE_ADMIN")
                .build();

        memberRepository.save(member);
    }
}
