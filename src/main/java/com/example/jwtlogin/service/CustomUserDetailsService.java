package com.example.jwtlogin.service;

import com.example.jwtlogin.domain.Member;
import com.example.jwtlogin.dto.CustomUserDetails;
import com.example.jwtlogin.repository.MemberRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@AllArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member member = memberRepository.findByUsername(username);
        System.out.println("member.getUsername() = " + member.getUsername());
        if (member != null) {
            // UserDetails 에 담아서 return 하면 AuthenticationManger 가 검증
            return new CustomUserDetails(member);
        }

        return null;
    }
}
