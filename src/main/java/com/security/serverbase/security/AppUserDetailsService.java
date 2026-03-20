package com.security.serverbase.security;

import com.security.serverbase.repository.AppUserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AppUserDetailsService implements UserDetailsService {

    private final AppUserRepository appUserRepository;

    public AppUserDetailsService(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = appUserRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Пользователь не найден: " + username));

        return User.builder()
                .username(user.getUsername())
                .password(user.getPasswordHash())
                .disabled(user.isDisabled())
                .accountExpired(user.isAccountExpired())
                .accountLocked(user.isAccountLocked())
                .credentialsExpired(user.isCredentialsExpired())
                .authorities(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
                .build();
    }
}
