package org.example.user;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.util.Collection;

import static java.lang.String.format;

/**
 * <p>
 * Redis-backed user management service that provides create, read, update and delete operations for users.
 * </p>
 * <p>
 * Inspired by {@link org.springframework.security.provisioning.JdbcUserDetailsManager}.
 * </p>
 */
@Service
public class RedisBackedUserDetailsManager implements UserDetailsManager, InitializingBean {

    Logger logger = LoggerFactory.getLogger(RedisBackedUserDetailsManager.class);

    private UserRepository userRepository;
    private AuthenticationManager authenticationManager;
    private PasswordEncoder passwordEncoder;

    public RedisBackedUserDetailsManager() {
    }

    public RedisBackedUserDetailsManager(UserRepository userRepository, AuthenticationManager authenticationManager,
                                         PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
    }

    public RedisBackedUserDetailsManager(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public RedisBackedUser loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findById(username)
                .orElseThrow(
                        () -> new UsernameNotFoundException(format("User with username - %s, not found", username))
                );
    }

    @Override
    public void createUser(UserDetails user) {
        validateUserDetails(user);
        this.userRepository.findById(user.getUsername())
                .ifPresentOrElse(redisBackedUser -> {
                            throw new IllegalArgumentException(
                                    format("User with username - %s already exists", user.getUsername()));
                        }, () -> {
                            String password = user.getPassword();
                            String encodedPassword = this.passwordEncoder.encode(password);
                            RedisBackedUser newUser = new RedisBackedUser(user.getUsername(), encodedPassword, user.getAuthorities());
                            this.userRepository.save(newUser);
                        }
                );
    }

    @Override
    public void updateUser(UserDetails user) {
        validateUserDetails(user);
        RedisBackedUser newUser = new RedisBackedUser(user.getUsername(), user.getPassword(), user.getAuthorities());
        this.userRepository.save(newUser);
    }

    @Override
    public void deleteUser(String username) {
        this.userRepository.deleteById(username);
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {
        Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
        if (currentUser == null) {
            // This would indicate bad coding somewhere
            throw new AccessDeniedException(
                    "Can't change password as no Authentication object found in context for current user.");
        }
        String username = currentUser.getName();
        // If an authentication manager has been set, re-authenticate the user with the
        // supplied password.
        if (this.authenticationManager != null) {
            this.logger.debug("Reauthenticating user {} for password change request.", username);
            this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, oldPassword));
        } else {
            this.logger.debug("No authentication manager set. Password won't be re-checked.");
        }
        this.logger.debug("Changing password for user {}", username);
        userRepository.findById(username)
                .ifPresentOrElse(foundUser -> {
                    String encodedNewPassword = this.passwordEncoder.encode(newPassword);
                    RedisBackedUser userWithUpdatedPassword =
                            new RedisBackedUser(foundUser.getUsername(), encodedNewPassword, foundUser.getAuthorities());
                    userRepository.save(userWithUpdatedPassword);
                    SecurityContextHolder.getContext().setAuthentication(createNewAuthentication(currentUser));
                }, () -> {
                    throw new UsernameNotFoundException("Username not found!");
                });
    }

    protected Authentication createNewAuthentication(Authentication currentAuth) {
        UserDetails user = loadUserByUsername(currentAuth.getName());
        UsernamePasswordAuthenticationToken newAuthentication = new UsernamePasswordAuthenticationToken(user, null,
                user.getAuthorities());
        newAuthentication.setDetails(currentAuth.getDetails());
        return newAuthentication;
    }

    @Override
    public boolean userExists(String username) {
        return this.userRepository.existsById(username);
    }

    @Override
    public void afterPropertiesSet() {
        if (this.authenticationManager == null) {
            this.logger.info("No authentication manager set. " +
                    "Reauthentication of users when changing passwords will not be performed.");
        }
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    private void validateUserDetails(UserDetails user) {
        Assert.hasText(user.getUsername(), "Username may not be empty or null");
        validateAuthorities(user.getAuthorities());
    }

    private void validateAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Assert.notNull(authorities, "Authorities list must not be null");
        for (GrantedAuthority authority : authorities) {
            Assert.notNull(authority, "Authorities list contains a null entry");
            Assert.hasText(authority.getAuthority(), "getAuthority() method must return a non-empty string");
        }
    }
}