package org.example.user;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

@SpringBootTest
class RedisBackedUserDetailsManagerTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private final String savedUsername = "joe";
    private final String savedUserPassword = "password";

    private RedisBackedUserDetailsManager userDetailsManager;
    private RedisBackedUser joe;

    @BeforeEach
    public void clearDatabase() {
        this.userRepository.deleteAll();
    }

    @BeforeEach
    public void recreateJoe() {
        String encodedPassword = this.passwordEncoder.encode(savedUserPassword);
        joe = new RedisBackedUser(savedUsername, encodedPassword, AuthorityUtils.createAuthorityList("A", "C", "B")
        );
    }

    @BeforeEach
    public void recreateUserDetailsManager() {
        this.userDetailsManager = new RedisBackedUserDetailsManager(this.userRepository, this.passwordEncoder);
    }

    @AfterEach
    public void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    public void clearDatabaseAgain() {
        this.userRepository.deleteAll();
    }

    // CREATE

    @Test
    void createUserInsertsCorrectData() {
        this.userDetailsManager.createUser(joe);
        UserDetails joe2 = this.userDetailsManager.loadUserByUsername(savedUsername);
        assertThat(joe2).isEqualTo(joe);
    }

    @Test
    void createUserDoesNotOverwriteExistingUser() {
        saveJoe();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> this.userDetailsManager.createUser(joe));
    }

    @Test
    void createUserAddsRelevantRedisAbstractions() {
        saveJoe();

        // equals() is used to get rid of unboxing warnings, see
        // https://stackoverflow.com/questions/64182596/springboot-unboxing-of-redistemplate-may-produce-nullpointerexception
        boolean hasUsername = Boolean.TRUE.equals(this.redisTemplate.hasKey("users:" + savedUsername));
        boolean hasUser = Boolean.TRUE.equals(this.redisTemplate.boundSetOps("users").isMember(savedUsername));

        assertThat(hasUsername).isTrue();
        assertThat(hasUser).isTrue();
    }

    // READ

    @Test
    void canLoadByUsername() {
        this.userRepository.save(joe);
        UserDetails loadedUser = this.userDetailsManager.loadUserByUsername(savedUsername);
        assertThat(loadedUser).isEqualTo(joe);
    }

    @Test
    void cannotLoadNonExistingUser() {
        assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(
                () -> this.userDetailsManager.loadUserByUsername("ghost")
        );
    }

    @Test
    void userExistsReturnsFalseForNonExistentUsername() {
        assertThat(this.userDetailsManager.userExists(savedUsername)).isFalse();
    }

    @Test
    void userExistsReturnsTrueForExistingUsername() {
        saveJoe();
        assertThat(this.userDetailsManager.userExists(savedUsername)).isTrue();
    }

    // UPDATE

    @Test
    void canUpdateUser() {
        saveJoe();

        GrantedAuthority[] newAuths = {
                new SimpleGrantedAuthority("MOTHER"),
                new SimpleGrantedAuthority("SECRET_LOVER"),
                new SimpleGrantedAuthority("TEACHER")
        };

        Set<GrantedAuthority> newAuthorities = Set.of(newAuths);

        joe.setAuthorities(newAuthorities);

        this.userDetailsManager.updateUser(joe);

        // should overwrite existing, not save new
        long userCount = this.userRepository.count();
        assertThat(userCount).isOne();

        Optional<RedisBackedUser> updatedFoundOpt = this.userRepository.findById(savedUsername);
        assertThat(updatedFoundOpt).isPresent();
        RedisBackedUser updatedUser = updatedFoundOpt.get();

        Collection<GrantedAuthority> authorities = updatedUser.getAuthorities();

        assertThat(authorities).containsExactly(newAuths);
    }


    @Test
    void updateUserChangesDataCorrectlyWhenUpdatingExistingUser() {
        saveJoe();
        joe.setAuthorities(Set.of(new SimpleGrantedAuthority("ROLE_USER")));
        this.userDetailsManager.updateUser(joe);
        RedisBackedUser newJoe = this.userDetailsManager.loadUserByUsername(savedUsername);
        Collection<GrantedAuthority> authorities = newJoe.getAuthorities();
        assertThat(authorities).hasSameElementsAs(Set.of(new SimpleGrantedAuthority("ROLE_USER")));
        assertThat(joe).isEqualTo(newJoe);
    }

    @Test
    void changePasswordFailsForUnauthenticatedUser() {
        assertThatExceptionOfType(AccessDeniedException.class)
                .isThrownBy(() -> this.userDetailsManager.changePassword("password", "newPassword"));
    }

    @Test
    void changePasswordSucceedsWithAuthenticatedUserAndNoAuthenticationManagerSet() {
        saveJoe();
        authenticateJoe();
        this.userDetailsManager.changePassword("wrongpassword", "newPassword");
        UserDetails newJoe = this.userDetailsManager.loadUserByUsername(savedUsername);
        boolean updated = passwordWasUpdated(newJoe.getPassword());
        assertThat(updated).isTrue();
    }

    @Test
    void changePasswordSucceedsWithAuthenticatedUserIfReAuthenticationSucceeds() {
        saveJoe();

        Authentication currentAuth = authenticateJoe();
        AuthenticationManager am = mock(AuthenticationManager.class);
        given(am.authenticate(currentAuth)).willReturn(currentAuth);
        this.userDetailsManager.setAuthenticationManager(am);

        this.userDetailsManager.changePassword("password", "newPassword");

        UserDetails newJoe = this.userDetailsManager.loadUserByUsername(savedUsername);
        boolean updated = passwordWasUpdated(newJoe.getPassword());
        assertThat(updated).isTrue();

        // The password in the context should also be altered
        Authentication newAuth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(newAuth.getName()).isEqualTo(savedUsername);
        assertThat(newAuth.getDetails()).isEqualTo(currentAuth.getDetails());
        assertThat(newAuth.getCredentials()).isNull();
    }

    @Test
    void changePasswordFailsIfReAuthenticationFails() {
        saveJoe();
        authenticateJoe();
        AuthenticationManager am = mock(AuthenticationManager.class);
        given(am.authenticate(any(Authentication.class))).willThrow(new BadCredentialsException(""));
        this.userDetailsManager.setAuthenticationManager(am);
        assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> this.userDetailsManager.changePassword("password", "newPassword"));
        UserDetails newJoe = this.userDetailsManager.loadUserByUsername(savedUsername);
        assertThat(newJoe.getPassword()).isEqualTo(joe.getPassword());
        assertThat(SecurityContextHolder.getContext().getAuthentication().getCredentials()).isEqualTo("password");
    }

    // DELETE

    @Test
    void canDeleteUser() {
        this.userRepository.save(joe);
        this.userDetailsManager.deleteUser(savedUsername);
        Optional<RedisBackedUser> userOpt = this.userRepository.findById(savedUsername);
        assertThat(userOpt).isEmpty();
    }

    @Test
    void deleteUserRemovesRelevantRedisAbstractions() {
        saveJoe();

        this.userDetailsManager.deleteUser(savedUsername);

        // equals() is used to get rid of unboxing warnings, see
        // https://stackoverflow.com/questions/64182596/springboot-unboxing-of-redistemplate-may-produce-nullpointerexception
        boolean doesNotHaveUsername = Boolean.FALSE.equals(this.redisTemplate.hasKey("users:" + savedUsername));
        boolean doesNotHaveUser = Boolean.FALSE.equals(this.redisTemplate.boundSetOps("users").isMember(savedUsername));

        assertThat(doesNotHaveUsername).isTrue();
        assertThat(doesNotHaveUser).isTrue();
    }

    @Test
    void createNewAuthenticationUsesNullPasswordToKeepPasswordsSafe() {
        saveJoe();
        UsernamePasswordAuthenticationToken currentAuth = new UsernamePasswordAuthenticationToken("joe", null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        Authentication updatedAuth = this.userDetailsManager.createNewAuthentication(currentAuth);
        assertThat(updatedAuth.getCredentials()).isNull();
    }

    private void saveJoe() {
        this.userRepository.save(joe);
    }

    private Authentication authenticateJoe() {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(savedUsername, savedUserPassword,
                joe.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(auth);
        return auth;
    }

    /*@TestConfiguration
    static class RedisTemplateConfiguration {
        @Bean
        public LettuceConnectionFactory redisConnectionFactory() {
            return new LettuceConnectionFactory();
        }

        @Bean
        public RedisTemplate<Object, Object> redisTemplate() {
            RedisTemplate<Object, Object> template = new RedisTemplate<>();
            template.setConnectionFactory(redisConnectionFactory());
            template.setKeySerializer(new StringRedisSerializer());
            template.setValueSerializer(new StringRedisSerializer());
            return template;
        }
    }*/

    private boolean passwordWasUpdated(String newEncodedPassword) {
        Pattern pattern = Pattern.compile("^\\$2[ayb]\\$.{56}$");
        Matcher matcher = pattern.matcher(newEncodedPassword);
        boolean isProbablyBCryptString = matcher.matches();
        boolean wasChanged = !newEncodedPassword.equals(savedUserPassword);
        return isProbablyBCryptString && wasChanged;
    }
}

