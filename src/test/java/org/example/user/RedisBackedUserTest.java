package org.example.user;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class RedisBackedUserTest {

    private static final List<GrantedAuthority> ROLE_12 = AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO");

    @Test
    void equalsReturnsTrueIfUsernamesAreTheSame() {
        UserDetails user1 = new RedisBackedUser("rod", "koala", ROLE_12);
        assertThat(user1).isNotNull()
                .isNotEqualTo("A STRING")
                .isEqualTo(user1)
                .isEqualTo((new RedisBackedUser("rod", "notthesame", ROLE_12)));
    }

    @Test
    void hashLookupOnlyDependsOnUsername() {
        UserDetails user1 = new RedisBackedUser("rod", "koala", ROLE_12);
        Set<UserDetails> users = new HashSet<>();
        users.add(user1);
        assertThat(users).contains(new RedisBackedUser("rod", "koala", ROLE_12))
                .contains(new RedisBackedUser("rod", "anotherpass",
                        AuthorityUtils.createAuthorityList("ROLE_X")))
                .doesNotContain(new RedisBackedUser("bod", "koala", ROLE_12));
    }

    @Test
    void testNoArgConstructorDoesNotExist() {
        assertThatExceptionOfType(NoSuchMethodException.class)
                .isThrownBy(() -> RedisBackedUser.class.getDeclaredConstructor((Class[]) null));
    }

    @Test
    void testNullValuesRejected() {
        assertThatIllegalArgumentException().isThrownBy(() -> new RedisBackedUser(null, "koala", ROLE_12));
        assertThatIllegalArgumentException().isThrownBy(() -> new RedisBackedUser("rod", null, ROLE_12));
        List<GrantedAuthority> auths = AuthorityUtils.createAuthorityList("ROLE_ONE");
        auths.add(null);
        assertThatIllegalArgumentException().isThrownBy(() -> new RedisBackedUser("rod", "koala", auths));
    }

    @Test
    void testNullWithinGrantedAuthorityElementIsRejected() {
        List<GrantedAuthority> auths = AuthorityUtils.createAuthorityList("ROLE_ONE");
        auths.add(null);
        auths.add(new SimpleGrantedAuthority("ROLE_THREE"));
        assertThatIllegalArgumentException().isThrownBy(() -> new RedisBackedUser(null, "koala", auths));
    }

    @Test
    void testUserGettersSetter() {
        GrantedAuthority[] newAuths = {
                new SimpleGrantedAuthority("ROLE_ONE"),
                new SimpleGrantedAuthority("ROLE_TWO")
        };

        RedisBackedUser user = new RedisBackedUser("rod", "koala",
                AuthorityUtils.createAuthorityList("ROLE_TWO", "ROLE_ONE"));
        assertThat(user.getUsername()).isEqualTo("rod");
        assertThat(user.getPassword()).isEqualTo("koala");
        assertThat(user.getAuthorities()).containsExactly(newAuths);
        assertThat(user.toString()).contains("rod");
    }

    @Test
    void userIsSerializable() {
        UserDetails user = new RedisBackedUser("rod", "koala", ROLE_12);
        assertDoesNotThrow(() -> {
            // Serialize to a byte array
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream out = new ObjectOutputStream(bos);
            out.writeObject(user);
            out.close();
        });
    }
}