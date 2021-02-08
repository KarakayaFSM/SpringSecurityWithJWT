package com.example.demo.security.user;

import com.example.demo.security.user.UserPermission;
import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.example.demo.security.user.UserPermission.*;

public enum UserRole {

    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
    ADMIN_TRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ));

    private final Set<UserPermission> permissions;

    UserRole(Set<UserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<UserPermission> getPermissions() {
        return permissions;
    }

    public Set<GrantedAuthority> getGrantedAuthorities() {

        Function<UserPermission, GrantedAuthority> withSimpleAuthority =
                permission -> new SimpleGrantedAuthority(permission.getPermission());

        var authorities = fillAuthorities(permissions, withSimpleAuthority);

        var thisRole = new SimpleGrantedAuthority("ROLE_" + this.name());
        authorities.add(thisRole);

        return authorities;
    }

    private Set<GrantedAuthority> fillAuthorities(
            Set<UserPermission> permissions,
            Function<UserPermission, GrantedAuthority> withAuthority) {
        return permissions
                .stream()
                .map(withAuthority)
                .collect(Collectors.toSet());
    }

}
