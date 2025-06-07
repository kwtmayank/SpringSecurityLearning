package org.learning.SpringSecurityLearning.model;

import org.learning.SpringSecurityLearning.entity.UserPermissions;

import java.util.List;

public class UserDTO {
    private String username;
    private String password;
    private String role;
    private List<UserPermissions> permissions;

    public UserDTO(String username, String password, String role, List<UserPermissions> permissions) {
        this.username = username;
        this.password = password;
        this.role = role;
        this.permissions = permissions;
    }

    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    public String getRole() {
        return role;
    }
    public void setRole(String role) {
        this.role = role;
    }

    public List<UserPermissions> getPermissions() {
        return permissions;
    }
    public void setPermissions(List<UserPermissions> permissions) {
        this.permissions = permissions;
    }
}
