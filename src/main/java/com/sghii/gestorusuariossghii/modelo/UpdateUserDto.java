package com.sghii.gestorusuariossghii.modelo;

public class UpdateUserDto {

    private String username;

    private String oldPassword;

    private String newPassword;

    private boolean estado;

    private String role;

    public String getUsername() {
        return username;
    }

    public String getOldPassword() {
        return oldPassword;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public String getRole() {
        return role;
    }

    public boolean isEstado() {
        return estado;
    }
}
