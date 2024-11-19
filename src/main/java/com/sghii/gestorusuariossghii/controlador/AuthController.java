package com.sghii.gestorusuariossghii.controlador;

import com.sghii.gestorusuariossghii.modelo.UpdateUserDto;
import com.sghii.gestorusuariossghii.servicio.JwtTokenProvider;
import com.sghii.gestorusuariossghii.modelo.TokenDto;
import com.sghii.gestorusuariossghii.modelo.UserDto;
import com.sghii.gestorusuariossghii.servicio.KeyGeneratorUtil;
import com.sghii.gestorusuariossghii.servicio.UserManagementService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.bind.annotation.*;

import javax.sql.DataSource;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private AuthenticationProvider verificador;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailsService userDetailsService;

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/register")
    public ResponseEntity<String> registrarUsuario(@RequestBody UserDto user){
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);

        if (!manager.userExists(user.getUsername())) {
            UserDetails userSpring = User.withUsername(user.getUsername())
                    .password(passwordEncoder.encode(user.getPassword()))
                    .roles(user.getRole())
                    .build();
            manager.createUser(userSpring);
            return ResponseEntity.ok("Usuario creado exitosamente");
        }else{
            return ResponseEntity.badRequest().build();
        }
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/delete")
    public ResponseEntity<String> eliminarUsuario (@RequestBody UserDto user){
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);

        if (manager.userExists(user.getUsername())) {

            manager.deleteUser(user.getUsername());
            return ResponseEntity.ok("Usuario eliminado exitosamente");

        }else{
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Usuario no encontrado");
        }
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/update")
    public ResponseEntity<String> actualizaUsuario (@RequestBody UpdateUserDto user){
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);

        if (manager.userExists(user.getUsername())) {

            UserDetails userSpring = User.withUsername(user.getUsername())
                    .password(passwordEncoder.encode(user.getNewPassword()))
                    .roles(user.getRole())
                    .disabled(user.isEstado())
                    .build();
            manager.updateUser(userSpring);
            return ResponseEntity.ok("Usuario actualizado exitosamente");

        }else{
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Usuario no encontrado");
        }
    }

    @PutMapping("/changePWD")
    public ResponseEntity <String> cambioPassword(@RequestBody UpdateUserDto user){

        String username = ((UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername();

        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);

        try {

            Authentication authentication = verificador.authenticate(
                    new UsernamePasswordAuthenticationToken(username,user.getOldPassword(), Collections.emptyList())
            );

            manager.changePassword(user.getOldPassword(), passwordEncoder.encode(user.getNewPassword()));
            return ResponseEntity.ok("Contraseña del usuario " + username + " ha sido actualizada correctamente");

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Datos de usuario no validados");
        }

    }

    @PostMapping("/login")
    public ResponseEntity<TokenDto> login(@RequestBody UserDto dataLogin) {
        try {
            Authentication authentication = verificador.authenticate(
                    new UsernamePasswordAuthenticationToken(dataLogin.getUsername(),dataLogin.getPassword(), Collections.emptyList())
            );

            String jwt = tokenProvider.generateToken(authentication);
            TokenDto token = new TokenDto(jwt);

            return ResponseEntity.ok(token);
        } catch (Exception e) {
            TokenDto failed = new TokenDto("Autenticación no valida, token no generado");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(failed);
        }
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public ResponseEntity<List<Map<String,Object>>> listarUsuarios () {
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        UserManagementService usuariosLista = new UserManagementService (jdbcTemplate);
        return ResponseEntity.ok(usuariosLista.listarUsuariosConRoles());
    }

    @GetMapping("/validation")
    public ResponseEntity<UsernamePasswordAuthenticationToken> validation(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            var user = userDetailsService.loadUserByUsername(tokenProvider.getUsername(token));
            return ResponseEntity.ok(new UsernamePasswordAuthenticationToken(user.getUsername(), null, user.getAuthorities()));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }


    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/generate")
    public ResponseEntity<String> generate () throws Exception {
       KeyGeneratorUtil generator = new KeyGeneratorUtil();
       return ResponseEntity.ok(generator.getKeyEncoded());
    }

}
