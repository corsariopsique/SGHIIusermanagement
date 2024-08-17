package com.sghii.gestorusuariossghii.controlador;

import com.sghii.gestorusuariossghii.servicio.JwtTokenProvider;
import com.sghii.gestorusuariossghii.modelo.TokenDto;
import com.sghii.gestorusuariossghii.modelo.UserDto;
import com.sghii.gestorusuariossghii.servicio.KeyGeneratorUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.bind.annotation.*;

import javax.sql.DataSource;
import java.util.Collections;

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

  //  @GetMapping("/generate")
   // public ResponseEntity<String> generate () throws Exception {
     //   KeyGeneratorUtil generator = new KeyGeneratorUtil();
      //  return ResponseEntity.ok(generator.getKeyEncoded());
   // }

}
