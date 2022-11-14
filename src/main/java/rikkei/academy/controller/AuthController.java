package rikkei.academy.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import rikkei.academy.dto.request.SignIn;
import rikkei.academy.dto.request.SignUpForm;
import rikkei.academy.dto.request.UserDTO;
import rikkei.academy.dto.response.JwtResponse;
import rikkei.academy.dto.response.ResponseMessage;
import rikkei.academy.model.Role;
import rikkei.academy.model.RoleName;
import rikkei.academy.model.User;
import rikkei.academy.security.jwt.JwtProvider;
import rikkei.academy.security.userprincipal.UserPrinciple;
import rikkei.academy.service.role.IRoleService;
import rikkei.academy.service.user.IUSerService;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin
public class AuthController {
    @Autowired
    private IRoleService roleService;
    @Autowired
    private IUSerService uSerService;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    JwtProvider jwtProvider;
    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@RequestBody SignUpForm signUpForm) {
        if (uSerService.existsByUsername(signUpForm.getUsername())) {
            return new ResponseEntity<>(new ResponseMessage("username_existed"), HttpStatus.OK);
        }
        if (uSerService.existsByEmail(signUpForm.getEmail())) {
            return new ResponseEntity<>(new ResponseMessage("email_existed"), HttpStatus.OK);
        }
//        Set<String> strRoles = signUpForm.getRoles();
        Set<Role> roles = new HashSet<>();
        Role roleSignUp = roleService.findByName(RoleName.USER).orElseThrow(() -> new RuntimeException("not_found"));
        roles.add(roleSignUp);

//        strRoles.forEach(role->{
//            switch (role.toLowerCase()){
//                case "admin":
//                    Role adminRole = roleService.findByName(RoleName.ADMIN).orElseThrow(()->new RuntimeException("not_found"));
//                    roles.add(adminRole);
//                    break;
//                case "pm":
//                    Role pmRole = roleService.findByName(RoleName.PM).orElseThrow(()->new RuntimeException("not_found"));
//                    roles.add(pmRole);
//                    break;
//                default:
//                    Role userRole = roleService.findByName(RoleName.USER).orElseThrow(()->new RuntimeException("not_found"));
//                    roles.add(userRole);
//
//            }
//        });
        User user = new User(signUpForm.getName(), signUpForm.getUsername(), signUpForm.getEmail(), passwordEncoder.encode(signUpForm.getPassword()), signUpForm.getAvatar(), roles);
        uSerService.save(user);
        return new ResponseEntity<>(new ResponseMessage("create_success"), HttpStatus.OK);
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signIn(@Valid @RequestBody SignIn signIn) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(signIn.getUsername(), signIn.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtProvider.generateJwtToken(authentication);
        UserPrinciple userPrinciple = (UserPrinciple) authentication.getPrincipal();

        return ResponseEntity.ok(new JwtResponse(token, userPrinciple.getName(), userPrinciple.getAvatar(), userPrinciple.getAuthorities()));
    }
    @GetMapping("/{id}")
    public ResponseEntity<?> details(@PathVariable Long id) {
        Optional<User> user = uSerService.findById(id);
        if (!user.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage("user not found!!!"), HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(user.get(), HttpStatus.OK);
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> editUser(
            @PathVariable
            Long id,
            @RequestBody
            UserDTO userDTO
    ) {
        Optional<User> userOptional = uSerService.findById(id);
        if (!userOptional.isPresent()) {
            return new ResponseEntity<>(new ResponseMessage("user not found!!!"), HttpStatus.NOT_FOUND);
        }

        User user = userOptional.get();
        user.setId(id);
        user.setName(userDTO.getName());
        user.setUsername(userDTO.getUsername());
        user.setPassword(userDTO.getPassword());
        user.setEmail(userDTO.getEmail());
        user.setAvatar(userDTO.getAvatar());
        Set<Role> roles = new HashSet<>();
        for (String idRole :
                userDTO.getRoles()) {
            Role userRole = roleService.findById(Long.parseLong(idRole));
            roles.add(userRole);
        }
//  Role userRole = roleService.findByName(RoleName.USER).orElseThrow(() -> new RuntimeException("not_found"));
        user.setRoles(roles);
        uSerService.save(user);
        return new ResponseEntity<>(new ResponseMessage("Edit user success!"), HttpStatus.OK);
    }



}