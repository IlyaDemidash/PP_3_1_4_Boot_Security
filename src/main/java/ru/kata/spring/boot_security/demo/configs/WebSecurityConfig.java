package ru.kata.spring.boot_security.demo.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.kata.spring.boot_security.demo.entities.Role;
import ru.kata.spring.boot_security.demo.entities.User;
import ru.kata.spring.boot_security.demo.repositories.UserRepo;
import ru.kata.spring.boot_security.demo.service.RoleService;
import ru.kata.spring.boot_security.demo.service.UserServiceImpl;

import javax.annotation.PostConstruct;
import java.util.HashSet;
import java.util.Set;

/*
Создание конфигурации для Spring Security (юзеры, пароли, роли...)
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private final SuccessUserHandler successUserHandler;
    private UserServiceImpl userService;

    private UserRepo userRepo;

    private RoleService roleService;

    @Autowired
    public void setUserService(UserServiceImpl userService) {
        this.userService = userService;
    }

    public WebSecurityConfig(SuccessUserHandler successUserHandler, UserRepo userRepo, RoleService roleService) {
        this.successUserHandler = successUserHandler;
        this.userRepo = userRepo;
        this.roleService = roleService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/admin/**").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/user/**").hasAnyRole("ADMIN", "USER")
                .anyRequest().authenticated()
                .and()
                .formLogin().successHandler(successUserHandler)
                .permitAll()
                .and()
                .logout()
                .permitAll();
        http.csrf().disable();
    }

    /*
    Преобразование паролей (из текста в хэш)
     */
    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*
    Далее создаем authenticationProvider его задача сказать существует ли такой пользователь и если существует,
    то его нужно положить в SpringSecurityContext. Для этого есть метод:
    setUserDetailsService - будет предоставлять юзеров
     */
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder()); //указываем наш энкодер паролей
        authenticationProvider.setUserDetailsService(userService);
        return authenticationProvider;
    }

    @PostConstruct
    public void addAdminInDB() {
        //Создаем пользователей при старте приложения

        Set<Role> roleAdmin = new HashSet<>();
        roleAdmin.add(new Role("ROLE_ADMIN"));
        Set<Role> roleUser = new HashSet<>();
        roleUser.add(new Role("ROLE_USER"));

        userService.saveUser(new User("admin", "adm", 33, "admin@mail.ru", "111", roleAdmin));
        userService.saveUser(new User("user", "usr", 33, "user@mail.ru", "111", roleUser));
    }

}