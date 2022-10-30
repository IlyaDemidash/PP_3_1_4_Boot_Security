package ru.kata.spring.boot_security.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.kata.spring.boot_security.demo.entities.Role;
import ru.kata.spring.boot_security.demo.entities.User;
import ru.kata.spring.boot_security.demo.repositories.RoleRepo;
import ru.kata.spring.boot_security.demo.repositories.UserRepo;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/*
Задача этого сервиса по имени пользователя предоставить юзера. И так как этому сервису нужен будет доступ к БД
для получения юзера в нем инжектим репо юзера. Так же основные операции.
 */
@Service
@Transactional(readOnly = true) //Указываем, что не аннотированные методы будут производить операции readOnly
public class UserServiceImpl implements UserDetailsService, UserService {
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserServiceImpl(UserRepo userRepo, RoleRepo roleRepo, PasswordEncoder passwordEncoder) {
        this.userRepo = userRepo;
        this.roleRepo = roleRepo;
        this.passwordEncoder = passwordEncoder;
    }

    //Как ищем пользователя
    public User findByEmail(String email) {
        return userRepo.findByEmail(email);
    }

    @Override
    @Transactional
    public void updateUser(User user) {
        //Берем старого юзера по id
        User userDB = findById(user.getId());
        /*
        Сравниваем пароли пришедший в параметре и какой был у старого юзера,
        если не равны и у нового не пустой, то устанавливаем новый, иначе сетим старый
         */
        if (!(passwordEncoder.matches(user.getPassword(), userDB.getPassword()))
                && (user.getPassword() != null)
                && !(user.getPassword().equals(""))) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        } else {
            user.setPassword(userDB.getPassword());
        }
        userRepo.save(user);
    }

    /*
    По имени пользователя (по email в нашем случае) возвращаем юзера, но уже в формате UserDetails.
    Делаем запрос в БД по email. Грубо говоря показываем спрингу (AuthenticationProvider) как получить User в формате UserDetails.
    Реализация метода зависит от того где лежат наши пользователи, как мы их будем получать в данном случае из БД
    */
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<User> userOptional = Optional.ofNullable(findByEmail(email));
        if (userOptional.isPresent()) {
            User user = userOptional.get();
        /*
        Если нашли, то его нужно преобразовать к UserDetails, создаем юзера спрингового и передаем ему
        имя нашего пользователя, полученный пароль и коллекцию GrantedAuthorities.
         */
            return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), mapRolesToAuthorities(user.getRoles()));
        } else throw new UsernameNotFoundException("User with username: " + email + "not found!");
    }

    //метод из коллекции ролей получает коллекцию прав доступа GrantedAuthorities
    private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Collection<Role> roles) {
        return roles.stream().map(r -> new SimpleGrantedAuthority(r.getName())).collect(Collectors.toList());
    }

    @Override
    public List<User> findAllUsers() {

        return userRepo.findAll();
    }

    @Override
    @Transactional
    public User findById(Long id) {

        return userRepo.findById(id).orElse(null);
    }

    @Override
    @Transactional
    public void saveUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepo.save(user);
    }

    @Override
    @Transactional
    public void deleteUser(Long id) {
        userRepo.deleteById(id);
    }

    @Override
    public List<Role> roleList() {
        return roleRepo.findAll();
    }


}
