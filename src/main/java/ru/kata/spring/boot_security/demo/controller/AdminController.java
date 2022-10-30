package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import ru.kata.spring.boot_security.demo.entities.Role;
import ru.kata.spring.boot_security.demo.entities.User;
import ru.kata.spring.boot_security.demo.service.UserService;

import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/admin")
public class AdminController {
    private final UserService userService;

    @Autowired
    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping()
    public String showAllUsers(Model model, Principal principal) {
        List<User> userList = userService.findAllUsers();
        model.addAttribute("user", userService.findByEmail(principal.getName()));
        model.addAttribute("users", userList);
        model.addAttribute("newUser", new User());
        return "allusers";
    }

    @GetMapping(value = "/addNewUser")
    public String addNewUserView(Model model) {
        List<Role> roleList = userService.roleList();
        model.addAttribute("user", new User());
        model.addAttribute("roleList", roleList);
        return "adduser";
    }

    @PostMapping(value = "/saveUser")
    public ResponseEntity<User> addUserAction(@RequestBody User user) {
        userService.saveUser(user);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }
    @PutMapping("/saveUser")
    public ResponseEntity<User> updateUserAction(@RequestBody User user) {
        userService.updateUser(user);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @GetMapping(value = "/updateUser/{id}")
    public String updateUserView(@PathVariable Long id, Model model) {
        User user = userService.findById(id);
        List<Role> roleList = userService.roleList();
        model.addAttribute("roleList", roleList);
        model.addAttribute("user", user);
        return "update";
    }



    @GetMapping("deleteUser/{id}")
    public String deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return "redirect:/admin";
    }

}
