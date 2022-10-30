package ru.kata.spring.boot_security.demo.service;

import ru.kata.spring.boot_security.demo.entities.Role;

import java.util.Set;

public interface RoleService {

    Role getRoleByName(String name);

    void saveRole(Role role);

    Set<Role> getAllRoles();
}
