package com.hrms.hrmsapi.repository;

import com.hrms.hrmsapi.model.Role;
import com.hrms.hrmsapi.model.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleName roleName);
}
