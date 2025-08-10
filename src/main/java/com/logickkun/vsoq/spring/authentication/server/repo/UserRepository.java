package com.logickkun.vsoq.spring.authentication.server.repo;


import com.logickkun.vsoq.spring.authentication.server.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    /// 1) JPQL + fetch join 방식
    Optional<User> findByUsername(String username);

    @Query("""
        select distinct u
        from User u
        left join fetch u.roles r
        where lower(u.username) = lower(:username)
    """)
    Optional<User> findByUsernameIgnoreCaseWithRoles(@Param("username") String username);

      /// 2) 파생 쿼리 + @EntityGraph 방식
//    @EntityGraph(attributePaths = "roles")
//    Optional<User> findByUsername(String username);


}
