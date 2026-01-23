package com.myproject.api.repositories; 

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.myproject.api.entities.User; 
import java.util.Optional; // THÊM DÒNG NÀY

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Boolean existsByEmail(String email);
    
    // THÊM DÒNG NÀY: Hàm này cần thiết cho Spring Security (UserDetailsService)
    Optional<User> findByEmail(String email); 
}