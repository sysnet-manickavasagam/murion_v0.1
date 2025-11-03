package com.example.murion.v10.Repository;

import com.example.murion.v10.Entity.CiscoAdvisory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CiscoAdvisoryRepository extends JpaRepository<CiscoAdvisory, String> {

    @Query(value = "SELECT * FROM cisco_advisory c " +
            "WHERE LOWER(CAST(c.productnames AS TEXT)) LIKE LOWER(CONCAT('%', :product, '%'))",
            nativeQuery = true)
    List<CiscoAdvisory> searchByProduct(@Param("product") String product);
}

