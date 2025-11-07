package com.example.murion.v10.Repository;

import com.example.murion.v10.Entity.CiscoAdvisory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
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


    @Query(
            value = "SELECT * FROM cisco_advisory ca " +
                    "WHERE LOWER(ca.productnames::text) LIKE LOWER(CONCAT('%', :product, '%'))",
            nativeQuery = true
    )
    Page<CiscoAdvisory> findByProductContains(@Param("product") String product, Pageable pageable);
}

