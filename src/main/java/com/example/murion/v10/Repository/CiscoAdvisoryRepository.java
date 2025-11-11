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


    @Query(value = """
    SELECT *
    FROM cisco_advisory ca
    WHERE EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text(ca.productnames) AS p(name)
        WHERE
            LOWER(p.name) LIKE LOWER(CONCAT('%', :product, '%'))
            AND p.name ~ CONCAT('(^|[^0-9.])', :version, '($|[^0-9.])')
    )
    ORDER BY (ca.cisco_data->>'first_published')::timestamp DESC
    LIMIT 1
""", nativeQuery = true)
    CiscoAdvisory findLatestByProduct(
            @Param("product") String product,
            @Param("version") String version
    );


}

