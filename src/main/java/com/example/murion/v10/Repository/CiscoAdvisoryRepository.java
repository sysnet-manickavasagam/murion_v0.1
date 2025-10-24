package com.example.murion.v10.Repository;

import com.example.murion.v10.Entity.CiscoAdvisory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CiscoAdvisoryRepository extends JpaRepository<CiscoAdvisory, String> {
}

