package com.example.murion.v10.Repository;

import com.example.murion.v10.Entity.VendorFetchLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface VendorFetchLogRepository extends JpaRepository<VendorFetchLog, Long> {
    Optional<VendorFetchLog> findByVendorName(String vendorName);
    Optional<VendorFetchLog> findByVendorNameAndYear(String vendorName, Integer year);

}
