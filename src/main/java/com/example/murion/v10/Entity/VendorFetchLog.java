package com.example.murion.v10.Entity;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Entity
@Data
public class VendorFetchLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String vendorName;

    private LocalDateTime lastFetchTime;
    private LocalDateTime previousFetchTime;

    private int totalData;
    private int addedData;
}
