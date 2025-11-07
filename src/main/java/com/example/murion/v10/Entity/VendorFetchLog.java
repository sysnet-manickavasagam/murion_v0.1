package com.example.murion.v10.Entity;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Entity
public class VendorFetchLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String vendorName;

    private String year;

    private LocalDateTime lastFetchTime;
    private LocalDateTime previousFetchTime;

    private Integer updatedData;

    private int totalData;
    private int addedData;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getVendorName() {
        return vendorName;
    }

    public void setVendorName(String vendorName) {
        this.vendorName = vendorName;
    }

    public String getYear() {
        return year;
    }

    public void setYear(String year) {
        this.year = year;
    }

    public LocalDateTime getLastFetchTime() {
        return lastFetchTime;
    }

    public void setLastFetchTime(LocalDateTime lastFetchTime) {
        this.lastFetchTime = lastFetchTime;
    }

    public LocalDateTime getPreviousFetchTime() {
        return previousFetchTime;
    }

    public void setPreviousFetchTime(LocalDateTime previousFetchTime) {
        this.previousFetchTime = previousFetchTime;
    }

    public int getTotalData() {
        return totalData;
    }

    public void setTotalData(int totalData) {
        this.totalData = totalData;
    }

    public int getAddedData() {
        return addedData;
    }

    public void setAddedData(int addedData) {
        this.addedData = addedData;
    }

    public Integer getUpdatedData() {
        return updatedData;
    }

    public void setUpdatedData(Integer updatedData) {
        this.updatedData = updatedData;
    }
}
