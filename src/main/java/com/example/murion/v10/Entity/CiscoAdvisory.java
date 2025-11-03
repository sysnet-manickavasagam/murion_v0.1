package com.example.murion.v10.Entity;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "cisco_advisory")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CiscoAdvisory {

    @Id
    @Column(name = "cve_id", nullable = false, unique = true)
    private String cveId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private JsonNode cisco_data;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private JsonNode bug_id;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private JsonNode cwe;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private JsonNode productnames;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private JsonNode csaf;


    @PrePersist
    @PreUpdate
    public void setProductNameFromJson() {
        if (productnames != null && productnames.isArray() && productnames.size() > 0) {
            this.productnames = productnames.get(0);
        }
    }
}