package com.example.signature.Repositories;

import com.example.signature.Entities.SignatureProperties;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class ObligCautRepository {
    private final JdbcTemplate jdbcTemplate;
    private final SignatureProperties properties;

    public ObligCautRepository(JdbcTemplate jdbcTemplate, SignatureProperties properties) {
        this.jdbcTemplate = jdbcTemplate;
        this.properties = properties;
    }

    public String getXmlFromOracle(String numDem) {
        String sql = "SELECT GENERATE_XML_OBLIGCAUT(?) FROM dual";

        return jdbcTemplate.queryForObject(
                sql,
                new Object[]{numDem},
                String.class
        );
    }

    public List<String> findNumDemToProcessO06() {
        String sourceTable = properties.getSourceTable();

        if (sourceTable == null || sourceTable.isBlank()) {
            throw new IllegalStateException("signature.sourceTable est vide");
        }

        String sql = """
                SELECT NUM_DEM_TTN
                FROM %s
                WHERE COD_TYP_DOC = 'O06'
                  AND NUM_DEM_TTN IS NOT NULL
                ORDER BY NUM_DEM_TTN
                """.formatted(sourceTable);

        return jdbcTemplate.queryForList(sql, String.class);
    }
}
