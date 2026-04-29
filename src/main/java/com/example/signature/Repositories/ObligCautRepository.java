package com.example.signature.Repositories;

import com.example.signature.Entities.SignatureProperties;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

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

    //pour la sol qui va generer prochainement (utilisé dans obligcautService)
    public List<String> findNumDemToProcessO06() {
        String sourceTable = properties.getSourceTable();

        if (sourceTable == null || sourceTable.isBlank()) {
            throw new IllegalStateException("signature.sourceTable est vide");
        }

        String sql = """
                SELECT NUM_DEM_TTN
                FROM %s
                WHERE COD_TYP_DOC = 'O04'
                  AND NUM_DEM_TTN IS NOT NULL
                ORDER BY NUM_DEM_TTN
                """.formatted(sourceTable);

        return jdbcTemplate.queryForList(sql, String.class);
    }

    //pour notre sol presente
    public Map<String, Object> findPendingO04ByNumDos(String numDos) {
        String sql = """
            SELECT ID_FLUX, NUM_DOSS_TTN, NUM_DEM_TTN, COD_TYP_DOC, STATUS, NUM_MESS_TTN
            FROM TTN.DETAIL_OBLIG_CAUT
            WHERE NUM_DOSS_TTN = ?
              AND COD_TYP_DOC = 'O04'
              AND STATUS = 'B'
            FETCH FIRST 1 ROWS ONLY
            """;

        List<Map<String, Object>> rows = jdbcTemplate.queryForList(sql, numDos);
        return rows.isEmpty() ? null : rows.get(0);
    }

    public int updateStatusToE(Long idFlux) {
        String sql = """
            UPDATE TTN.DETAIL_OBLIG_CAUT
            SET STATUS = 'E'
            WHERE ID_FLUX = ?
            """;
        return jdbcTemplate.update(sql, idFlux);
    }


}
