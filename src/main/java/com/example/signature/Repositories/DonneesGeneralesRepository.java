package com.example.signature.Repositories;

import com.example.signature.Entities.DonneesGenerales;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface DonneesGeneralesRepository extends JpaRepository<DonneesGenerales, Long> {

    @Query("select d.pathScanAs from DonneesGenerales d")
    String findPathScanAs();
}
