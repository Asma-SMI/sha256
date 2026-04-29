package com.example.signature.Entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "DONNEES_GENERALES", schema = "ref")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class DonneesGenerales {

    @Id
    private Long id;

    @Column(name = "PATH_SCAN_AS")
    private String pathScanAs;
}
