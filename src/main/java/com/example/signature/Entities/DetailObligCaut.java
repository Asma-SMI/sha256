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
@Table(name = "DETAIL_OBLIG_CAUT", schema = "ttn")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class DetailObligCaut {

    @Id
    @Column(name = "ID_FLUX", nullable = false)
    private Long idFlux;

    @Column(name = "ID_IMAIL")
    private Long idImail;

    @Column(name = "STATUS")
    private String status;

    @Column(name = "NUM_MESS_TTN")
    private String numMessTtn;


}

