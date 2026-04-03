package com.example.signature.Repositories;

import com.example.signature.Entities.DetailObligCaut;
import com.example.signature.Entities.Imail;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface DetailObligCautRepository  extends JpaRepository<DetailObligCaut, Long> {
    @Modifying
    @Query("update DetailObligCaut d set d.status = :status where d.idImail = :idImail")
    int updateStatusByIdImail(@Param("idImail") Long idImail,
                              @Param("status") String status);
}
