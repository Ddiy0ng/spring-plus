package org.example.expert.domain.todo.repository;

import org.example.expert.domain.todo.entity.Todo;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;

public interface TodoRepository extends JpaRepository<Todo, Long>, QueryDslTodoRepository {

    @Query("SELECT t FROM Todo t LEFT JOIN FETCH t.user u ORDER BY t.modifiedAt DESC")
    Page<Todo> findAllByOrderByModifiedAtDesc(Pageable pageable);

    // 조건에서 null이 있는 경우 알아서 걸러짐
    @Query("SELECT t FROM Todo t " +
            "WHERE :weather IS NULL OR t.weather LIKE :weather " +
            "AND :startDate IS NULL OR t.modifiedAt >= :startDate " +
            "AND :endDate IS NULL OR t.modifiedAt <= :endDate " +
            "ORDER BY t.modifiedAt DESC")
    Page<Todo> findTodos(@Param("weather") String weather, @Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate, Pageable pageable);

}
