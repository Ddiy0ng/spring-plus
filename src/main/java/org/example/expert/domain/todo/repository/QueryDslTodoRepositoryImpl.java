package org.example.expert.domain.todo.repository;

import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import org.example.expert.domain.todo.entity.QTodo;
import org.example.expert.domain.todo.entity.Todo;
import org.example.expert.domain.user.entity.QUser;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class QueryDslTodoRepositoryImpl implements QueryDslTodoRepository {
    private final JPAQueryFactory jpaQueryFactory;

    @Override
    public Optional<Todo> findByIdWithUser(Long todoId){
        QTodo qTodo = QTodo.todo;
        QUser qUser = QUser.user;

        return Optional.ofNullable(jpaQueryFactory
                .selectFrom(qTodo)
                .leftJoin(qTodo.user, qUser).fetchJoin()
                .where(qTodo.id.eq(todoId))
                .fetchOne());
    }
}
