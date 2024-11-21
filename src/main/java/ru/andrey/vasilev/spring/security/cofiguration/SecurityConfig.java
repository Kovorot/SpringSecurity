package ru.andrey.vasilev.spring.security.cofiguration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;

import javax.sql.DataSource;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private DataSource dataSource;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        User.UserBuilder userBuilder = User.withDefaultPasswordEncoder();
//        auth.inMemoryAuthentication()
//                .withUser(userBuilder.username("Andrey").password("Andrey").roles("EMPLOYEE"))
//                .withUser(userBuilder.username("Elena").password("Elena").roles("HR"))
//                .withUser(userBuilder.username("Ivan").password("Ivan").roles("MANAGER", "HR"));

        auth.jdbcAuthentication().dataSource(dataSource);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/").hasAnyRole("EMPLOYEE", "HR", "MANAGER")
                .antMatchers("/hr-info").hasAnyRole("HR")
                .antMatchers("/manager-info/**").hasAnyRole("MANAGER")
                .and().formLogin().permitAll();
    }

    @Autowired
    private void setDataSource(DataSource dataSource) {
        this.dataSource = dataSource;
    }
}
