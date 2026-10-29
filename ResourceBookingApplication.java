
package com.example.booking;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.persistence.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.*;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@SpringBootApplication
public class ResourceBookingApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResourceBookingApplication.class, args);
    }

    // =====================================================
    // ENUMS
    // =====================================================

    public enum Role {
        ADMIN, USER
    }

    public enum ReservationStatus {
        PENDING, CONFIRMED, CANCELLED
    }

    // =====================================================
    // DATABASE ENTITIES
    // =====================================================

    @Entity
    @Table(name = "app_users")
    public static class AppUser implements UserDetails {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        public Long id;

        @Column(nullable = false, length = 80)
        public String name;

        @Column(nullable = false, unique = true, length = 150)
        public String email;

        @JsonIgnore
        @Column(nullable = false)
        public String password;

        @Enumerated(EnumType.STRING)
        @Column(nullable = false, length = 10)
        public Role role = Role.USER;

        public AppUser() {}

        @Override
        @JsonIgnore
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
        }

        @Override
        @JsonIgnore
        public String getUsername() {
            return email;
        }

        @Override
        @JsonIgnore
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        @JsonIgnore
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        @JsonIgnore
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        @JsonIgnore
        public boolean isEnabled() {
            return true;
        }
    }

    @Entity
    @Table(name = "resources")
    public static class BookableResource {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        public Long id;

        @NotBlank
        @Size(max = 120)
        @Column(nullable = false, length = 120)
        public String name;

        @NotBlank
        @Size(max = 80)
        @Column(nullable = false, length = 80)
        public String type;

        @Size(max = 500)
        public String description;

        @NotBlank
        @Size(max = 150)
        @Column(nullable = false, length = 150)
        public String location;

        @Column(nullable = false)
        public boolean active = true;

        public BookableResource() {}
    }

    @Entity
    @Table(name = "reservations",
           indexes = @Index(name = "idx_reservation_owner",
                            columnList = "user_id"))
    public static class Reservation {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        public Long id;

        @ManyToOne(fetch = FetchType.EAGER, optional = false)
        @JoinColumn(name = "resource_id", nullable = false)
        public BookableResource resource;

        @ManyToOne(fetch = FetchType.EAGER, optional = false)
        @JoinColumn(name = "user_id", nullable = false)
        public AppUser user;

        @NotNull
        @Column(nullable = false)
        public LocalDateTime startTime;

        @NotNull
        @Column(nullable = false)
        public LocalDateTime endTime;

        @NotNull
        @DecimalMin(value = "0.01")
        @Column(nullable = false, precision = 12, scale = 2)
        public BigDecimal price;

        @Enumerated(EnumType.STRING)
        @Column(nullable = false, length = 20)
        public ReservationStatus status = ReservationStatus.PENDING;

        public Reservation() {}
    }

    // =====================================================
    // REPOSITORIES
    // =====================================================

    public interface UserRepository
            extends org.springframework.data.jpa.repository.JpaRepository<AppUser, Long> {
        Optional<AppUser> findByEmail(String email);
        boolean existsByEmail(String email);
    }

    public interface ResourceRepository
            extends org.springframework.data.jpa.repository.JpaRepository<BookableResource, Long> {}

    public interface ReservationRepository
            extends org.springframework.data.jpa.repository.JpaRepository<Reservation, Long>,
                    org.springframework.data.jpa.repository.JpaSpecificationExecutor<Reservation> {

        boolean existsByResourceIdAndStartTimeLessThanAndEndTimeGreaterThan(
                Long resourceId, LocalDateTime endTime, LocalDateTime startTime);

        boolean existsByResource_IdAndStartTimeLessThanAndEndTimeGreaterThanAndIdNot(
                Long resourceId, LocalDateTime endTime,
                LocalDateTime startTime, Long excludedId);
    }

    // =====================================================
    // DTOs
    // =====================================================

    public record LoginRequest(
            @NotBlank @Email String email,
            @NotBlank String password) {}

    public record LoginResponse(String token, String tokenType, String role) {}

    public record ResourceRequest(
            @NotBlank @Size(max = 120) String name,
            @NotBlank @Size(max = 80) String type,
            @Size(max = 500) String description,
            @NotBlank @Size(max = 150) String location,
            Boolean active) {}

    public record ReservationRequest(
            @NotNull @Positive Long resourceId,
            @NotNull LocalDateTime startTime,
            @NotNull LocalDateTime endTime,
            @NotNull @DecimalMin("0.01") BigDecimal price,
            ReservationStatus status,
            Long userId) {}

    // =====================================================
    // JWT SERVICE
    // =====================================================

    @Service
    public static class JwtService {
        private final javax.crypto.SecretKey key;
        private final long expirationMs;

        public JwtService(
                @Value("${app.jwt.secret}") String secret,
                @Value("${app.jwt.expiration-ms:86400000}") long expirationMs) {
            this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
            this.expirationMs = expirationMs;
        }

        public String generate(AppUser user) {
            Date now = new Date();

            return Jwts.builder()
                    .subject(user.email)
                    .claim("role", user.role.name())
                    .issuedAt(now)
                    .expiration(new Date(now.getTime() + expirationMs))
                    .signWith(key)
                    .compact();
        }

        public Claims parse(String token) {
            return Jwts.parser().verifyWith(key).build()
                    .parseSignedClaims(token).getPayload();
        }
    }

    // =====================================================
    // JWT AUTHENTICATION FILTER
    // =====================================================

    @Component
    public static class JwtFilter extends OncePerRequestFilter {
        private final JwtService jwt;
        private final UserRepository users;

        public JwtFilter(JwtService jwt, UserRepository users) {
            this.jwt = jwt;
            this.users = users;
        }

        @Override
        protected void doFilterInternal(
                HttpServletRequest request,
                HttpServletResponse response,
                FilterChain chain) throws ServletException, IOException {

            String header = request.getHeader("Authorization");

            if (header != null && header.startsWith("Bearer ")) {
                try {
                    Claims claims = jwt.parse(header.substring(7));
                    String email = claims.getSubject();

                    if (SecurityContextHolder.getContext().getAuthentication() == null) {
                        AppUser user = users.findByEmail(email).orElse(null);

                        if (user != null) {
                            var authentication =
                                    new UsernamePasswordAuthenticationToken(
                                            user, null, user.getAuthorities());

                            SecurityContextHolder.getContext()
                                    .setAuthentication(authentication);
                        } else {
                            response.sendError(401, "User not found");
                            return;
                        }
                    }
                } catch (io.jsonwebtoken.JwtException |
                         IllegalArgumentException ex) {
                    SecurityContextHolder.clearContext();
                    response.sendError(401, "Invalid or expired token");
                    return;
                }
            }

            chain.doFilter(request, response);
        }
    }

    // =====================================================
    // SECURITY CONFIGURATION
    // =====================================================

    @Configuration
    @EnableMethodSecurity
    public static class SecurityConfig {

        @Bean
        PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }

        @Bean
        UserDetailsService userDetailsService(UserRepository users) {
            return email -> users.findByEmail(email)
                    .orElseThrow(() ->
                            new UsernameNotFoundException("User not found"));
        }

        @Bean
        DaoAuthenticationProvider authenticationProvider(
                UserDetailsService service, PasswordEncoder encoder) {
            DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
            provider.setUserDetailsService(service);
            provider.setPasswordEncoder(encoder);
            return provider;
        }

        @Bean
        AuthenticationManager authenticationManager(
                org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration config)
                throws Exception {
            return config.getAuthenticationManager();
        }

        @Bean
        SecurityFilterChain securityFilterChain(
                HttpSecurity http,
                JwtFilter filter,
                DaoAuthenticationProvider provider) throws Exception {

            return http
                    .csrf(csrf -> csrf.disable())
                    .sessionManagement(s -> s.sessionCreationPolicy(
                            SessionCreationPolicy.STATELESS))
                    .authenticationProvider(provider)
                    .authorizeHttpRequests(auth -> auth
                            .requestMatchers("/auth/login", "/error",
                                    "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                            .requestMatchers("/api/resources/**")
                                    .hasAnyRole("USER", "ADMIN")
                            .requestMatchers("/api/reservations/**")
                                    .hasAnyRole("USER", "ADMIN")
                            .anyRequest().authenticated())
                    .exceptionHandling(ex -> ex
                            .authenticationEntryPoint((req, res, error) ->
                                    res.sendError(401, "Authentication required"))
                            .accessDeniedHandler((req, res, error) ->
                                    res.sendError(403, "Access denied")))
                    .addFilterBefore(filter,
                            UsernamePasswordAuthenticationFilter.class)
                    .build();
        }
    }

    // =====================================================
    // LOGIN CONTROLLER
    // =====================================================

    @RestController
    @RequestMapping("/auth")
    public static class AuthController {
        private final AuthenticationManager manager;
        private final JwtService jwt;

        public AuthController(AuthenticationManager manager, JwtService jwt) {
            this.manager = manager;
            this.jwt = jwt;
        }

        @PostMapping("/login")
        public LoginResponse login(@Valid @RequestBody LoginRequest request) {
            var authentication = manager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.email().trim().toLowerCase(),
                            request.password()));

            AppUser user = (AppUser) authentication.getPrincipal();

            return new LoginResponse(
                    jwt.generate(user), "Bearer", user.role.name());
        }
    }

    // =====================================================
    // RESOURCE CONTROLLER
    // =====================================================

    @RestController
    @RequestMapping("/api/resources")
    public static class ResourceController {
        private final ResourceRepository resources;

        public ResourceController(ResourceRepository resources) {
            this.resources = resources;
        }

        @GetMapping
        public List<BookableResource> list() {
            return resources.findAll();
        }

        @GetMapping("/{id}")
        public BookableResource get(@PathVariable Long id) {
            return resources.findById(id).orElseThrow(() ->
                    new ResponseStatusException(HttpStatus.NOT_FOUND,
                            "Resource not found"));
        }

        @PostMapping
        @org.springframework.security.access.prepost.PreAuthorize("hasRole('ADMIN')")
        @ResponseStatus(HttpStatus.CREATED)
        public BookableResource create(@Valid @RequestBody ResourceRequest request) {
            BookableResource resource = new BookableResource();
            copy(request, resource);
            return resources.save(resource);
        }

        @PutMapping("/{id}")
        @org.springframework.security.access.prepost.PreAuthorize("hasRole('ADMIN')")
        public BookableResource update(
                @PathVariable Long id,
                @Valid @RequestBody ResourceRequest request) {
            BookableResource resource = resources.findById(id)
                    .orElseThrow(() -> new ResponseStatusException(
                            HttpStatus.NOT_FOUND, "Resource not found"));

            copy(request, resource);
            return resources.save(resource);
        }

        @DeleteMapping("/{id}")
        @org.springframework.security.access.prepost.PreAuthorize("hasRole('ADMIN')")
        @ResponseStatus(HttpStatus.NO_CONTENT)
        public void delete(@PathVariable Long id) {
            BookableResource resource = resources.findById(id)
                    .orElseThrow(() -> new ResponseStatusException(
                            HttpStatus.NOT_FOUND, "Resource not found"));
            resources.delete(resource);
        }

        private void copy(ResourceRequest request, BookableResource resource) {
            resource.name = request.name();
            resource.type = request.type();
            resource.description = request.description();
            resource.location = request.location();
            if (request.active() != null) {
                resource.active = request.active();
            }
        }
    }

    // =====================================================
    // RESERVATION CONTROLLER
    // =====================================================

    @RestController
    @RequestMapping("/api/reservations")
    public static class ReservationController {
        private final ReservationRepository reservations;
        private final ResourceRepository resources;
        private final UserRepository users;

        public ReservationController(
                ReservationRepository reservations,
                ResourceRepository resources,
                UserRepository users) {
            this.reservations = reservations;
            this.resources = resources;
            this.users = users;
        }

        private boolean isAdmin(AppUser user) {
            return user.role == Role.ADMIN;
        }

        private Reservation findOwned(Long id, AppUser currentUser) {
            Reservation reservation = reservations.findById(id)
                    .orElseThrow(() -> new ResponseStatusException(
                            HttpStatus.NOT_FOUND, "Reservation not found"));

            if (!isAdmin(currentUser)
                    && !reservation.user.id.equals(currentUser.id)) {
                // Return 404 to avoid disclosing another user's reservation.
                throw new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Reservation not found");
            }
            return reservation;
        }

        @PostMapping
        @Transactional
        @ResponseStatus(HttpStatus.CREATED)
        public Reservation create(
                @Valid @RequestBody ReservationRequest request,
                @org.springframework.security.core.annotation.AuthenticationPrincipal
                AppUser currentUser) {

            Reservation reservation = new Reservation();
            apply(request, reservation, currentUser, true);
            return reservations.save(reservation);
        }

        @GetMapping
        public Page<Reservation> list(
                @org.springframework.security.core.annotation.AuthenticationPrincipal
                AppUser currentUser,
                @RequestParam(required = false) ReservationStatus status,
                @RequestParam(required = false) BigDecimal minPrice,
                @RequestParam(required = false) BigDecimal maxPrice,
                @RequestParam(defaultValue = "0") int page,
                @RequestParam(defaultValue = "10") int size,
                @RequestParam(defaultValue = "startTime") String sortBy,
                @RequestParam(defaultValue = "asc") String direction) {

            if (page < 0 || size < 1 || size > 100) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "page must be >= 0 and size must be 1..100");
            }

            if ((minPrice != null && minPrice.signum() < 0)
                    || (maxPrice != null && maxPrice.signum() < 0)
                    || (minPrice != null && maxPrice != null
                    && minPrice.compareTo(maxPrice) > 0)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Invalid price range");
            }

            Set<String> allowedSort = Set.of(
                    "id", "startTime", "endTime", "price", "status");

            if (!allowedSort.contains(sortBy)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Unsupported sort field");
            }

            Sort.Direction sortDirection;
            try {
                sortDirection = Sort.Direction.fromString(direction);
            } catch (IllegalArgumentException ex) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "direction must be asc or desc");
            }

            Specification<Reservation> spec =
                    (root, query, cb) -> cb.conjunction();

            if (!isAdmin(currentUser)) {
                spec = spec.and((root, query, cb) ->
                        cb.equal(root.get("user").get("id"), currentUser.id));
            }

            if (status != null) {
                spec = spec.and((root, query, cb) ->
                        cb.equal(root.get("status"), status));
            }
            if (minPrice != null) {
                spec = spec.and((root, query, cb) ->
                        cb.greaterThanOrEqualTo(root.get("price"), minPrice));
            }
            if (maxPrice != null) {
                spec = spec.and((root, query, cb) ->
                        cb.lessThanOrEqualTo(root.get("price"), maxPrice));
            }

            Pageable pageable = PageRequest.of(page, size,
                    Sort.by(sortDirection, sortBy));

            return reservations.findAll(spec, pageable);
        }

        @GetMapping("/{id}")
        public Reservation get(
                @PathVariable Long id,
                @org.springframework.security.core.annotation.AuthenticationPrincipal
                AppUser currentUser) {
            return findOwned(id, currentUser);
        }

        @PutMapping("/{id}")
        @Transactional
        @org.springframework.security.access.prepost.PreAuthorize("hasRole('ADMIN')")
        public Reservation update(
                @PathVariable Long id,
                @Valid @RequestBody ReservationRequest request,
                @org.springframework.security.core.annotation.AuthenticationPrincipal
                AppUser currentUser) {

            Reservation reservation = findOwned(id, currentUser);
            apply(request, reservation, currentUser, false);
            return reservations.save(reservation);
        }

        @PatchMapping("/{id}/status")
        @org.springframework.security.access.prepost.PreAuthorize("hasRole('ADMIN')")
        public Reservation changeStatus(
                @PathVariable Long id,
                @RequestBody Map<String, String> body,
                @org.springframework.security.core.annotation.AuthenticationPrincipal
                AppUser currentUser) {

            Reservation reservation = findOwned(id, currentUser);

            try {
                reservation.status =
                        ReservationStatus.valueOf(body.get("status"));
            } catch (Exception ex) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "status must be PENDING, CONFIRMED, or CANCELLED");
            }
            return reservations.save(reservation);
        }

        @DeleteMapping("/{id}")
        @org.springframework.security.access.prepost.PreAuthorize("hasRole('ADMIN')")
        @ResponseStatus(HttpStatus.NO_CONTENT)
        public void delete(
                @PathVariable Long id,
                @org.springframework.security.core.annotation.AuthenticationPrincipal
                AppUser currentUser) {
            reservations.delete(findOwned(id, currentUser));
        }

        private void apply(
                ReservationRequest request,
                Reservation reservation,
                AppUser currentUser,
                boolean creating) {

            if (!request.endTime().isAfter(request.startTime())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "endTime must be after startTime");
            }

            if (request.startTime().isBefore(LocalDateTime.now())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "startTime cannot be in the past");
            }

            BookableResource resource = resources.findById(request.resourceId())
                    .orElseThrow(() -> new ResponseStatusException(
                            HttpStatus.NOT_FOUND, "Resource not found"));

            if (!resource.active) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Resource is not active");
            }

            boolean admin = isAdmin(currentUser);

            if (!admin && request.status() != null) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                        "Only ADMIN can set reservation status");
            }

            // Ownership always comes from the authenticated principal for USER.
            AppUser owner = currentUser;
            if (admin && request.userId() != null) {
                owner = users.findById(request.userId())
                        .orElseThrow(() -> new ResponseStatusException(
                                HttpStatus.NOT_FOUND, "User not found"));
            }

            boolean overlapping;
            if (creating) {
                overlapping =
                        reservations.existsByResourceIdAndStartTimeLessThanAndEndTimeGreaterThan(
                                resource.id, request.endTime(), request.startTime());
            } else {
                overlapping =
                        reservations.existsByResource_IdAndStartTimeLessThanAndEndTimeGreaterThanAndIdNot(
                                resource.id, request.endTime(),
                                request.startTime(), reservation.id);
            }

            if (overlapping) {
                throw new ResponseStatusException(HttpStatus.CONFLICT,
                        "Resource already has an overlapping reservation");
            }

            reservation.resource = resource;
            reservation.user = owner;
            reservation.startTime = request.startTime();
            reservation.endTime = request.endTime();
            reservation.price = request.price();

            if (admin && request.status() != null) {
                reservation.status = request.status();
            } else if (creating) {
                reservation.status = ReservationStatus.PENDING;
            }
        }
    }

    // =====================================================
    // SEED TEST USERS AND SAMPLE RESOURCE
    // =====================================================

    @Bean
    CommandLineRunner seedData(
            UserRepository users,
            ResourceRepository resources,
            PasswordEncoder encoder,
            @Value("${SEED_ADMIN_PASSWORD}") String adminPassword,
            @Value("${SEED_USER_PASSWORD}") String userPassword) {

        return args -> {
            if (!users.existsByEmail("admin@example.com")) {
                AppUser admin = new AppUser();
                admin.name = "Test Administrator";
                admin.email = "admin@example.com";
                admin.password = encoder.encode(adminPassword);
                admin.role = Role.ADMIN;
                users.save(admin);
            }

            if (!users.existsByEmail("user@example.com")) {
                AppUser user = new AppUser();
                user.name = "Test User";
                user.email = "user@example.com";
                user.password = encoder.encode(userPassword);
                user.role = Role.USER;
                users.save(user);
            }

            if (resources.count() == 0) {
                BookableResource resource = new BookableResource();
                resource.name = "Meeting Room A";
                resource.type = "Room";
                resource.description = "Sample bookable meeting room";
                resource.location = "First Floor";
                resource.active = true;
                resources.save(resource);
            }
        };
    }

    // =====================================================
    // ERROR HANDLING
    // =====================================================

    @RestControllerAdvice
    public static class ApiExceptionHandler {

        @ExceptionHandler(ResponseStatusException.class)
        public ResponseEntity<Map<String, Object>> handleStatus(
                ResponseStatusException ex) {
            return ResponseEntity.status(ex.getStatusCode()).body(Map.of(
                    "success", false,
                    "message", ex.getReason() == null
                            ? "Request failed" : ex.getReason()));
        }

        @ExceptionHandler(
                org.springframework.web.bind.MethodArgumentNotValidException.class)
        public ResponseEntity<Map<String, Object>> handleValidation(
                org.springframework.web.bind.MethodArgumentNotValidException ex) {
            List<String> errors = ex.getBindingResult().getFieldErrors()
                    .stream()
                    .map(error -> error.getField() + ": " + error.getDefaultMessage())
                    .toList();

            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "Validation failed",
                    "errors", errors));
        }

        @ExceptionHandler(
                org.springframework.http.converter.HttpMessageNotReadableException.class)
        public ResponseEntity<Map<String, Object>> handleBadJson(Exception ex) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "Invalid request body or enum value"));
        }

        @ExceptionHandler(Exception.class)
        public ResponseEntity<Map<String, Object>> handleUnexpected(Exception ex) {
            // Log the exception in server logs; do not disclose internal details.
            System.err.println("Unexpected API error: " + ex.getMessage());

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "message", "Internal server error"));
        }
    }
}
