# Bai04 - JWT voi Nimbus JOSE+JWT

Bai tap vi du **JSON Web Token** trong bai giang *Lap trinh Web (WEBPR330479) - "Json Web Token"*
(ThS. Nguyen Huu Trung, HCMUTE), duoc lam lai voi mot thay doi chinh:

> **Dung thu vien [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt) thay cho JJWT.**

Toan bo 10 buoc trong bai giang van duoc giu nguyen (them dependency, entity, models, repository,
services, ApplicationConfiguration, Filter, SecurityConfig, RestController, xu ly exception,
render bang Ajax), chi thay lop ky/xac thuc JWT.

- Stack: **Spring Boot 3.5.16**, **Spring Security 6**, Java 21, Maven
- JWT: **com.nimbusds:nimbus-jose-jwt 10.10**, thuat toan HS256
- Database: **H2 in-memory** (mac dinh, chay ngay khong can cai gi) hoac **MySQL** (profile `mysql`, giong bai giang)
- Frontend: Thymeleaf + JavaScript thuan (`fetch`), khong dung CDN

---

## 1. Chay ung dung

Yeu cau: **JDK 21** va **Maven**.

```bash
cd Bai04-JWT-Nimbus
mvn spring-boot:run
```

Mo trinh duyet: <http://localhost:8005/login> (port 8005 giong bai giang).

1. Bam **Dang ky** de tao tai khoan (hoac `POST /auth/signup`).
2. Dang nhap -> server tra JWT -> trinh duyet luu vao `localStorage` -> chuyen sang `/user/profile`.
3. Trang profile goi `GET /users/me` kem header `Authorization: Bearer <token>`.

> Chay tren cong khac: `mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=9000`

### Tai khoan demo (tuy chon)

Mat khau khong duoc luu trong source. Muon co san mot tai khoan demo:

```bash
DEMO_USER_ENABLED=true DEMO_USER_PASSWORD='MatKhauCuaBan@123' mvn spring-boot:run
# email mac dinh: demo@example.test (doi bang DEMO_USER_EMAIL)
```

### Chay bang MySQL / MariaDB (giong bai giang)

Cau hinh duoc dat ten bien moi truong **trung voi cac du an khac trong `Lap-trinh-Web`**
(`Assignment05`, `Assignment06`, `DeThiQuaTrinh03`, `Web-Project-24162120`) nen chi can mot cach cau hinh duy nhat:

```bash
APP_DB_PASSWORD='mat-khau-cua-ban' \
mvn spring-boot:run -Dspring-boot.run.profiles=mysql
```

| Bien moi truong   | Gia tri mac dinh | Y nghia |
|-------------------|------------------|---------|
| `APP_DB_URL`      | `jdbc:mysql://localhost:3306/jwt_springboot3?useUnicode=true&characterEncoding=UTF-8&serverTimezone=Asia/Ho_Chi_Minh&sslMode=PREFERRED&createDatabaseIfNotExist=true` | JDBC URL |
| `APP_DB_USERNAME` | `thien`          | Tai khoan |
| `APP_DB_PASSWORD` | (rong)           | Mat khau |

Ghi chu:

- Database mac dinh la **`jwt_springboot3`** (theo bai giang) chu khong phai `thien`, de bang `users`
  cua bai JWT khong dung do voi bang `users` cua cac du an khac tren cung MySQL server.
- URL co `createDatabaseIfNotExist=true` nen database duoc tao tu dong neu tai khoan co quyen.
  Neu tai khoan khong co quyen do, tao database truoc bang tay — dung script co san:

  ```bash
  mysql -u root -p < docs/setup-mysql.sql     # sua mat khau trong file truoc khi chay
  ```

- `spring.jpa.database-platform=org.hibernate.dialect.MySQLDialect` duoc khai bao **tuong minh**
  (giong cac du an khac). Can thiet vi XAMPP phan phoi kem MariaDB, ma Hibernate 6.6 khong doc duoc
  metadata cua MariaDB (loi `Unknown column 'RESERVED' in 'WHERE'`) nen khong tu nhan dien duoc dialect.
  Canh bao `HHH90000025` khi khoi dong la **binh thuong**, khong phai loi.

Da kiem chung that: profile `mysql` da chay voi mot server MySQL-protocol (MariaDB 11.4.5) —
13/13 phep kiem tra PASS, Hibernate tu tao bang `users`, va **du lieu con nguyen sau khi restart server**
(xem `docs/SECURITY-REVIEW.md` muc 7).

### Build file jar

```bash
mvn clean package
java -jar target/bai04-jwt-nimbus-1.0.0.jar
```

---

## 2. API

| Method | Duong dan       | Yeu cau token | Mo ta                                                  |
|--------|-----------------|---------------|--------------------------------------------------------|
| POST   | `/auth/signup`  | khong         | Tao tai khoan (`fullName`, `email`, `password`)         |
| POST   | `/auth/login`   | khong         | Dang nhap, tra `{ token, expiresIn, tokenType }`        |
| GET    | `/users/me`     | **co**        | Thong tin nguoi dung tu token                           |
| GET    | `/users`        | **co**        | Danh sach nguoi dung                                    |
| GET    | `/login`        | khong         | Trang dang nhap (Thymeleaf)                             |
| GET    | `/register`     | khong         | Trang dang ky (Thymeleaf)                               |
| GET    | `/user/profile` | khong (trang) | Trang ca nhan, goi API bang JavaScript                  |
| GET    | `/h2-console`   | khong (dev)   | Xem database H2 (chi khi `spring.h2.console.enabled=true`) |

### Thu bang curl

```bash
# 1. Dang ky
curl -i -X POST http://localhost:8005/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"fullName":"Nguyen Van A","email":"a@example.test","password":"MatKhau@123"}'

# 2. Dang nhap -> lay token
TOKEN=$(curl -s -X POST http://localhost:8005/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"a@example.test","password":"MatKhau@123"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')

# 3. Goi API duoc bao ve
curl -i http://localhost:8005/users/me -H "Authorization: Bearer $TOKEN"
curl -i http://localhost:8005/users   -H "Authorization: Bearer $TOKEN"

# 4. Khong co token -> 401
curl -i http://localhost:8005/users/me

# 5. Token bi sua -> 401 "The JWT signature is invalid"
curl -i http://localhost:8005/users/me -H "Authorization: Bearer ${TOKEN}x"
```

### Bang ma loi (giong bang o slide 30)

| Loi xac thuc                        | Ngoai le (bai giang)    | HTTP | Ngoai le trong project nay          |
|-------------------------------------|-------------------------|------|-------------------------------------|
| Thong tin dang nhap khong hop le    | `BadCredentialsException` | 401 | `BadCredentialsException`           |
| Tai khoan bi khoa                   | `AccountStatusException`  | 403 | `AccountStatusException`            |
| Khong duoc phep truy cap tai nguyen | `AccessDeniedException`   | 403 | `AccessDeniedException`             |
| JWT khong hop le (sai chu ky)       | `SignatureException`      | 401 | `InvalidTokenSignatureException`    |
| JWT da het han                      | `ExpiredJwtException`     | 401 | `TokenExpiredException`             |
| JWT sai dinh dang / sai thuat toan  | (khong co trong bai)      | 401 | `InvalidTokenException`             |

Tat ca loi tra ve theo dinh dang **RFC 9457 ProblemDetail**:

```json
{
  "type": "about:blank",
  "title": "Unauthorized",
  "status": 401,
  "detail": "The JWT signature is invalid",
  "description": "The JWT signature is invalid"
}
```

---

## 3. Test

```bash
mvn test
```

- `JwtTokenServiceTest` - test don vi lop token: roundtrip, sua token, sai secret, het han,
  thieu `exp`, `alg=none`, token rac, secret qua ngan.
- `JwtNimbusIntegrationTest` - test tich hop: dang ky, dang nhap, goi API bang Bearer token,
  cac ma 401/409/400, va kiem tra response **khong** chua password.

---

## 4. Cau truc project

```
src/main/java/vn/iotstar/jwtnimbus/
├── JwtNimbusApplication.java          # @SpringBootApplication
├── config/
│   ├── ApplicationConfiguration.java  # Buoc 5: UserDetailsService, PasswordEncoder, AuthenticationManager
│   ├── SecurityConfiguration.java     # Buoc 7: SecurityFilterChain + CORS + CSP
│   └── DemoUserInitializer.java       # Tai khoan demo (tuy chon, khong luu mat khau trong source)
├── controller/
│   ├── AuthenticationController.java  # Buoc 8: POST /auth/signup, POST /auth/login
│   ├── UserController.java            # Buoc 8: GET /users/me, GET /users
│   └── ViewController.java            # Buoc 10: /login, /register, /user/profile
├── entity/User.java                   # Buoc 2: @Entity implements UserDetails
├── exception/                         # Buoc 10: cay exception + GlobalExceptionHandler
├── models/                            # Buoc 3: LoginUserModel, RegisterUserModel, LoginResponse, UserResponse
├── repository/UserRepository.java     # Buoc 4
├── security/
│   ├── JwtAuthenticationFilter.java   # Buoc 6
│   └── RestSecurityErrorHandler.java  # Tra ve 401/403 dang JSON
└── service/
    ├── AuthenticationService.java     # Buoc 4: signup + authenticate
    ├── UserService.java               # Buoc 4: allUsers
    └── JwtTokenService.java           # Buoc 4: sinh va xac thuc JWT bang NIMBUS

src/main/resources/
├── application.properties             # H2 + cau hinh JWT
├── application-mysql.properties       # Profile MySQL giong bai giang
├── static/css/app.css
├── static/js/mainjs.js                # Buoc 10: goi API bang fetch
├── static/images/avatar.svg
└── templates/{login,register,profile}.html
```

Tai lieu them:

- [`docs/NIMBUS-VS-JJWT.md`](docs/NIMBUS-VS-JJWT.md) - bang doi chieu tung dong code JJWT -> Nimbus,
  kem bang chung kiem chung bang `javap`/chuong trinh chay that.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - luong du lieu va trach nhiem tung module.
- [`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md) - nhung diem da sua so voi bai giang,
  bang chung kiem chung, va nhung rui ro con lai.
- [`docs/setup-mysql.sql`](docs/setup-mysql.sql) - script tao database + cap quyen cho profile `mysql`.

---

## 5. Diem khac biet so voi bai giang (co chu y)

| # | Bai giang                                   | Project nay                                                  | Ly do |
|---|---------------------------------------------|--------------------------------------------------------------|-------|
| 1 | JJWT (`io.jsonwebtoken`)                    | Nimbus JOSE+JWT (`com.nimbusds`)                              | Theo yeu cau |
| 2 | Tra entity `User` (co ca `password`)        | Tra DTO `UserResponse` (khong co `password`)                  | Khong ro ri password hash |
| 3 | `@Data` tren entity                         | `@Getter/@Setter` + `toString()` khong co password            | Khong ro ri hash vao log |
| 4 | `authorities` luon rong (`List.of()`)       | Co cot `role`, tra ve `ROLE_USER` that                        | Phan quyen dung nghia |
| 5 | Secret key hard-code trong properties       | Doc tu `JWT_SECRET_KEY`; neu khong dat thi tu sinh khoa ngau nhien 256 bit | Khong luu secret trong source |
| 6 | CORS `setAllowedOrigins(List.of("http://localhost:8005"))` | Doc tu `CORS_ALLOWED_ORIGINS`                  | Cau hinh theo moi truong |
| 7 | Dung `columnDefinition = "nvarchar(...)"`   | Dung `length`                                                 | Chay duoc tren H2/MySQL, khong chi SQL Server |
| 8 | MySQL bat buoc                              | H2 in-memory mac dinh, MySQL qua profile                      | Chay duoc ngay sau khi clone |
| 9 | Bootstrap/jQuery tu CDN                     | CSS + JS noi bo                                                | Chay duoc khi khong co Internet |
| 10 | Khong co test                               | 2 bo test (don vi + tich hop)                                 | Kiem chung hoat dong |
| 11 | Khai bao ca bean `UserDetailsService` **va** bean `AuthenticationProvider` | Chi khai bao `UserDetailsService` + `PasswordEncoder`, de Spring Security tu tao `DaoAuthenticationProvider` | Bo bean thua, log khoi dong sach (khong con canh bao `InitializeUserDetailsManagerConfigurer`); hanh vi khong doi, da kiem chung lai bang test |
| 12 | `spring.jpa.hibernate.ddl-auto=update` + MySQL | Giu nguyen, nhung mac dinh chay H2 | Chay duoc ngay ca khi chua cai MySQL |
| 13 | Secret key hard-code (khoa co dinh trong file) | **Khong co khoa mac dinh**; tu sinh khoa ngau nhien luu `.jwt-secret-key`, hoac dung `JWT_SECRET_KEY` | Chan viec doc source roi ky token gia mao (lo hong do reviewer doc lap phat hien) |
| 14 | H2 console bat san, khong can dang nhap | Mac dinh **tat**, phai tu bat | Console doc duoc ca hash mat khau trong bang `users` |
| 15 | Khong co xu ly loi giao thuc HTTP | 404/405/415/400 duoc tra dung ma | Truoc khi sua, tat ca deu bi doi thanh 500 |
| 16 | Claim `iss` chi duoc ghi, khong kiem tra | `iss` phai khop chinh xac khi da cau hinh | Token mang issuer khac bi tu choi |
| 17 | Dung **Lombok** (`@Data`, `@Getter`, `@Setter`) | **Khong dung Lombok**, viet tay getter/setter | Eclipse/STS chi hieu Lombok khi da cai Lombok vao IDE. Neu chua cai, class sinh ra thieu getter/setter, Jackson khong gan duoc du lieu va API tra 400 "Du lieu gui len khong hop le" (xem muc 6) |

---

## 6. Xu ly su tuc: dang ky / dang nhap bao "Du lieu gui len khong hop le"

Day la loi tung gap khi mo project bang **Eclipse / STS ma chua cai Lombok**.

**Trieu chung:** dien day du Ho ten / Email / Password nhung bam Dang ky van bao
`Du lieu gui len khong hop le`; response 400 co dang:

```json
{"status":400,"detail":"Du lieu gui len khong hop le",
 "errors":{"email":"email khong duoc de trong","password":"password khong duoc de trong",
           "fullName":"fullName khong duoc de trong"}}
```

**Nguyen nhan:** ca 3 truong deu bao "trong" nghia la du lieu khong duoc gan vao model.
Class do Eclipse bien dich **thieu getter/setter** vi Lombok khong chay trong IDE:

```bash
javap -p target/classes/vn/iotstar/jwtnimbus/models/RegisterUserModel.class
# => chi co: private String email; ... public RegisterUserModel();   (KHONG co setEmail)
```

**Cach xu ly:** project nay **da bo Lombok** va viet tay getter/setter, nen khong con gap loi nay.
Chi can build lai that sach:

```bash
mvn clean            # xoa class cu do Eclipse build thieu Lombok
mvn spring-boot:run
```

Trong STS/Eclipse: dung server dang chay, chon project -> **Maven -> Update Project... (Alt+F5)**,
tick *Clean projects*, roi chay lai. Kiem tra lai bang:

```bash
javap -p target/classes/vn/iotstar/jwtnimbus/models/RegisterUserModel.class | grep setEmail
# phai thay: public void setEmail(java.lang.String);
```

---

## 7. Bang chung da kiem chung

| Noi dung | Cach kiem chung | Ket qua |
|---|---|---|
| Build + test | `mvn clean test` tai `Lap-trinh-Web/Bai04-JWT-Nimbus` voi `~/.m2` mac dinh | 37/37 test PASS, BUILD SUCCESS |
| Chay server | `mvn spring-boot:run` (mac dinh, H2) | Server len trong ~9s, `GET /login` = 200 |
| Chuc nang + bao mat | 44 phep kiem tra HTTP (dang ky, dang nhap, token, `/users/me`, `/users`, 401/409/400/404/405/415, token bi sua, token het han, sai issuer, token gia mao bang khoa cu, CSP, H2 console) | 44/44 PASS |
| Giao dien | Trinh duyet that: dang ky -> dang nhap -> trang ca nhan -> logout -> token gia mao bi tu choi | PASS, console khong co loi/warning |
| Profile `mysql` | Chay voi server MySQL-protocol (MariaDB 11.4.5): 13 phep kiem tra + kiem tra bang truc tiep trong DB | 13/13 PASS, bang `users` duoc tao, mat khau luu dang BCrypt |
| Du lieu ben vung | Restart server MySQL, dang nhap lai bang tai khoan tao tu lan chay truoc | PASS (du lieu con nguyen) |
| Khoa JWT ben vung | Restart, dung **lai token cu** khong doi | PASS (file `.jwt-secret-key` khong doi) |
| Kiem chung doc lap | Subagent verifier chay lai tren mot ban sao rieng, cong 8015, tu viet kich ban kiem tra | PASS (28 test + 32 phep kiem tra rieng, tren ban truoc khi sua loi bao mat) |
| Danh gia bao mat doc lap | Subagent reviewer phan tich doi khang + chay thu tren instance rieng | 7 finding; 6 da sua, 1 giu nguyen co chu y — xem `docs/SECURITY-REVIEW.md` muc 8 |

Chi tiet o [`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md) muc 7 va 8.

---

## 8. Luu y bao mat

- **Secret key - KHONG co khoa mac dinh trong source.** Neu dat `JWT_SECRET_KEY` thi dung gia tri do
  (tao bang `openssl rand -hex 32`, phai >= 32 byte). Neu khong dat, ung dung tu sinh khoa ngau nhien
  256 bit va luu vao `.jwt-secret-key` trong thu muc lam viec (quyen `600`, da co trong `.gitignore`).
  Nho vay token van con hieu luc sau khi restart, va **moi may co mot khoa rieng** — khong ai doc source
  ma ky duoc token gia mao. Khi trien khai that van nen dat `JWT_SECRET_KEY` va xoay khoa dinh ky.
- **H2 console mac dinh TAT.** Khi bat (`--spring.h2.console.enabled=true`), duong dan `/h2-console/**`
  duoc phep khong can dang nhap va co the doc toan bo bang `users` ke ca hash mat khau.
  Chi bat khi chay local mot minh.
- **localStorage**: bai giang (va project nay) luu token trong `localStorage`. Cach nay de bi XSS doc token.
  Project da them header `Content-Security-Policy` de giam thieu, nhung khi lam that nen dung cookie
  `HttpOnly` + `SameSite`, hoac co che refresh token.
- **CSRF**: da tat vi API dung Bearer token trong header (khong dung cookie => khong co ambient authority).
  Neu chuyen sang cookie, **phai bat lai CSRF**.
- **JWT chi duoc ky, khong duoc ma hoa**: khong dat thong tin nhay cam trong claim.
- Chi tiet day du, kem ket qua danh gia doc lap: [`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md).
