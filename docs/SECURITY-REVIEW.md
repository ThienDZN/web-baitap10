# Danh gia bao mat

Tai lieu nay ghi lai: (a) nhung lo hong cua bai giang da duoc sua, (b) nhung kiem soat dang co,
(c) nhung rui ro con lai. Phan "tu ra soat" va "danh gia doc lap" duoc ghi tach nhau.

- Pham vi: toan bo source cua project `Bai04-JWT-Nimbus`.
- Phuong phap: doc code + chay thu nghiem (test tu dong, kiem tra HTTP that, kiem tra bang trinh duyet)
  + doi chieu OWASP Top 10 va cac loi JWT dac thu.

---

## 1. Lo hong cua bai giang da duoc sua

| # | Van de trong bai giang | Rui ro | Cach sua trong project nay | Bang chung |
|---|---|---|---|---|
| 1 | `POST /auth/signup` tra ve nguyen entity `User`, **bao gom ca `password`** (slide 28) | Lo password hash, cho phep brute-force offline | Dung DTO `UserResponse` (khong co truong password) + `@JsonIgnore` tren `User.password` | `JwtNimbusIntegrationTest.signupDoesNotLeakPassword`; kiem tra e2e (`response signup KHONG co password`) |
| 2 | `@Data` (Lombok) tren entity | `toString()` sinh ra chua password hash -> ro ri vao log | **Bo Lombok**, viet tay getter/setter + `toString()` khong co password | `User.java` |
| 3 | `getAuthorities()` tra ve `List.of()` (rong) | Nguoi dung da dang nhap nhung khong co quyen nao; khong the phan quyen | Them cot `role`, tra ve `ROLE_<role>` | `token` payload co `"authorities": ["ROLE_USER"]` (kiem tra e2e muc 4) |
| 4 | Secret key hard-code trong `application.properties` | Khoa ky bi lo trong source control -> ke tan cong ky duoc token tuy y | Doc tu `JWT_SECRET_KEY`; kiem tra do dai >= 256 bit va tu choi khoi dong neu sai | `JwtTokenServiceTest.shortSecretIsRejected`, `blankSecretIsRejected` |
| 5 | Khong kiem tra `alg` cua token | **Algorithm confusion**: chap nhan `alg=none` hoac thuat toan khac | Chi chap nhan dung `HS256` da cau hinh, kiem tra **truoc** khi verify chu ky | `JwtTokenServiceTest.noneAlgorithmTokenIsRejected` |
| 6 | (Doi sang Nimbus) `verify()` khong kiem tra `exp`, va thieu `exp` van duoc chap nhan | Token khong bao gio het han hoac dung qua han | Bat buoc claim `exp` (`requiredClaims`) + goi `DefaultJWTClaimsVerifier` | `JwtTokenServiceTest.tokenWithoutExpirationIsRejected`, `expiredTokenIsRejected` |
| 7 | CORS cau hinh cung trong code | Kho cau hinh theo moi truong, de bi mo rong sai | Doc tu `app.cors.allowed-origins`, khong dung `*` | `SecurityConfiguration.corsConfigurationSource()` |
| 8 | Khong co CSP | Neu co XSS thi script doc duoc token trong `localStorage` | Dat `Content-Security-Policy` (chi noi long `unsafe-inline` khi bat H2 console) | Header that: `default-src 'self'; script-src 'self'; ...` (kiem tra e2e muc 8) |
| 9 | `@Component` + `addFilterBefore` -> filter chay **hai lan** | Filter xu ly hai lan moi request; kho doan loi | `FilterRegistrationBean.setEnabled(false)` | `SecurityConfiguration.jwtAuthenticationFilterRegistration()` |
| 10 | Loi 500 tra `ex.getMessage()` | Lo chi tiet noi bo | Loi 500 tra thong bao chung, chi tiet ghi log | `GlobalExceptionHandler.handleUnexpected()` |

---

## 2. Kiem soat bao mat dang co

| Kiem soat | Chi tiet | Trang thai |
|---|---|---|
| Hash mat khau | BCrypt (strength 10), khong bao gio luu plaintext | Co |
| Chong enumerate email | Giu mac dinh `hideUserNotFoundExceptions=true`; email khong ton tai va sai mat khau deu tra 401 giong nhau | Co |
| Kiem tra dau vao | `@Valid`, `@Email`, `@NotBlank`, `@Size` tren model; loi tra 400 + chi tiet tung truong | Co |
| Chong SQL injection | Spring Data JPA repository, khong noi chuoi SQL | Co |
| Chong XSS | Thymeleaf escape mac dinh; `mainjs.js` dung `textContent` (khong dung `innerHTML`) | Co |
| Chong XSS (lop 2) | CSP header | Co (noi long khi bat H2 console) |
| Chong CSRF | Tat CSRF **co ly do**: API dung Bearer token trong header, khong dung cookie => khong co ambient authority | Co (co dieu kien, xem muc 4) |
| Phan quyen | `authorities` duoc lay tu `role`; `SecurityContext` duoc thiet lap tu token da xac thuc | Co |
| Tra loi loi | RFC 9457 `ProblemDetail`, khong lo stack trace | Co |
| Kiem tra chu ky | Bat buoc verify truoc khi doc bat ky claim nao | Co |
| Secret | Lay tu bien moi truong, kiem tra do dai, khong log gia tri | Co |

---

## 3. Rui ro con lai

Xep theo muc do giam dan. Day la han che **co y thuc** cua mot bai tap, khong phai khang dinh an toan.

### 3.1 [CAO] Token luu trong `localStorage`

- **Mo ta:** `mainjs.js` luu JWT vao `localStorage` (giong bai giang). Bat ky XSS nao cung doc duoc token.
- **Giam thieu da co:** CSP `script-src 'self'` (khong co inline script), khong dung `innerHTML`.
- **Khuyen nghi khi lam that:** dung cookie `HttpOnly` + `Secure` + `SameSite=Lax/Strict`, hoac mo hinh BFF
  (token giu o server, trinh duyet chi giu session cookie).
- **Chua kiem chung:** chua chay quet XSS tu dong.

### 3.2 [CAO] Khong co co che thu hoi token

- **Mo ta:** logout chi xoa token o `localStorage`. Token van hop le tren server den khi het han (mac dinh 1 gio).
  Neu token bi lo, khong the vo hieu hoa truoc han.
- **Khuyen nghi:** thoi han token ngan (5-15 phut) + refresh token; hoac denylist theo `jti`;
  hoac doi `security.jwt.secret-key` (thu hoi tat ca token cung luc).
- **Ghi chu:** day la danh doi co huu cua JWT stateless, khong phai loi trien khai.

### 3.3 [DA SUA - muc CAO] Secret mac dinh nam trong `application.properties`

- **Van de (do reviewer doc lap phat hien, muc HIGH):** ban dau project dat mot khoa mac dinh
  trong `application.properties`. Reviewer da **ky duoc mot token gia mao bang chinh khoa do**
  va goi duoc `GET /users/me` voi quyen cua nan nhan. Bat ky ai doc duoc source (vi du tren GitHub)
  deu lam duoc dieu nay. Kiem tra do dai >= 256 bit khong giup ich gi.
- **Da sua:** **khong con khoa mac dinh nao trong source** (`security.jwt.secret-key=${JWT_SECRET_KEY:}`).
  - Neu dat `JWT_SECRET_KEY` -> dung gia tri do (phai >= 32 byte, neu ngan hon thi tu choi khoi dong).
  - Neu khong dat -> sinh khoa ngau nhien 256 bit, luu vao `.jwt-secret-key` trong thu muc lam viec
    voi quyen `600` (da co trong `.gitignore`), nen token van con hieu luc sau khi restart va
    **moi may co mot khoa rieng**.
  - Neu khong ghi duoc file -> dung khoa ngau nhien trong bo nho (token mat hieu luc khi restart).
- **Bang chung:** `JwtTokenServiceTest.missingSecretIsGeneratedInsteadOfUsingADefault` (token ky bang khoa
  mac dinh cu bi tu choi); kiem tra e2e muc 7 (`token ky bang khoa mac dinh CU -> 401`);
  kiem tra thu cong: restart server voi profile `mysql`, dung **lai token cu** -> 200, va file khoa
  khong doi (`sha256` giong nhau truoc/sau restart).

### 3.4 [TRUNG BINH] Khong co gioi han so lan dang nhap

- **Mo ta:** `/auth/login` khong co rate limit hay khoa tai khoan => co the brute-force mat khau.
- **Khuyen nghi:** rate limit theo IP + theo tai khoan, exponential backoff, hoac CAPTCHA sau N lan sai.

### 3.5 [TRUNG BINH] Khong co HTTPS

- **Mo ta:** JWT truyen trong header `Authorization` dang HTTP thuong => bi doc neu nghe len.
- **Khuyen nghi:** bat buoc TLS khi trien khai; bat `server.ssl.*` hoac dat sau reverse proxy;
  them HSTS.

### 3.6 [DA SUA - muc TRUNG BINH] H2 console bat mac dinh va duoc `permitAll`

- **Van de (reviewer phat hien, muc MEDIUM):** ban dau `spring.h2.console.enabled=true` trong profile
  mac dinh va `/h2-console/**` duoc `permitAll`. Reviewer da dang nhap H2 console **khong can xac thuc**
  (url `jdbc:h2:mem:jwt_nimbus`, user `sa`, mat khau rong) va chay
  `SELECT id,email,full_name,role,password FROM users` — doc duoc **hash BCrypt** cua moi nguoi dung.
- **Da sua:** `spring.h2.console.enabled=false` la mac dinh. Muon xem database phai tu bat:
  ```bash
  mvn spring-boot:run -Dspring-boot.run.arguments=--spring.h2.console.enabled=true
  ```
  Khi bat, duong dan van duoc `permitAll` (H2 console co form dang nhap rieng), nen chi nen bat khi
  chay local mot minh. Profile `mysql` cung dat `spring.h2.console.enabled=false`.
- **Bang chung:** `JwtNimbusIntegrationTest.h2ConsoleIsNotPublicByDefault` (401); kiem tra e2e muc 10
  (`H2 console KHONG truy cap an danh -> 401`).
- **Luu y:** CSP cung vi vay ma nghiem hon — khi H2 console tat, CSP khong con `'unsafe-inline'`.

### 3.7 [THAP] Nhanh loi 403 cho tai khoan bi khoa chua co duong kich hoat

- **Mo ta:** `GlobalExceptionHandler` co nhanh `AccountStatusException -> 403` (giong bang cua bai giang),
  nhung `User.isAccountNonLocked()` luon tra `true` nen thuc te khong co tai khoan nao bi khoa.
- **Khuyen nghi:** them cot `locked`/`enabled` va tra gia tri that neu can kiem thu nhanh 403.

### 3.8 [THAP] `spring.jpa.hibernate.ddl-auto=update`

- **Mo ta:** phu hop bai tap, khong phu hop production (khong co version hoa schema, co the mat du lieu).
- **Khuyen nghi:** dung Flyway hoac Liquibase.

### 3.9 [THAP] Thieu audit log

- **Mo ta:** dang nhap thanh cong/that bai chi duoc ghi o muc `WARN`/`INFO` chung, khong co audit trail.
- **Khuyen nghi:** ghi log co cau truc (ai, khi nao, IP, ket qua) va canh bao khi co bat thuong.

### 3.10 [THAP] JWT chi duoc ky, khong duoc ma hoa

- **Mo ta:** payload chi chua `sub` (email), `iss`, `iat`, `exp`, `authorities` - khong co du lieu nhay cam.
- **Luu y:** khong duoc dat thong tin nhay cam vao claim trong tuong lai, vi bat ky ai co token deu doc duoc payload.

### 3.11 [DA SUA - muc TRUNG BINH] Loi giao thuc HTTP bi doi thanh 500

- **Van de (reviewer phat hien, muc MEDIUM):** `GlobalExceptionHandler` co `@ExceptionHandler(Exception.class)`
  bat tat ca, nen cac loi phia client bi tra sai ma:
  `PUT /auth/login` -> 500 (dung ra 405), body JSON hong hoac thieu body -> 500 (dung ra 400),
  `Content-Type: text/plain` -> 500 (dung ra 415), duong dan khong ton tai -> 500 (dung ra 404).
  Tat ca con bi ghi log o muc ERROR kem stack trace, tao them kha nang lam ngap log tu endpoint cong khai.
- **Da sua:** them `@ExceptionHandler` rieng cho `NoResourceFoundException`/`NoHandlerFoundException` (404),
  `HttpRequestMethodNotSupportedException` (405), `HttpMediaTypeNotSupportedException` (415),
  `HttpMessageNotReadableException`/`MethodArgumentTypeMismatchException`/`MissingServletRequestParameterException` (400).
  Cac loi nay chi ghi log muc WARN, khong in stack trace.
- **Bang chung:** 5 test trong `JwtNimbusIntegrationTest` (`unknownPathIsNotFound`, `wrongHttpMethodIsMethodNotAllowed`,
  `unsupportedMediaTypeIsRejected`, `malformedJsonBodyIsBadRequest`, `missingBodyIsBadRequest`); kiem tra e2e muc 9.

### 3.12 [DA SUA - muc THAP] Claim `iss` duoc ghi nhung khong duoc kiem tra

- **Van de (reviewer phat hien, muc LOW):** token co `iss` nhung `DefaultJWTClaimsVerifier` chi duoc cau hinh
  `requiredClaims = {"exp"}`, nen token thieu `iss` hoac mang `iss` khac van duoc chap nhan.
- **Da sua:** khi `security.jwt.issuer` duoc cau hinh, issuer duoc dua vao `exactMatchClaims` cua
  `DefaultJWTClaimsVerifier`, buoc token phai co `iss` dung chinh xac.
- **Bang chung:** `JwtTokenServiceTest.tokenWithWrongIssuerIsRejected`, `.tokenWithoutIssuerIsRejected`;
  `JwtNimbusIntegrationTest.tokenWithWrongIssuerIsUnauthorized`; kiem tra e2e muc 8 (`token sai issuer -> 401`).

### 3.13 [GIU NGUYEN - muc THAP] `GET /users` tra ve moi tai khoan cho bat ky nguoi dung nao

- **Mo ta (reviewer ghi nhan, muc LOW):** bat ky nguoi dung tu dang ky nao cung goi duoc `GET /users` va
  nhan ve `id`, `fullName`, `email`, `role` cua tat ca nguoi dung (khong co phan trang, khong gioi han quyen).
- **Quyet dinh:** **giu nguyen** vi day chinh la hanh vi cua bai giang (slide 27 va buoc test bang Postman).
  DTO `UserResponse` da loai bo `password` nen khong ro ri thong tin xac thuc.
- **Khuyen nghi neu lam that:** doi `@PreAuthorize("hasRole('ADMIN')")` hoac gioi han quyen tuong tu.


---

## 4. Vi sao tat CSRF la chap nhan duoc (co dieu kien)

CSRF khai thac **ambient authority**: trinh duyet tu dong gui cookie/session cua nan nhan.
Project nay:

- khong dung cookie phien, khong dung form login cua Spring Security;
- moi request duoc bao ve phai kem header `Authorization: Bearer <token>` do JavaScript cua chinh trang doc tu `localStorage`.

Trinh duyet khong tu dong gan header nay vao request cua trang khac, nen khong co ambience de khai thac.

**Dieu kien:** neu sau nay chuyen sang xac thuc bang cookie (ke ca cookie chua JWT), **bat buoc phai bat lai CSRF**
(`.csrf(csrf -> csrf.enable())` kem `CookieCsrfTokenRepository` va `XSRF-TOKEN` cho AJAX).

---

## 5. Phu thuoc (dependency)

| Dependency | Phien ban | Ghi chu |
|---|---|---|
| `com.nimbusds:nimbus-jose-jwt` | 10.10 | Da xac nhan bang `mvn dependency:tree -Dincludes=com.nimbusds` |
| Spring Boot | 3.5.16 | Quan ly phien ban qua BOM cua Boot |
| H2 | theo BOM Boot | runtime, chi dev |

- Voi HS256, Nimbus **khong** can BouncyCastle hay thu vien ma hoa ben thu ba (da kiem chung bang cach chay
  chuong trinh voi classpath chi gom 1 jar Nimbus).
- **Canh bao:** `spring-security-oauth2-jose` (6.4.2/6.5.0) keo theo `nimbus-jose-jwt:9.37.3`, phien ban nay
  **khong co** `com.nimbusds.jwt.proc.ExpiredJWTException`. Project nay khong dung starter do, nen khong bi ghi de.
  Neu them `spring-boot-starter-oauth2-resource-server` sau nay, phai ghim nimbus 10.10 trong `<dependencyManagement>`
  hoac doi nhanh `catch (ExpiredJWTException)` thanh `catch (BadJWTException)`.
- **Chua chay** cong cu SCA (OWASP dependency-check, OSV-Scanner, `mvn versions:display-dependency-updates`) => **NOT VERIFIED**.

---

## 6. Nhung gi CHUA duoc kiem chung

- Chua chay quet XSS/CSRF tu dong (ZAP, Burp).
- Chua chay SCA / liet ke CVE cho dependency.
- Chua kiem thu tai khoan bi khoa (nhanh 403) vi entity chua ho tro.
- Chua kiem thu voi MySQL that (chi H2 in-memory).
- Chua do hieu nang / tai dong thoi.
- Chua danh gia cau hinh TLS vi project chay HTTP o localhost.

---

## 7. Trang thai xac minh

### 7.1 Tu ra soat (self-review) - do tac gia thuc hien

| Noi dung | Lenh / cach lam | Ket qua |
|---|---|---|
| Build + test tai thu muc da giao | `mvn clean test` trong `Lap-trinh-Web/Bai04-JWT-Nimbus`, dung `~/.m2` mac dinh | `Tests run: 37, Failures: 0, Errors: 0` - BUILD SUCCESS |
| Chay server | `mvn spring-boot:run` (profile mac dinh, H2) | Len trong ~9s, `GET /login` = 200 |
| Kiem tra chuc nang + bao mat | 44 phep kiem tra HTTP | 44/44 PASS |
| Giao dien that | Trinh duyet: dang ky -> dang nhap -> trang ca nhan -> logout -> token gia mao bi tu choi | PASS, console 0 loi / 0 warning |
| Profile `mysql` | Server MySQL-protocol (MariaDB 11.4.5) + 13 phep kiem tra + doc bang truc tiep | 13/13 PASS |
| Ben vung du lieu | Restart server MySQL, dang nhap lai bang tai khoan cu | PASS - du lieu con nguyen |
| Ben vung khoa JWT | Restart voi profile `mysql`, dung **lai token cu** (khong doi) | PASS - 200, file `.jwt-secret-key` khong doi |
| Chong gia mao bang khoa cu | Ky token bang khoa mac dinh cu cua bai giang roi goi API | PASS - 401 |
| Doi chieu API Nimbus | `javap` tren jar that + chuong trinh probe chay that (11 tinh huong) | Khop voi `docs/NIMBUS-VS-JJWT.md` |
| Dependency day du | `mvn dependency:resolve` vao mot local repo HOAN TOAN MOI | 173 jar duoc tai ve, BUILD SUCCESS |

### 7.2 Kiem chung doc lap (independent verification)

Mot subagent **verifier** rieng biet da:

- copy project sang mot thu muc rieng (khong build tai cho), ghi lai hash cua `src` + `pom.xml`;
- chay lai `mvn clean test` tu ban sao cua no: `Tests run: 28, Failures: 0, Errors: 0` - BUILD SUCCESS;
- dong goi jar va chay tren **cong 8015** (khac cong cua tac gia);
- **tu viet** kich ban kiem tra rieng (khong dung lai script cua tac gia) va **tu viet** chuong trinh
  ky token het han bang Nimbus: **32/32 phep kiem tra PASS**, gom ca viec chung minh token het han
  van `verify() = true` nhung ung dung tra 401 `The JWT token has expired`.

**Gioi han da neu ro:** khong dat duoc cach ly bubblewrap (lop rieng). Kernel khong cho tao user namespace
khong dac quyen:
`bwrap: No permissions to create new namespace, likely because the kernel does not allow non-privileged user namespaces`.
Vi vay kiem chung doc lap chay tren **ban sao dung mot lan**, khong phai profile cach ly rieng.
Khong duoc goi day la "kiem chung trong sandbox".

### 7.3 Nhung gi CHUA kiem chung o muc nay

- Chua chay tren **MySQL 8 that cua may** (server dang chay o `127.0.0.1:3306` nhung khong dang nhap duoc
  bang tai khoan `thien`/`root` hien co). Da kiem chung bang server MySQL-protocol khac (MariaDB 11.4.5)
  voi day du luong chuc nang va tinh ben vung cua du lieu.
- Chua chay scanner SCA/XSS/CSRF tu dong.

## 8. Ket qua danh gia doc lap (subagent reviewer)

Mot subagent **reviewer** rieng biet da doc toan bo source, chay thu tren mot instance rieng
(cong 8025), va bao cao. Ket qua:

### 8.1 Phan reviewer xac nhan LA DUNG (khong co loi)

- Chu ky duoc xac thuc **truoc khi** doc bat ky claim nao.
- `alg=none`, token bi cat chu ky, token sai thuat toan, token het han, token thieu `exp` -> deu 401.
- Quyen (`authorities`) duoc lay tu **database**, khong lay tu claim trong token: reviewer da ky mot
  token hop le mang `authorities: ["ROLE_ADMIN"]` va API van tra ve `role: USER`.
- `/user/**` khong khop `/users/**` (khong co token -> 401, co token -> 200).
- Filter khong bi dang ky hai lan (log khoi dong co dong `Filter jwtAuthenticationFilterRegistration was not registered (disabled)`).
- Khong co `SecurityContext` bi ro ri giua cac request (STATELESS + `SecurityContextHolderFilter`).
- Password/hash khong xuat hien trong response hay log; khong co secret trong log.
- Khong co sink XSS trong `mainjs.js` (dung `textContent`, khong co `innerHTML`/`eval`).
- Khong co be mat SQL injection (chi dung derived query cua Spring Data JPA).
- CORS dung: origin duoc phep -> 200, `evil.example` -> 403 `Invalid CORS request`.
- Thread-safety: `MACSigner`/`MACVerifier` duoc tao moi cho moi lan dung; `DefaultJWTClaimsVerifier` chi doc.

### 8.2 Cac finding VA cach da xu ly

| # | Muc do | Finding | Xu ly |
|---|--------|---------|-------|
| F1 | HIGH | Khoa ky mac dinh nam trong `application.properties`; reviewer **ky duoc token gia mao** va goi API thanh cong voi quyen cua nan nhan | **Da sua**: bo hoan toan khoa mac dinh, tu sinh khoa ngau nhien 256 bit va luu `.jwt-secret-key` (quyen 600, gitignore) hoac dung `JWT_SECRET_KEY`. Xem muc 3.3 |
| F2 | MEDIUM | H2 console bat mac dinh va `permitAll`; reviewer dang nhap an danh va doc duoc **hash BCrypt** cua bang `users` | **Da sua**: mac dinh `spring.h2.console.enabled=false`, phai tu bat. Xem muc 3.6 |
| F3 | MEDIUM | `@ExceptionHandler(Exception.class)` bien 404/405/415/400 thanh 500, kem log ERROR co stack trace | **Da sua**: them handler rieng cho tung nhom loi, chi log WARN. Xem muc 3.11 |
| F4 | LOW | `GET /users` tra ve moi tai khoan cho bat ky nguoi dung nao | **Giu nguyen** (dung hanh vi bai giang), da ghi chu. Xem muc 3.13 |
| F5 | LOW | README ghi `DB_URL`/`DB_USERNAME`/`DB_PASSWORD` nhung `application-mysql.properties` doc `APP_DB_*` | **Da sua** truoc khi reviewer bao cao (README da doi sang `APP_DB_*` cho trung voi cac du an khac trong `Lap-trinh-Web`) |
| F6 | LOW | `iss` duoc ghi vao token nhung khong duoc kiem tra | **Da sua**: dua issuer vao `exactMatchClaims`. Xem muc 3.12 |
| F7 | LOW | Javadoc ghi "mac dinh Nimbus" cho do lech gio 60 giay gay hieu nham la project co cau hinh | **Da sua** comment: neu ro project khong doi gia tri nay va token thuc te con dung duoc them 60 giay sau `exp` |

### 8.3 Ghi chu ve phuong phap

- Reviewer chay tren instance **khong duoc cach ly** (bubblewrap khong tao duoc namespace tren may nay),
  da neu ro trong bao cao: `ENVIRONMENT — NOT AN IMPLEMENTATION FAILURE`.
- Reviewer dung jar co san (khong build lai) va khong chay profile `mysql` voi server that.
- Sau khi sua xong, bo test da tang tu **28 len 37** test va bo kiem tra e2e tu **36 len 44** phep kiem tra,
  trong do co test hoi quy truc tiep cho F1, F2, F3, F6.

---

## 9. Vong kiem chung thu hai (sau khi sua)

Mot subagent **verifier** thu hai da kiem chung doc lap **ban da sua**, tren mot ban sao rieng
(cong 8035), voi hash cua `src`/`pom.xml` duoc ghim truoc va kiem tra lai sau khi xong.

### 9.1 Ket qua: PASS 6/6

| # | Noi dung kiem chung | Ket qua | Bang chung chinh |
|---|---|---|---|
| 1 | Khong con khoa mac dinh; tu sinh + luu khoa; khoa cu bi tu choi; token song qua restart | PASS | Token ky bang khoa cu -> 401 ca hai cach dien giai (UTF-8 va hex); token ky bang khoa doc tu file -> 200 (doi chung); sau restart, token **truoc** restart van 200, hash file khoa khong doi; quyen file `600` |
| 2 | H2 console khong truy cap an danh | PASS | `GET /h2-console`, `/h2-console/`, `/h2-console/login.jsp` -> deu 401 |
| 3 | Loi giao thuc HTTP tra dung ma | PASS | 404 (co token), 405, 415, 400, 400 - khong con 500 |
| 4 | `iss` duoc kiem tra | PASS | Token dung khoa nhung `iss=evil-issuer` -> 401; thieu `iss` -> 401; doi chung `iss` dung -> 200 |
| 5 | Khong hoi quy hanh vi JWT loi | PASS | signup 200 khong lo password/hash; trung email 409; sai mat khau 401; khong token 401; token bi sua 401 dung thong bao; token het han 401 dung thong bao; `alg=none` 401 |
| 6 | Bo test chay tu ban sao cua verifier | PASS | `Tests run: 37, Failures: 0, Errors: 0` - BUILD SUCCESS |

Khong phat hien hoi quy. Verifier cung neu ro: bubblewrap khong dung duoc nen **khong co cach ly sandbox**.

### 9.2 Diem ve sinh do verifier phat hien va da sua

Verifier luu y: `mvn test` de lai file `.jwt-secret-key` trong thu muc du an (do test
`missingSecretIsGeneratedInsteadOfUsingADefault` dung vi tri file mac dinh).

**Da sua:** them property `security.jwt.secret-file` (mac dinh `.jwt-secret-key`) de co the doi vi tri;
test do nay dung `@TempDir` cua JUnit 5 nen **khong con ghi file vao thu muc du an**
(da kiem chung lai: `mvn test` xong khong con file `.jwt-secret-key` trong thu muc du an, 37/37 test van PASS,
va 44/44 phep kiem tra e2e van PASS).

### 9.3 Nhung gi verifier thu hai CHUA kiem chung

- CORS (origin mac dinh `http://localhost:8005` trong khi verifier chay cong 8035).
- Duong dan tu bat H2 console (`--spring.h2.console.enabled=true`).
- Nhanh khong ghi duoc file khoa (fallback dung khoa trong bo nho).
- Giao dien Thymeleaf / JavaScript (tac gia da kiem tra bang trinh duyet that, xem muc 7.1).
