# 📌 spring-security
## 1. 인증과 인가
### 🔐 인증 Authentication
**증명하다**라는 의미로, 예를 들어 아이디와 비밀번호를 이용하여 로그인 하는 과정
### ✅ 인가 Authorization
**권한부여**나 **허가**와 같은 의미로 사용되고, 어떤 대상이 특정 목적을 실현하도록 허용(Access) 하는 것 의미  

> Web에서의 인증은 해당 URL은 보안 절차를 거친 사용자들만 접근할 수 있다는 의미이고,  
> 인가란 URL에 접근한 사용자가 특정한 자격이 있다는 것 의미

## 2. 스프링 시큐리티 설정
### 2.1. `SecurityFilterChain` 설정 
> **변경**  
> 스프링 부트 3.0 이상부터 스프링 시큐리티 6.0.0 이상의 버전이 적용되며  
> Deprecated된 코드 변경 

```java
//.httpBasic().disable()
.httpBasic(HttpBasicConfigurer::disable)
```
* UI쪽으로 들어오는 설정
* Http basic Auth 기반으로 로그인 인증창이 뜨는데, JWT를 사용할 거라 뜨지 않도록 설정   
  \+ `formLogin.disable()` : formLogin 대신 JWT를 사용하기 때문에 disable로 설정

```java
//.csrf.disable()
//.cors().and()
.csrf(AbstractHttpConfigurer::disable)
.cors(Customizer.withDefaults())
```
* API를 작성하는데 프런트가 정해져있지 않기 때문에 csrf 설정 우선 꺼놓기
#### CSRF 
  * **Cross Site Request Forgery**  : 사이트 간 위조 요청
  * 웹 사이트 취약점 공격 방법 중 하나로, 사용자가 자신의 의지와는 무관하게 공격자가 의도한 행위를 특정 웹 사이트에 요청하게 하는 공격
  * Spring Security에서는 CSRF에 대한 예방 기능을 제공한다
  * **근데 이 좋은 기능을 왜 disable?**
    * 스프링 시큐리티 문서에서는 일반 사용자가 브라우저에서 처리할 수 있는 모든 요청에 CSRF 보호를 사용할 것을 권장하고,  
      브라우저를 사용하지 않는 클라이언트만 사용하는 서비스를 만드는 경우 CSRF 보호를 비활성화하는 것이 좋다고 함
    * 여기에서 브라우저를 사용하지 않는 클라이언트만 사용하는 서비스 → 대부분의 REST API 서비스라고 이해함  
      즉 대부분의 가이드는 REST API 서버 기준으로 disable을 적용하고 있다
#### CORS
  * **Cross-Origin Resource Sharing** : 서로 다른 Orgin 간의 상호작용 시 브라우저에서 이를 중지하기 위해 제공하는 기본 보호 기능, 프로토콜
  * HTTP 요청은 기본적으로 Cross-Site HTTP Requests가 가능 (다른 도메인 사용 가능)   
    하지만 Cross-Site HTTP Requests는 Same Origin Policy를 적용받기 때문에,  
    프로토콜, 호스트명, 포트가 같아야만 요청이 가능하다
  * `cors()`로 cors에 대한 커스텀 설정 허용
    * `addAllowedOrigin()` : 허용할 URL 설정
    * `addAllowedHeader()` : 허용할 Header 설정
    * `addAllowedMethod()` : 허용할 Http Method 설정

```java
//.authorizeRequests()
//.requestMatchers("/api/**").permitAll()
//.requestMatchers("/api/**/users/join", "/api/**/users/login").permitAll()
.authorizeHttpRequests(authorize -> authorize
    .requestMatchers("/api/**").permitAll()
    .requestMatchers("/api/v1/users/join", "/api/v1/users/login").permitAll())
```
* 특정한 경로에 특정한 권한을 가진 사용자만 접근할 수 있도록 하는 설정
* `authorizeRequests()` : 시큐리티 처리에 HttpServletRequest를 이용한다는 것, 각 경로별 권한 처리 
* `requestMatchers()` : 특정한 경로 지정
  * 만약 spring-security 5.8 이상의 버전을 사용하는 경우에는  
    `antMatchers`, `mvcMatchers`, `regexMatchers`가 더 이상 사용되지 않기 때문에,   
    `requestMatchers`를 사용해야 한다고 함
* `permitAll()` :  모든 사용자가 인증절차 없이 접근할 수 있음
* `hasRole()` : 시스템 상에서 특정 권한을 가진 사람만이 접근할 수 있음
* `anyRequest().authenticated()` : 나머지 모든 리소스들은 무조건 인증을 완료해야 접근이 가능하다는 의미

```java
//.sessionManagement()
//.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
.sessionManagement((sessionManagement) -> sessionManagement
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
```
* 스프링 시큐리티는 기본적으로 session을 사용해 웹을 처리하는데,  
  JWT를 사용하기 때문에 session을 stateless로 설정, 세션 사용하지 않음

### 2.2. `BCryptPasswordEncode` 설정
#### 🪢 **`BCryptPasswordEncode`**
* Spring Seurity 프레임워크에서 제공하는 클래스 중 하나로 비밀번호를 암호화하는 데 사용할 수 있는 메서드를 가진 클래스  
#### 🔒 **`BCryptPasswordEncoder.encode(CharSequence rawPassword)`**
* 패스워드를 암호화해주는 메서드, `String` 반환  
* 똑같은 비밀번호를 인코딩하더라도 매번 다른 문자열을 반환한다 
#### 🗝️ **`matches(CharSequence rawPassword, String encodedPassword)`** 
* 제출된 인코딩 되지 않은 패스워드(일치 여부를 확인하고자 하는 패스워드)와 인코딩 된 패스워드의 일치 여부 확인
* 첫 번째 파라미터로 일치 여부를 확인하고자 하는 인코딩 되지 않은 패스워드,  
두 번째 파라미터로 인코딩된 패스워드 입력
* `boolean` 반환 
 
## 🚨 Spring Security 테스트 하기
### 1. 의존성 추가 🐘
```java
testImplementation 'org.springframework.security:spring-security-test'
```
### 2. 인증 정보 미리 주입하기 💉
#### 2.1. SecurityContext에 직접 Authentication 주입
#### 2.2. @WithMockUser
* 테스트에 필요한 **인증된 인증 정보**를 제공하며 간단한 정보를 기본으로 설정할 수 있게 도와준다
* 미리 인증된 사용자를 만들어놓지 않아도 간단하게 인증이 필요한 메소드를 테스트할 수 있다
* `userName`, `password`, `role` 등을 어노테이션 value를 통해 설정해줄 수 있고,  
  default value로 `username = "user"`, `password = "password"`, `role = "USER"`가 설정되어 있다
* 테스트 시 필요한 정보가 인증여부 정도거나, 사용자 이름 등과 같이 간단한 것이라면  
  `@WithMockUser`를 통해 간단히 테스트 가능
#### 2.3. @WithAnonymousUser
* 테스트 진행 시 `@WithMockUser`를 통해 **인증된 사용자 정보**를 간단히 주입해주었다면,  
  반대로 `@WithAnonymousUser`는 **인증되지 않은 사용자**에 대한 테스트 시 이용

### 3. csrf 설정해주기
```java
mockMvc.perform(post("/api/v1/users/login")
        .with(csrf())
        .contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsBytes(new LoginRequestDto(userName, password))))
    .andDo(print())
    .andExpect(status().isUnauthorized());
```
* 테스트로 호출하면 스프링 시큐리티가 csrf라고 판단하기 때문에 `.with(csrf())` 꼭 처리 해주어야 한다
* `MockMvc`에서 `request`에 자동으로 valid한 `CsrfToken` 제공 
#### csrf 처리 전
![csrf 처리 전](https://github.com/yoonsseo/spring-security/assets/90557277/c8a16d1a-21c2-4cd1-9b7c-4402e3f82e6f)
#### csrf 처리 후
![csrf 처리 후](https://github.com/yoonsseo/spring-security/assets/90557277/1d8beb47-0487-4ac3-a63c-1fedc3dc17e1)

## 4. JWT - JWT TOKEN 발행
### 🛡️ JWT : Json Web Token
* 서로 다른 기기에 데이터를 전달할 때 사용하는 방법 중 하나로, `Base64`의 형태를 가진다 
* `Header`와 `Body(또는 Payload)`, 그리고 `Signature` 세 부분으로 나눠진다  
#### 📑 Header
* JWT의 metadata들을 나타낸다  
* Sign에 사용된 Algorithms, format, 그리고 ContentType 등의 정보
#### 📄 Payload (Body)
* `Claim` 단위로 저장
* **Claim**
  * 사용자의 속성이나 권한, 정보의 한 조각 또는 Json의 필드라고 생각하면 된다 
  * `Claim`에는 JWT 생성자가 원하는 정보들을 자유롭게 담을 수 있는데  
    Json 형식을 가지고 있기 때문에 단일 필드도 가능하고,  
    Object와 같은 complexible한 필드도 추가할 수 있다
#### 📝 Signature
* Header와 Body는 Base64 형태로 인코딩되어 암호화되어 있지 않은데  
  공격자가 내용을 바꿀 수가 있다
* Signature로 서명을 통해 암호화 과정을 거친다
* 서명 이후 Header와 Body의 내용이 바뀐다면 Signature의 결과값이 바뀌어 받아들여지지 않는다

### 4.1. 의존성 추가 🐘
```java
implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
```
* JWT 라이브러리의 핵심 API를 제공하고 JWT의 생성 및 검증을 다룰 수 있다
```java
runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
```
* `jjwt-impl` 의존성을 추가하지 않은 채 `Jwts.builder()` 를 호출하게 되면 오류가 발생한다

```java
runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
```
* `jjwt-impl`의 구현체 라이브러리로, `jjwt-jackson` 외에도 `jjwt-gson`이 있다  
* `jjwt-jackson` 의존성을 추가하지 않으면 `compact` 메서드를 처리하던 도중 오류가 발생한다  
  → `jjwt-impl`에서 구현체를 찾아보지만 없기에 오류가 발생 

#### 의존성을 세 개나 추가해야 하는 이유는?
> `jjwt-api` 는 패키지 관리에 있어서 `implemenation` 과 `runtimeonly` 로 구분하여 의존성 추가를 권장하고 있다  
> 경고 없이 언제든 변할 수 있는 패키지는 `runtimeonly`로 관리하고 그렇지 않은 것은 `implemenation`으로 관리해  
> 안정적으로 `jjwt-api` 라이브러리를 사용하겠다는 의도
> 즉, `jjwt-impl`, `jjwt-jackson` 또는 `jjwt-gson` 은 경고없이 언제든 변화할 수 있고  
> `jjwt-api`는 하위호환성을 맞춰가며 개발한다는 의미  
> 실제로 코드를 보면서 하위호환성에 대한 언급과 `@Deprecated`를 통해 코드를 유지하려는 노력을 살펴볼 수 있다

### 4.2. JWT 생성 시 필요한 정보
#### Jwts 클래스
* JWT 인스턴스를 생성하는 역할을 하는 팩토리 클래스 

#### 4.2.1. `Jwts.builder()`
```java
public static String createToken(String userName, Key key, long expireTimeMs) {
    Claims claims = Jwts.claims(); //일종의 Map
    claims.put("userName", userName);

    return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + expireTimeMs))
            .signWith(key, SignatureAlgorithm.HS256)
            .compact();
}
```
0. Header 설정
   * `.setHeaderParam("key", "value")` 또는 `.setHeader(header)`와 같은 방식 사용 가능 

##### Body(Payload) 설정 
1. `setClaims()` : JWT에 포함시킬 Custom Claims 추가 - 주로 인증된 사용자 정보
    * `.claim("key", "value")` 또는 `.setClaims(claims)`와 같은 방식 사용 가능
   
2. `setSubject()` : JWT에 대한 제목 
   

3. `setIssuedAt()` : JWT 발행 일자 - 파라미터 타입은 `java.util.Date`
    

4. `setExpiration()` : JWT의 만료기한 - 파라미터 타입은 `java.util.Date`  


5. `signWith()` : 서명을 위한 `Key(java.security.Key)` 객체 설정
    ```java
    //.signWith(SignatureAlgorithm.HS256, key)
    .signWith(key, SignatureAlgorithm.HS256)
    ```
    ##### `signWith(io.jsonwebtoken.SignatureAlgorithm, java.lang.String)' is deprecated`  
   * 특정 문자열(String)이나 byte를 인수로 받는 메서드로 사용이 중단되었는데,  
     많은 사용자가 안전하지 않은 원시적인 암호 문자열을 키 인수로 사용하려고 시도하며 혼란스러워했기 때문이라고 한다 
    #### `signWith(java.security.Key key, io.jsonwebtoken.SignatureAlgorithm alg)`
   * `String`이 아니라 `Key` 값을 생성하고 서명을 진행해야 한다 
     ```java
     Key = Keys.hmacShaKeyFor(secretKey.toByteArray(StandardCharsets.UTF_8))
     ``` 
   * `io.jsonwebtoken.security.WeakKeyException`
       * `String`을 `Utf8`로 인코딩후 `Byte`로 형변환 할 때 `Exception`이 터질 수도 있다
       * **`256bit`보다 커야** 한다는 `Exception` - 알파벳 한 글자당 `8bit`이므로 **32글자 이상**이어야 한다는 뜻
       * 한글은 한 글자 당 `16bit`인데 16글자이면 생성될까? → 생성된다


6. `compact()` : JWT 생성하고 직렬화 

```java
//.signWith(SignatureAlgorithm.HS256, key)
.signWith(key, SignatureAlgorithm.HS256)
```
#### `signWith(io.jsonwebtoken.SignatureAlgorithm, java.lang.String)' is deprecated`  
* 특정 문자열(String)이나 byte를 인수로 받는 메서드로 사용이 중단되었는데,  
  많은 사용자가 안전하지 않은 원시적인 암호 문자열을 키 인수로 사용하려고 시도하며 혼란스러워했기 때문이라고 한다 
#### `signWith(java.security.Key key, io.jsonwebtoken.SignatureAlgorithm alg)`
* `String`이 아니라 `Key` 값을 생성하고 서명을 진행해야 한다 
  ```java
  Key = Keys.hmacShaKeyFor(secretKey.toByteArray(StandardCharsets.UTF_8))
  ``` 
* `io.jsonwebtoken.security.WeakKeyException`
  * `String`을 `Utf8`로 인코딩후 `Byte`로 형변환 할 때 `Exception`이 터질 수도 있다
  * **`256bit`보다 커야** 한다는 `Exception` - 알파벳 한 글자당 `8bit`이므로 **32글자 이상**이어야 한다는 뜻  
  * 한글은 한 글자 당 `16bit`인데 16글자이면 생성될까? → 생성된다 



## 🪪 회원가입 
>1. `POST` `/api/v1/users/join` 만들기   
>    - RequestBody - userName, password
>2. 회원가입 성공/실패 Controller Test
>3. `UserService.join()` - 중복 체크해서 `ifPresent`면 `RuntimeException` 리턴
>    - `@RestControllerAdvice` 선언
>    - `@ExceptionHandler`로 `RuntimeException` 받기
>4. `CuntomException`으로 변경
>    - ErrorCode 선언
>    - 중복 check exception 수정
>5. Spring Security 적용해보기
>    - Spring Security 넣고 join(추후 login도) 허용해주는 세팅
>    - BCryptPasswordEncoder 추가
>    - Join할 때 password Encoding해서 저장하기  

### 1. `User`, `UserRepository`, `UserService`, `UserController`, `JoinRequestDto` 생성
- `User` - id, name, password
- `JoinRequestDto` - userName, password  
- `UserService` - 이름 중복 체크(`ifPresent`로 `RunTimeException`) 후 저장
  * `isPresent` → true, false 체크  
  * `ifPresent` → 값을 가지고 있는지 확인 후 예외처리
```java
public String join(JoinRequestDto joinRequestDto) {
    //중복체크
    userRepository.findByName(joinRequestDto.getUserName())
        .ifPresent(user -> {throw new AppException(ErrorCode.USERNAME_DUPLICATED, "이미 있는 회원");});

    //저장
    userRepository.save(User.builder()
            .name(joinRequestDto.getUserName())
            .password(joinRequestDto.getPassword())
            .build());
    
    return "회원가입 성공";
}
```


### 2. `UserController`에 대한 `@WebMvcTest`
```java
@WebMvcTest
class UserControllerTest {
    @Autowired MockMvc mockMvc;
    @MockBean UserService userService;
    @Autowired ObjectMapper objectMapper;
    //자바 오브젝트를 JSON으로 만들어주는 잭슨의 오브젝트

    @Test
    @DisplayName("회원가입 성공")
    void join() throws Exception{
        //given
        String userName = "yoonsseo";
        String password = "1234";

        //when, then
        mockMvc.perform(post("/api/v1/users/join")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsBytes(new JoinRequestDto(userName, password)))) 
										//HttpRequest에 어떤 값을 보낼 때는 byte로 보낸다
                .andDo(print())
                .andExpect(status().isOk());
    }
}
```

### 3. `@RestControllerAdvice`를 통해 `@ExceptionHandler`로 특정 exception 처리 

```java
@RestControllerAdvice
public class ExceptionManager {
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<?> runtimeExceptionHandler(RuntimeException e) { 
		//? -> 리스펀스엔티티 바디에 뭐든지 들어갈 수 있다
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(e.getMessage());
    }
}
```

### 4. Custom Exception
```java
@AllArgsConstructor
@Getter
public class AppException extends RuntimeException {
    private ErrorCode errorCode;
    private String message;
}
```
```java
@AllArgsConstructor
@Getter
public enum ErrorCode {
    USERNAME_DUPLICATED(HttpStatus.CONFLICT, "");

    private HttpStatus httpStatus;
    private String message;
}
```
```java
@RestControllerAdvice
public class ExceptionManager {
    @ExceptionHandler(AppException.class)
    public ResponseEntity<?> appExceptionHandler(AppException e) { 
        return ResponseEntity.status(e.getErrorCode().getHttpStatus())
                .body(e.getErrorCode() + " " + e.getMessage());
                //리스펀스오브젝트로 랩핑을 할 수도 있는데 일단 이렇게 처리
    }
}
```

#### 포스트맨  
![회원가입 포스트맨](https://github.com/yoonsseo/spring-security/assets/90557277/99eb10eb-96dd-4292-865e-bc6089a38432)

### 5. Spring Security 적용
#### 5.1. 의존성 추가 🐘
```java
implementation 'org.springframework.boot:spring-boot-starter-security'
```
#### 5.2. `SecurityConfig` 설정 추가 
* 웹 설정을 extends 하던 방법이 있었는데, 스프링 부트 버전이 올라가면서  
  `@Bean`으로 `SpringFilterChain`을 재정의해서 이용하는 방법으로 바뀜  


* 시큐리티 적용 후 잘 되던 회원가입에 DENY가 뜬다 

![시큐리티 적용 DENY 포스트맨](https://github.com/yoonsseo/spring-security/assets/90557277/e2a18970-fc4a-495b-b123-7647b31ae6aa)

#### 5.3. `BCryptPasswordEncoder` 이용해 비밀번호 암호화해서 저장하기 
```java
//User Service
private final BCryptPasswordEncoder bCryptPasswordEncoder;
...
        
    //.password(joinRequestDto.getPassword())
    .password(bCryptPasswordEncoder.encode(joinRequestDto.getPassword()))
```
|적용 전|BCryptPasswordEncoder 적용 후|
|---|---|
|![인코딩 없이 저장된 비밀번호 DB](https://github.com/yoonsseo/spring-security/assets/90557277/b86eaf45-3d11-485d-a1f7-78a31be68674)|![인코딩 후 저장된 비밀번호 DB](https://github.com/yoonsseo/spring-security/assets/90557277/a6f62ddd-1955-4b7f-9a5a-d9521a230d6d)|
* 순환 참조 문제가 생길 수 있기 때문에 `SecurityConfig`와 `BCryptPasswordEncoder`는 꼭 다른 클래스에 선언해주어야 한다고 한다 

## 🔐 로그인 
>1. 로그인 테스트
>    - `Spring Security Test` 라이브러리 사용
>    - `with(csrf())`로 호출 
>2. 로그인 Service 구현  
>    - `login(String userName, String password)`
>    - 아이디 확인 → 비밀번호 확인 → TOKEN 발행 
>3. 로그인 시 Token 발행하기
>    - `JWT` 라이브러리 사용
>    - `jwt.token.secret = "secretKey"`
>    - `JWT_TOKEN_SECRET = "real_secret_key"`

#### 로그인이란?
아이디와 패스워드를 입력하면 `토큰`을 발행 해주는 것

### 1. 로그인/회원가입 - 스프링 시큐리티 테스트
* `@WithMockUser`, `.with(csrf())` 적용 
```java
@Test
@DisplayName("로그인 실패 - 아이디(이름) 없음")
@WithMockUser
void login_fail1() throws Exception {
    //given
    String userName = "hello";
    String password = "1234";

    //when, then
    when(userService.login(userName, password))
            .thenThrow(new AppException(ErrorCode.USER_NOT_FOUND, ""));

    mockMvc.perform(post("/api/v1/users/login")
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsBytes(new LoginRequestDto(userName, password))))
            .andDo(print())
            .andExpect(status().isNotFound());
}
```

### 2. 로그인 Service 구현 : ID → PW (→ TOKEN 발행) 
#### 로그인 경우의 수 
1. 아이디와 패스워드 올바르게 입력 → `SUCCESS`
2. 아이디가 없는 경우 → `NOT_FOUND`
3. 비밀번호가 틀린 경우 → `UNAUTHORIZED`

### 3. 로그인 시 Token 발행하기
#### 3.1. 의존성 주입 🐘
```java
implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
```
#### 3.2. SecretKey 등록
* 왼쪽 상단의 `Run` → `Edit Configurations` 또는 오른쪽 상단에서 다음과 같이 `Edit Configurations`
![환경변수등록1](https://github.com/yoonsseo/spring-security/assets/90557277/dacea8e3-0068-4400-900b-732c0a847603)
* 왼쪽 메뉴에서 `Spring Boot Application`으로 잘 접속되었나 확인 후   
  → 오른쪽 메뉴에서 `Environment variables`란이 없는 경우 `Modify options` → `Environment variables` 선택해서 환경변수 칸 추가
  ![환경변수등록2](https://github.com/yoonsseo/spring-security/assets/90557277/fbda65bf-a610-4df7-a24e-8e8eae976527)
  ![환경변수등록3](https://github.com/yoonsseo/spring-security/assets/90557277/7aebe1bc-d7d8-4c89-897d-1acd76953663)
* 환경 변수 옵션 칸에서 키-값 쌍을 직접 입력해주거나 오른쪽 아이콘을 눌러서 등록
    ![환경변수등록4](https://github.com/yoonsseo/spring-security/assets/90557277/030acec2-c913-4b4c-baa1-40a258a05e07)

#### 3.3. `JwtTokenUtil` - `createToken` 작성
```java
public static String createToken(String userName, Key key, long expireTimeMs) {...}
```

#### 3.4. 'UserService' - `TOKEN` 발행 로직
* `yml`과 `환경변수`로 넣어준 `secretKey` 가져오기
```yaml
#application.yml
jwt:
  token:
    secret: "secretKey"
```
```java
//UserService
@Value("${jwt.token.secret}")
private String key;

//토큰 만료 시간 1초 * 60 * 60 = 1시간
private final static Long expireTimeMs = 1000 * 60 * 60L;
```

* 먼저, 사용하고자 하는 `plain secretKey`(암호화 되지 않음)를 `byte`배열로 변환해주고,  
  HMAC-SHA 알고리즘을 통해 암호화해주는 `Keys.hmacShaKeyFor`를 통해 암호화된 `Key` 객체로 만들어주기 
```java
String keyBase64Encoded = Base64.getEncoder().encodeToString(key.getBytes());
SecretKey key = Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());
```

* `createToken`으로 토큰 생성해서 반환
```java
String token = JwtTokenUtil.createToken(userName, key, expireTimeMs);
```

#### 포스트맨
![로그인토큰반환](https://github.com/yoonsseo/spring-security/assets/90557277/b92b8a59-c8e4-43ef-95a1-706dfabc8acf)
