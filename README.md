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

```java
.httpBasic().disable()
```
* UI쪽으로 들어오는 설정
* Http basic Auth 기반으로 로그인 인증창이 뜨는데, JWT를 사용할 거라 뜨지 않도록 설정   
  \+ `formLogin.disable()` : formLogin 대신 JWT를 사용하기 때문에 disable로 설정

```java
csrf.disable()
.cors().and()
```
* API를 작성하는데 프런트가 정해져있지 않기 때문에 csrf 설정 우선 꺼놓기
* **CSRF란?**
  * **Cross Site Request Forgery**  : 사이트 간 위조 요청
  * 웹 사이트 취약점 공격 방법 중 하나로, 사용자가 자신의 의지와는 무관하게 공격자가 의도한 행위를 특정 웹 사이트에 요청하게 하는 공격
  * Spring Security에서는 CSRF에 대한 예방 기능을 제공한다
  * **근데 이 좋은 기능을 왜 disable?**
    * 스프링 시큐리티 문서에서는 일반 사용자가 브라우저에서 처리할 수 있는 모든 요청에 CSRF 보호를 사용할 것을 권장하고,  
      브라우저를 사용하지 않는 클라이언트만 사용하는 서비스를 만드는 경우 CSRF 보호를 비활성화하는 것이 좋다고 함
    * 여기에서 브라우저를 사용하지 않는 클라이언트만 사용하는 서비스 → 대부분의 REST API 서비스라고 이해함  
      즉 대부분의 가이드는 REST API 서버 기준으로 disable을 적용하고 있다
* **CORS**
  * **Cross-Origin Resource Sharing** : 서로 다른 Orgin 간의 상호작용 시 브라우저에서 이를 중지하기 위해 제공하는 기본 보호 기능, 프로토콜
  * HTTP 요청은 기본적으로 Cross-Site HTTP Requests가 가능 (다른 도메인 사용 가능)   
    하지만 Cross-Site HTTP Requests는 Same Origin Policy를 적용받기 때문에,  
    프로토콜, 호스트명, 포트가 같아야만 요청이 가능하다
  * `cors()`로 cors에 대한 커스텀 설정 허용
    * `addAllowedOrigin()` : 허용할 URL 설정
    * `addAllowedHeader()` : 허용할 Header 설정
    * `addAllowedMethod()` : 허용할 Http Method 설정

```java
.authorizeRequests()
.requestMatchers("/api/**").permitAll()
.requestMatchers("/api/**/users/join", "/api/**/users/login").permitAll()
```
* 특정한 경로에 특정한 권한을 가진 사용자만 접근할 수 있도록 하는 설정
* `authorizeRequests()` : 시큐리티 처리에 HttpServletRequest를 이용한다는 것
* `requestMatchers()` : 특정한 경로 지정
  * 만약 spring-security 5.8 이상의 버전을 사용하는 경우에는 `antMatchers`, `mvcMatchers`, `regexMatchers`가 더 이상 사용되지 않기 때문에,   
    `requestMatchers`를 사용해야 한다고 함
* `permitAll()` :  모든 사용자가 인증절차 없이 접근할 수 있음
* `hasRole()` : 시스템 상에서 특정 권한을 가진 사람만이 접근할 수 있음
* `anyRequest().authenticated()` : 나머지 모든 리소스들은 무조건 인증을 완료해야 접근이 가능하다는 의미

```java
.sessionManagement()
.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
```
* 스프링 시큐리티는 기본적으로 session을 사용해 웹을 처리하는데,  
  JWT를 사용하기 때문에 session을 stateless로 설정, 세션 사용하지 않음

### 2.2. `BCryptPasswordEncode` 설정
* Spring Seurity 프레임워크에서 제공하는 클래스 중 하나로 비밀번호를 암호화하는 데 사용할 수 있는 메서드를 가진 클래스  
#### 🔒 **`encode()`**
* 패스워드를 암호화해주는 메서드, `String` 반환  
* 똑같은 비밀번호를 인코딩하더라도 매번 다른 문자열을 반환한다 
#### 🗝️ **`matches()`** 
* 제출된 인코딩 되지 않은 패스워드(일치 여부를 확인하고자 하는 패스워드)와 인코딩 된 패스워드의 일치 여부 확인
* 첫 번째 파라미터로 일치 여부를 확인하고자 하는 인코딩 되지 않은 패스워드, 두 번째 파라미터로 인코딩된 패스워드 입력
* `boolean` 반환 


## 🪪 회원가입 
>1. `POST` `/api/v1/users/join` 만들기   
>   - RequestBody - userName, password
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
#### 의존성 추가 
```java
implementation 'org.springframework.boot:spring-boot-starter-security'
```
#### SecurityConfig에 설정 추가 
* 웹 설정을 extends 하던 방법이 있었는데, 스프링 부트 버전이 올라가면서  
  `@Bean`으로 `SpringFilterChain`을 재정의해서 이용하는 방법으로 바뀜  


* 시큐리티 적용 후 잘 되던 회원가입에 DENY가 뜬다 

![시큐리티 적용 DENY 포스트맨](https://github.com/yoonsseo/spring-security/assets/90557277/e2a18970-fc4a-495b-b123-7647b31ae6aa)

#### `BCryptPasswordEncoder` 이용해 비밀번호 암호화해서 저장하기 
```java
//User Service
private final BCryptPasswordEncoder bCryptPasswordEncoder;
...
        
    //.password(joinRequestDto.getPassword())
    .password(bCryptPasswordEncoder.encode(joinRequestDto.getPassword()))
```
|적용 전|BCryptPasswordEncoder 적용 후|
|---|---|
|![인코딩 없이 저장된 비밀번호 DB](https://github.com/yoonsseo/spring-security/assets/90557277/b86eaf45-3d11-485d-a1f7-78a31be68674)|![인코딩 후 저장된 비밀번호 DB](https://github.com/yoonsseo/spring-security/assets/90557277/a6f62ddd-1955-4b7f-9a5a-d9521a230d6d)
|
* 순환 참조 문제가 생길 수 있기 때문에 `SecurityConfig`와 `BCryptPasswordEncoder`는 꼭 다른 클래스에 선언해주어야 한다고 한다 
