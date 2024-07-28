
## 목차

1. 개요
    1. 총평
    2. 진단 결과 요약

2. 모의해킹 수행 내용
    1. 정보 수집
    2. 취약점 진단
    3. 취약점 공격과 호스트 초기 침투
    4. 권한 상승

3. 취약점 및 대응 방안
    1. 웹서비스 불필요한 파일 제거
    2. 불충분한 인증
    3. 웹서비스 디렉토리 리스팅 제거
    4. 약한 암호화 종류 사용
    5. 파일 업로드 허용
    6. root 계정 원격 접속 제한


## 개요

### 총평

| **분석 기간**                   | **호스트 이름** | **IP주소**  | **목적**            |
| --------------------------- | ---------- | --------- | ----------------- |
| 2024년 7월 27일 ~ 2024년 7월 28일 | Host3      | 10.0.4.30 | 보안 취약점 진단 및 침투테스트 |

본 보고서는 2024년 7월 27일부터 28일까지 진행된 Host3 호스트에 대한 모의해킹 작업을 요약한다. 이 과정에서 발견된 취약점과 그에 따른 침투 테스트 결과를 중점적으로 다룬다.

웹서버의 워드프레스 로그인 페이지에서 임의의 유저로 로그인 시도 시, 유저의 존재 유무를 알려주는 취약점이 발견되었다. 기본 관리자 계정인 `admin`과 임의의 비밀번호로 로그인을 시도할 경우, 해당 `admin` 유저가 존재함을 파악 할 수 있다. 나아가 공격자는 관리자의 비밀번호를 알아내기 위해 사전 파일을 만들어 무차별 대입 공격을 진행할 가능성이 높다.

웹서버의 루트 경로 전체가 디렉토리 리스팅을 허용하고 있음을 확인하였고, 공격자는 디렉토리 내의 파일 탐색 및 정보 수집이 가능하다. 
이 때, 백업(`_backup`) 디렉토리에 노출되고 있는 문서 파일을 발견할 수 있었다. 해당 파일은 약한 암호화 종류를 사용하여 암호화 되어있으므로, 공격자는 해당 암호의 평문을 어렵지 않게 추출 및 문서 열람이 가능하다. 공격자는 해당 문서 내의 계정 정보를 이용한하여 워드프레스 관리자 계정으로 접속까지 가능하다. 

워드프레스의 테마 파일업로드 기능에서 파일 확장자 검증이 미흡하므로, 임의의 악성 파일(리버스쉘)을 업로드 및 실행할 수 있는 취약점을 발견했다. 웹서버 계정으로 리버스쉘을 획득한 공격자는 내부 시스템에 접근 및 탐색을 진행할 수 있다. 실행 파일에 대한 sudo 권한이 웹서버의 유저에게 과도하게 부여되어 있는 상태이기 때문에, 이를 악용할 시, root 권한 상승 및 시스템을 장악할 위험이 존재한다.

인터넷에 노출되어 있는 호스트의 특성상 점검자는 취약점을 발견한 즉시 RedRaccoon사의 보안 담당자에게 연락해 취약점 정보를 제공했다.

### 진단 결과 요약

아래 표는 이번 모의해킹 과정에서 발견된 주요 취약점을 요약한 것이다. 각 취약점에 대한 자세한 설명 및 대응 방안은 본 보고서의 '취약점 및 대응 방안' 섹션에서 확인할 수 있다.

| 번호  | 이름                       | 중요도 | 설명                                                                           | 대응 방안                                                          |
| --- | ------------------------ | --- | ---------------------------------------------------------------------------- | -------------------------------------------------------------- |
| 1   | 웹서비스 불필요한 파일 제거          | 상   | Ubuntu Apache2 기본페이지 노출 설정으로 인해, 실제 경로 및 파악 및 접근 가능                          | 기본으로 생성되는 불필요한 파일 및 디렉토리 제거                                    |
| 2   | 불충분한 인증                  | 상   | 관리자 아이디를 대상으로 서버 내에 해당 유저 존재 유무 확인 가능 및 계정 정보 추측 가능                          | 임의의 유저 존재 여부를 확인하지 추측하지 못하도록, 서버측에서 아이디가 존재 여부와 상관없이 같은 응답을 출력 |
| 3   | 웹서비스 디렉토리 리스팅 제거<br><br> | 상   | 임의의 유저가 디렉토리 리스팅 하여 계정 정보와 관련된 중요 파일 확인 가능                                   | 디렉토리 리스팅 설정 해제, 및 관리자 유저 외에 접근하지 못하도록 권한 설정                    |
| 4   | 약한 암호화 종류 사용             | 상   | MS Office 2007 버전의 약한 암호화종류 사용으로 인해 평문 암호를 쉽게 추출 가능                          | MS 2014 이상의 버전으로 파일을 암호화 종류 사용 및 복잡한 비밀번호 사용, 또는 솔트값 적용<br>    |
| 5   | 파일 업로드 허용                | 상   | zip 파일 업로드 시, 파일 확장자 검증이 미흡하여, 악성 php파일 업로드 및 실행 가능                          | 화이트리스트 및 블랙리스트 필터링을 도입하여 특정 확장자 허용하도록 설정                       |
| 6   | root 계정 원격 접속 제한         | 상   | busybox 명령어에 대해 과도한 권한 설정으로 인해 낮은 권한의 유저가 root 계정 비밀번호 없이 명령어를 악용하여 권한 상승 가능 | 해당 바이너리 파일에 대한 sudo 권한 제거                                      |



## 모의해킹 수행 내용

### 정보 수집 - 포트스캐닝

대상 호스트의 아이피주소를 상대로 모든 TCP 포트들의 상태를 알아보기 위해 TCP SYN 스캔을 이용해 포트스캐닝을 진행했다.

```
# nmap -p- --max-retries 1 -sS -Pn -n -oA overallscan 10.0.4.30
Nmap scan report for 10.0.4.30

Host is up (0.00029s latency).
Not shown: 65533 closed tcp ports (reset)

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 0A:10:C8:01:2B:B1 (Unknown)

```


해당 열린 포트에서 어떤 종류의 네트워크 서비스들이 실행중인지 알아보기 위해 서비스 배너 그래빙과 Nmap 기본 스크립트를 이용해 더 자세한 정보 수집을 진행했다.

```
# nmap -p 22,80 -sV -sC -Pn -n -oA detailed 10.0.4.30

Nmap scan report for 10.0.4.30
Host is up (0.000091s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4d:37:99:12:86:a6:9a:63:ff:a3:a6:03:96:f7:58:b8 (ECDSA)
|_  256 72:bd:17:d8:a9:1e:6a:60:ed:67:be:35:2b:7d:18:45 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
MAC Address: 0A:10:C8:01:2B:B1 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

포트 스캔 결과, 리눅스 우분투환경에서 포트 22에서는 OpenSSH 8.9p1 가 실행중이며 기본적으로 버전 7.7 이상이기 때문에 유저 정보수집 취약점이 없을 것이라고 예측해 볼 수 있다. 포트 80에서는 아파치 웹서버가 실행중이며 우분투 기본페이지가 나오는 것을 예측해볼 수 있다.


### 정보 수집 - 웹

기초적인 웹 정보 수집을 위해 포트 80을 방문하니 Apache2 기본 페이지를 확인할 수 있다. 해당 파일을 랜딩페이지로 유지한다면 공격자는 설정 파일 및 웹루트 경로( `/var/www/html`) 등 실제 경로를 쉽게 추측할 수 있다. 서버의 버전 정보는 물론 관련 취약점까지 확인 후 2차 공격을 시도할 수 있다.
![[Pasted image 20240728075039.png]]


Nikto의 디렉토리 무작위 대입 스캔을 통해, /blog/ 디렉토리 및 wp-login.php 로그인 페이지가 있음을 확인한다. 워드프레스를 사용 중임을 알 수 있고 /wp-admin/, /wp-content/, wp-config.php 등의 경로도 역시 기본 워드프레스 경로로 잘 알려져있으므로 존재함을 추측할 수 있다.

```
nikto -host 10.0.4.30 | tee nikto.output

- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.0.4.30
+ Target Hostname:    10.0.4.30
+ Target Port:        80
+ Start Time:         2024-07-27 06:23:19 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.52 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.52 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Server may leak inodes via ETags, header found with file /, inode: 29af, size: 60ba068a537ea, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ OPTIONS: Allowed HTTP Methods: POST, OPTIONS, HEAD, GET .
+ /blog/wp-login.php: Cookie wordpress_test_cookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /blog/wp-login.php: Wordpress login found.
+ 8102 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2024-07-27 06:23:31 (GMT0) (12 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```



### 취약점 진단

워드프레스 로그인 페이지에서 기본 관리자 계정인 admin으로 임의의 비밀번호와 함께 로그인을 시도한다. 그 결과, 서버에서 해당 유저의 비밀번호가 틀렸다고 응답하기 때문에, admin 유저가 존재함을 알 수 있다.
![[Pasted image 20240728075623.png]]

`Gobuster` 툴을 통해 알아낸 `/blog/_backup/` 경로에 접속 시 디렉토리 리스팅이 가능하며, 중요 파일이 노출되어 있음을 확인한다.
![[Pasted image 20240728080319.png]]


해당 xlsx 확장자의 문서를 다운 후 공격자의 호스트에서 분석 시, CDFV2로 암호화가 되어있고 내용 확인이 불가능한 상태이다.
```
file corp-creds.xlsx
```


해당 암호화 종류에 해당하는 johntheripper 검색 결과를 확인한 결과, `office2john` 명령어로 해시를 추출 후, `johntheripper` 툴을 이용해 해시를 크래킹할 수 있으며 `<REDACTED>` 라는 비밀번호가 추출됨을 확인한다.
```
office2john ./corp-creds.xlsx > corp.hash

john --wordlist=/usr/share/wordlists/rockyou.txt corp.hash
```



비밀번호를 이용해 해당 문서를 열람했을 때, admin 사용자에 대한 평문 비밀번호를 확인할 수 있다. 워드프레스 로그인 시도 시, 정상적으로 관리자 로그인이 가능함을 확인한다.
![[Pasted image 20240728081440.png]]


### 취약점 공격과 호스트 초기 침투


파일 업로드 취약점과 관련하여 테마 또는 플러그인 추가하는 기능에서, zip 파일 대신 임의의 악성 php 파일 업로드를 시도했을 때, 파일 확장자에 대한 검증 없이 php 파일이 업로드 됨을 확인한다.
![[Pasted image 20240728081757.png]]


`/blog/wp-content/uploads/2024/07/` 경로로 접속하여 php 파일이 정상적으로 업로드 됨을 확인한다.
![[Pasted image 20240728081936.png]]



사전에 열어둔 공격자 서버의 1234 포트로 리버스 쉘을 받아오며, 웹서버 계정 권한으로 타겟 네트워크에 접속할 수 있다.
![[Pasted image 20240728082509.png]]



### 권한 상승

root 권한 상승을 위해 파일 시스템 내에 잘못된 권한 설정이 있는지 확인한다. `sudo -l` 명령어를 이용해 root 비밀번호 없이 sudo 권한으로 실행가능한 파일이 존재함을 확인한다.
![[Pasted image 20240728082711.png]]



[GTFOBins](https://gtfobins.github.io/) 사이트를 참고하여 sudo 및 해당 바이너리를 악용하는 방법을 확인 후 실행한다.

```
sudo busybox sh
```

![[Pasted image 20240728083248.png]]

root 권한으로 설정된 쉘을 획득했다. 이 권한 상승을 통해 Host3 의 제어권을 확보했고, 모의 침투 테스트는 여기서 마무리됐다. 테스트 과정에서 발견된 취약점들은 다음 섹션에 문서화했다.



## 취약점 및 대응 방안
### 1. 웹서비스 불필요한 파일 제거

#### 취약점 개요

| 정보          | 설명                                                        |
| ----------- | --------------------------------------------------------- |
| 이름          | 웹서비스 불필요한 파일 제거                                           |
| 중요도         | 상                                                         |
| 위치          | URL: http://10.0.4.30/<br>파일 경로: /var/www/html/index.html |

#### 취약점 설명

Ubuntu Apache2 기본페이지를 제거하지 않고 남겨두었으므로, 공격자는 OS 및 웹서버 정보 수집 후 관련 버전의 취약점을 찾아 2차 공격을 시도할 가능성이 높다. 또한 실제 경로 파악 및 접근 가능하다.
해당 기본 페이지를 랜딩페이지로 유지한다면 공격자는 설정 파일 및 웹루트 경로( `/var/www/html`) 등 실제 경로를 쉽게 추측할 수 있다.


#### 대응 방안

웹서버를 설치할 때, 기본으로 생성되는 불필요한 파일 및 디렉토리는 제거 후 자체 제작한 랜딩페이지를 사용한다.
삭제할 기본 페이지 경로: `/var/www/html/index.html`




### 2. 불충분한 인증

#### 취약점 개요

| 정보          | 설명                                      |
| ----------- | --------------------------------------- |
| 이름          | 불충분한 인증                                 |
| 중요도         | 상                                       |
| 위치          | URL: http://10.0.4.30/blog/wp-login.php |


#### 취약점 설명

사용자 아이디가 존재하지만 비밀번호를 틀릴 경우, 서버측 응답을 통해 해당 유저의 유무 확인이 가능한 취약점이다.
사용자의 비밀번호를 단순한 문자열로 설정한 경우, 무작위 사전 대입 공격을 시도해 비밀번호를 알아낼 가능성이 있다. 


#### 대응 방안

서버내에 있는 유저 존재 여부를 추측하지 못하도록, 유저 존재 여부와 상관없이 같은 응답을 출력하도록 한다
또한 무작위 대입공격을 막기위해서, 특정 IP에 대하여 로그인 시도 횟수 제한을 둔다. 시간 당 제한을 초과한 경우, 해당 IP주소를 차단하거나 캡차(CAPTCHA) API 등을 도입해 반복적인 로그인을 시도하지 못하도록 대응한다.


- 로그인 시도 한 유저가 존재하지 않을 경우의 응답
```php       
if ( ! $user ) {                                                                      
		return new WP_Error(                                                          
				'invalid_username',                                                   
				sprintf(                                                              
						/* translators: %s: User name. */
						__( '<strong>Error:</strong> The username or password were wrong.' ),                                                                                      
						$username                                                     
				)                                                                     
		);                                                                            
} 
```

- 로그인 시도 한 유저가 존재할 경우의 응답
```php
if ( ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
                return new WP_Error(
                        'incorrect_password',
                        sprintf(
                                /* translators: %s: User name. */
                                __( '<strong>Error:</strong> The username or password were wrong.' ),
                                '<strong>' . $username . '</strong>'
                        ) .     
                );      
        }               
                        
        return $user;
}   
```


### 3. 웹서비스 디렉토리 리스팅 제거

#### 취약점 개요

| 정보          | 설명                                                              |
| ----------- | --------------------------------------------------------------- |
| 이름          | 웹서비스 디렉토리 리스팅 제거                                                |
| 중요도         | 상                                                               |
| 위치          | URL: http://10.0.4.30/blog/_backup/<br>파일 이름: `corp-creds.xlsx` |

#### 취약점 설명

서버의 디렉토리 리스팅이 설정되어 있으므로, 공격자가 해당 디렉토리에 있는 파일들을 확인 및 열람이 가능한 취약점이다.

`Gobuster` 툴을 통해 알아낸 `/blog/_backup/` 경로에 접속 시 디렉토리 리스팅이 설정되어 있으며, 중요 파일이 노출되어 있다.
계정 정보와 관련된 중요 파일을 열람 후, 권한 상승에 이용할 수 있었다.


#### 대응 방안

디렉토리 내에 특정파일이 존재하더라도, 특정 파일의 경로를 요청하지 않는 이상 해당 디렉토리에 대해 리스팅이 불가능하도록 설정한다.
또는 해당 경로를 관리자 유저 외에 접근하지 못하도록 권한 설정한다.

- Apache2 설정 파일 경로: `/etc/apache2/apache2.conf`

- 설정 이전
```
<Directory /var/www/>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
</Directory>
```

- 설정 이후
```
<Directory /var/www/>
        Options FollowSymLinks
        AllowOverride None
        Require all granted
</Directory>
```

- 웹 서비스 재시작
```
service apache2 restart
```


해당 디렉토리에서 리스팅이 금지되어 파일 확인이 불가함을 확인한다.
![[Pasted image 20240728165107.png]]


### 4. 약한 암호화 종류 사용

#### 취약점 개요

| 정보          | 설명                                                              |
| ----------- | --------------------------------------------------------------- |
| 이름          | 약한 암호화 종류 사용                                                    |
| 중요도         | 상                                                               |
| 위치          | 파일 이름: `corp-creds.xlsx`<br>암호 종류 및 버전:  CDFV2 - MS Office 2007 |


#### 취약점 설명


해당 `corp-creds.xlsx` 문서 파일은 CDFV2로 암호화가 되어있었다. 해당 암호화 종류에 해당하는 johntheripper 검색 결과를 확인한 결과, `office2john` 명령어로 해시를 추출 후, `johntheripper` 툴을 이용해 해시를 크래킹할 수 있으며 `<REDACTED>` 라는 비밀번호가 추출됨을 확인했다.

이는 MS Office 2007 버전의 약한 암호화종류 사용으로 인한 취약점으로, 평문 비밀번호를 어렵지 않게 추출 가능했다.


#### 대응 방안

파일 암호화 시, MS 2014 이상의 버전으로 파일 암호화를 적용한다.
기본적으로 흔하지 않은 복잡한 비밀번호 사용해야 한다. 또는 해당 파일에 솔트값을 적용시켜 공격자가 크래킹하기 어렵도록 만든다. 


### 5. 파일 업로드 허용

#### 취약점 개요

| 정보  | 설명                                                                                                                                                |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| 이름  | 파일 업로드 허용                                                                                                                                         |
| 중요도 | 상                                                                                                                                                 |
| 위치  | URL: http://10.0.4.30/blog/wp-admin/update.php?action=upload-theme<br>업로드 파일 경로: `/blog/wp-content/uploads/2024/07/`<br>POST 요청 파라미터 : `themezip` |


#### 취약점 설명

파일 업로드 기능 사용 시, 파일 확장자 검증이 미흡하여, 악성 php파일 업로드가 가능한 취약점이다.
파일 업로드 취약점과 관련하여 테마 또는 플러그인 추가하는 기능에서, zip 파일 대신 임의의 악성 php 파일 업로드를 시도했을 때, 파일 확장자에 대한 검증 없이 php 파일이 업로드 됨을 확인한다.


#### 대응 방안

파일 업로드 기능에서, 화이트리스트 또는 블랙리스트 필터링을 적용시켜 특정 확장자의 파일만 업로드가 가능하도록 파일 확장자를 정확히 검증한다.

```php
# 예시
function checkFormat($source){
    $whitelist = "zip";
    $type="";
    if(version_compare('4.3.0', PHP_VERSION) > 0){
        $type=mime_content_type($source['tmp_name']);
    }else{
        $type=$source['type'];
    }

    return (in_array($type, $whitelist));
}
```

또한 웹서버와 파일 업로드 서버를 구분시켜, 해당 디렉토리 경로에서는 실행하지 못하도록 대응하는 방법도 고려할 수 있다.


### 6. root 계정 원격 접속 제한

#### 취약점 개요

| 정보          | 설명                       |
| ----------- | ------------------------ |
| 이름          | root 계정 원격 접속 제한         |
| 중요도         | 상                        |
| 위치          | 실행 파일 경로: `/bin/busybox` |


#### 취약점 설명

`busybox` 명령어에 대해 불필요한 sudo 권한 설정으로 인해 낮은 권한의 유저가 root 유저로 권한을 상승할 수 있는 취약점이다.

`sudo -l` 명령어를 이용해, root 유저의 비밀번호 없이 sudo 권한으로 실행가능한 파일이 존재함을 확인했다. 이를 악용하여 root 유저로 권한 상승까지 가능했다.

```
sudo busybox sh
```



#### 대응 방안

`/etc/sudoers` 파일에서, 낮은 권한의 유저에게 설정된 sudo 바이너리 권한을 제거한다.

```
# Allow members of group sudo to execute any command           
%sudo   ALL=(ALL:ALL) ALL                                         
                                                               
# See sudoers(5) for more information on "@include" directives:                 
                                         
@includedir /etc/sudoers.d                  
www-data ALL=(ALL) NOPASSWD: /bin/busybox  
```
	- `www-data ALL=(ALL) NOPASSWD: /bin/busybox` 제거

