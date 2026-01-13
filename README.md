
## Shodan Queries for Authorized Testing

## Target Reconnaissance & Asset Discovery
> **Map the attack surface of a specific company.**

| Goal | Shodan Query |
| :--- | :--- |
| **Find All Assets by Org** | `org:"Target Company Inc"` |
| **Find Assets by SSL Cert** | `ssl:"target-company.com"` |
| **Find Subdomains** | `hostname:"target-company.com"` |
| **Find Dev/Staging Environments** | `hostname:"dev.target.com" OR hostname:"staging.target.com"` |
| **Find Test Environments** | `hostname:"test.target.com" OR hostname:"uat.target.com"` |
| **Find Internal Assets** | `hostname:"internal" org:"Target Company"` |
| **Find Cloud Assets (AWS)** | `org:"Amazon Data Services" ssl:"target.com"` |
| **Find Cloud Assets (Azure)** | `org:"Microsoft Azure" ssl:"target.com"` |
| **Find Cloud Assets (GCP)** | `org:"Google Cloud" ssl:"target.com"` |
| **Favicon Hash Hunting** | `http.favicon.hash:-123456789` (Calculate hash of target favicon) |

##  Information Disclosure & Config Leaks

| File / Leak | Shodan Query |
| :--- | :--- |
| **Exposed .env Files** | `http.title:"Index of /" http.html:".env"` |
| **Exposed .git Directory** | `http.title:"Index of /" http.html:".git"` |
| **Exposed .vscode Directory** | `http.title:"Index of /" http.html:".vscode"` |
| **Exposed Docker Config** | `http.title:"Index of /" http.html:"docker-compose.yml"` |
| **Apache Server Status** | `http.title:"Apache Status" "Server Version: Apache/"` |
| **PHP Info Page** | `http.html:"phpinfo()" http.status:200` |
| **Django Debug Mode** | `title:"DisallowedHost at /" OR title:"OperationalError at /"` |
| **Laravel Debug Mode** | `title:"Whoops! There was an error." http.status:500` |
| **Rails Default Page** | `title:"Ruby on Rails: Welcome aboard"` |
| **Spring Boot Actuators** | `http.html:"/actuator/health" OR http.html:"/actuator/env"` |
| **Open Directory (Generic)** | `http.title:"Index of /" -http.title:"Welcome"` |
| **Exposed Log Files** | `http.title:"Index of /" http.html:".log"` |
| **Exposed SQL Dumps** | `http.title:"Index of /" http.html:".sql"` |

##  API & Documentation Exposure
> **Forgotten endpoints and exposed Swagger UIs.**

| Technology | Shodan Query |
| :--- | :--- |
| **Swagger UI (Docs)** | `http.title:"Swagger UI" -401` |
| **Swagger API Json** | `http.html:"swagger.json" http.status:200` |
| **GraphQL Playground** | `http.title:"GraphQL Playground"` |
| **GraphiQL Interface** | `http.title:"GraphiQL"` |
| **Kibana (No Auth)** | `kibana content-length:217` |
| **Elasticsearch (No Auth)** | `port:9200 "lucene" -authentication` |
| **Solr Admin** | `http.title:"Solr Admin" -401` |
| **Postman Echo** | `title:"Postman Echo"` |
| **Kong API Gateway** | `port:8001 "kong"` |
| **WSO2 API Manager** | `title:"WSO2 API Manager"` |

##  DevOps & CI/CD Vulnerabilities

| Tool | Query |
| :--- | :--- |
| **Jenkins (Script Console)** | `http.title:"Jenkins" http.html:"script"` |
| **Jenkins (No Auth)** | `http.title:"Dashboard [Jenkins]" -401` |
| **GitLab (Open reg)** | `title:"GitLab" http.html:"Register"` |
| **TeamCity (Guest)** | `title:"TeamCity" http.html:"Log in as Guest"` |
| **SonarQube (Public)** | `title:"SonarQube" -401` |
| **ArgoCD** | `title:"Argo CD" -401` |
| **Kubernetes Dashboard** | `title:"Kubernetes Dashboard" 200` |
| **Docker Registry** | `"Docker-Distribution-Api-Version: registry/2.0" -401` |
| **Selenium Grid** | `title:"Selenium Grid" -401` |
| **RabbitMQ Management** | `title:"RabbitMQ Management" -401` |
| **HAProxy Stats** | `title:"HAProxy Statistics" -401` |

## Specific CVE Hunting (Bounty Focused)

| Vulnerability | Shodan Query |
| :--- | :--- |
| **Grafana LFI** | `product:"Grafana" version:"8.0.0"` |
| **Confluence OGNL** | `http.component:"Atlassian Confluence" version:"<7.13.0"` |
| **Jira Info Leak** | `http.component:"Atlassian Jira" http.html:"/secure/Dashboard.jspa"` |
| **Citrix ADC RCE** | `http.title:"Citrix Gateway" http.html:"/vpn/../vpns/"` |
| **F5 BIG-IP TMUI RCE** | `http.title:"BIG-IP" http.html:"/tmui/"` |
| **Pulse Secure RCE** | `http.html:"/dana-na/" http.html:"/dana/js/"` |
| **FortiOS Path Trav** | `server:"x-content-type-options" http.html:"/remote/fgt_lang"` |
| **Exchange ProxyShell** | `http.title:"Outlook Web App" http.html:"/owa/auth/logon.aspx"` |
| **Log4j (Passive)** | `product:"Apache Solr" OR product:"Elasticsearch" OR product:"Log4j"` |

## Cloud Storage (Buckets & Blobs)

| Asset | Query |
| :--- | :--- |
| **Amazon S3 Listing** | `http.html:"amazonaws.com" http.title:"Index of /"` |
| **Azure Blob Listing** | `http.html:"blob.core.windows.net" http.title:"Index of /"` |
| **Google Cloud Listing** | `http.html:"googleapis.com" http.title:"Index of /"` |
| **DigitalOcean Spaces** | `http.html:"digitaloceanspaces.com" http.title:"Index of /"` |
| **MinIO Browser** | `title:"MinIO Browser"` |


 Admin Panels & Login Portals


| Target System | Shodan Query |
| :--- | :--- |
| **Cisco ASA** | `title:"Cisco Systems, Inc. Web VPN Service"` |
| **Cisco Firepower** | `title:"Cisco Firepower Management Center"` |
| **Citrix Gateway** | `title:"Citrix Gateway"` |
| **Citrix StoreFront** | `title:"Citrix StoreFront"` |
| **SonicWall** | `title:"SonicWall" "login"` |
| **FortiGate** | `title:"FortiGate" OR title:"Fortinet"` |
| **Palo Alto** | `title:"GlobalProtect Portal"` |
| **Pulse Secure** | `title:"Pulse Secure" OR title:"Pulse Connect Secure"` |
| **F5 BIG-IP** | `title:"BIG-IP" OR title:"F5"` |
| **Juniper** | `title:"Juniper Web Device Manager"` |
| **Sophos** | `title:"Sophos User Portal"` |
| **WatchGuard** | `title:"WatchGuard Firebox"` |
| **PfSense** | `title:"pfSense - Login"` |
| **Opnsense** | `title:"OPNsense" -401` |
| **MikroTik** | `title:"MikroTik RouterOS"` |
| **Ubiquiti UniFi** | `title:"UniFi Controller"` |
| **Ubiquiti EdgeRouter** | `title:"EdgeRouter"` |
| **Ubiquiti AirOS** | `title:"AirOS"` |
| **Synology DSM** | `title:"Synology DiskStation"` |
| **QNAP QTS** | `title:"QNAP TurboNAS"` |
| **Asustor** | `title:"ASUSTOR ADM"` |
| **Traefik** | `title:"Traefik"` |
| **Portainer** | `title:"Portainer"` |
| **Docker Registry** | `title:"Docker Registry"` |
| **Kubernetes** | `title:"Kubernetes Dashboard"` |
| **OpenShift** | `title:"OpenShift Web Console"` |
| **Rancher** | `title:"Rancher"` |
| **Jenkins** | `title:"Sign in [Jenkins]"` |
| **GitLab** | `title:"GitLab" -401` |
| **Gitea** | `title:"Gitea"` |
| **Bitbucket** | `title:"Bitbucket"` |
| **SonarQube** | `title:"SonarQube"` |
| **Nexus Repo** | `title:"Nexus Repository Manager"` |
| **Artifactory** | `title:"Artifactory"` |
| **Grafana** | `title:"Grafana"` |
| **Kibana** | `title:"Kibana"` |
| **Splunk** | `title:"Splunk"` |
| **Graylog** | `title:"Graylog"` |
| **Zabbix** | `title:"Zabbix"` |
| **Nagios** | `title:"Nagios XI"` |
| **SolarWinds** | `title:"SolarWinds Orion"` |
| **PRTG** | `title:"PRTG Network Monitor"` |
| **Checkmk** | `title:"Checkmk"` |
| **Webmin** | `title:"Webmin"` |
| **Cockpit** | `title:"Cockpit"` |
| **cPanel** | `title:"cPanel"` |
| **WHM** | `title:"WHM"` |
| **Plesk** | `title:"Plesk"` |
| **DirectAdmin** | `title:"DirectAdmin"` |
| **ISPConfig** | `title:"ISPConfig"` |
| **VestaCP** | `title:"Vesta Control Panel"` |
| **Virtualmin** | `title:"Virtualmin"` |
| **Proxmox** | `title:"Proxmox Virtual Environment"` |
| **VMware ESXi** | `title:"VMware ESXi"` |
| **VMware vCenter** | `title:"ID_VC_Welcome"` |
| **XenServer** | `title:"Citrix XenServer"` |
| **iDRAC** | `title:"iDRAC"` |
| **iLO** | `title:"Integrated Lights-Out"` |
| **Supermicro IPMI** | `title:"Supermicro" port:443` |
| **Pi-hole** | `title:"Pi-hole admin"` |
| **Home Assistant** | `title:"Home Assistant"` |
| **OpenHAB** | `title:"openHAB"` |
| **Domoticz** | `title:"Domoticz"` |
| **Node-RED** | `title:"Node-RED"` |
| **OctoPrint** | `title:"OctoPrint"` |

## Database & Cache (The "No Auth" List)
> **Direct access to data stores.**

| Technology | Shodan Query |
| :--- | :--- |
| **MongoDB** | `port:27017 -authentication` |
| **Redis** | `port:6379 "redis_version" -authentication` |
| **Memcached** | `port:11211 "STAT pid"` |
| **ElasticSearch** | `port:9200 "lucene" -authentication` |
| **Cassandra** | `port:9042 "Cassandra"` |
| **CouchDB** | `port:5984 "couchdb"` |
| **RethinkDB** | `port:8080 "rethinkdb"` |
| **RabbitMQ** | `port:15672 "RabbitMQ"` |
| **ActiveMQ** | `port:8161 "ActiveMQ"` |
| **Mosquitto (MQTT)** | `port:1883 "mosquitto"` |
| **Kafka** | `port:9092 "kafka"` |
| **ZooKeeper** | `port:2181 "zookeeper"` |
| **Etcd** | `port:2379 "etcd"` |
| **Consul** | `port:8500 "consul"` |
| **Hadoop HDFS** | `port:50070 "Hadoop"` |
| **Hadoop YARN** | `port:8088 "cluster"` |
| **Apache Spark** | `port:8080 "Spark Master"` |
| **Apache Solr** | `port:8983 "solr"` |
| **PostgreSQL** | `port:5432 "PostgreSQL" -authentication` |
| **MySQL** | `port:3306 "MySQL" -authentication` |
| **OrientDB** | `port:2480 "OrientDB"` |
| **ArangoDB** | `port:8529 "ArangoDB"` |
| **InfluxDB** | `port:8086 "X-Influxdb-Version"` |
| **Neo4j** | `port:7474 "neo4j"` |

##  Webcams & DVRs (Brands)
> **Specific brand targeting.**

| Brand | Query |
| :--- | :--- |
| **Hikvision** | `title:"Hikvision"` |
| **Dahua** | `title:"Dahua"` |
| **Axis** | `product:"Axis Network Camera"` |
| **Avigilon** | `title:"Avigilon"` |
| **Mobotix** | `title:"Mobotix"` |
| **Vivotek** | `title:"VIVOTEK"` |
| **Reolink** | `title:"Reolink"` |
| **Foscam** | `title:"Foscam"` |
| **Geovision** | `title:"GeoVision"` |
| **Panasonic** | `title:"Panasonic Network Camera"` |
| **Sony** | `title:"Sony Network Camera"` |
| **Samsung** | `title:"Samsung IP Camera"` |
| **Bosch** | `title:"Bosch"` |
| **Honeywell** | `title:"Honeywell"` |
| **Pelco** | `title:"Pelco"` |
| **Amcrest** | `title:"Amcrest"` |
| **Swann** | `title:"Swann"` |
| **Lorex** | `title:"Lorex"` |
| **Netgear Arlo** | `title:"Arlo"` |
| **Nest** | `title:"Nest"` |
| **Ring** | `title:"Ring"` |
| **D-Link** | `title:"D-Link"` |
| **TP-Link** | `title:"TP-Link Camera"` |
| **Linksys** | `title:"Linksys Camera"` |
| **Trendnet** | `title:"TRENDnet"` |
| **Canon** | `title:"Canon Network Camera"` |
| **Toshiba** | `title:"Toshiba Network Camera"` |
| **JVC** | `title:"JVC Network Camera"` |
| **Cisco** | `title:"Cisco Video Surveillance"` |
| **Ubiquiti** | `title:"UniFi Video"` |
| **Blue Iris** | `title:"Blue Iris"` |
| **Shinobi** | `title:"Shinobi"` |
| **ZoneMinder** | `title:"ZoneMinder"` |
| **iSpy** | `title:"iSpy"` |
| **MotionEye** | `title:"motionEye"` |
| **Kerberos.io** | `title:"Kerberos.io"` |
| **Xeoma** | `title:"Xeoma"` |
| **Genetec** | `title:"Genetec"` |
| **Milestone** | `title:"Milestone XProtect"` |
| **ExacqVision** | `title:"exacqVision"` |

## ☁️ Software & Headers (Fingerprinting)
> **Identify specific software versions.**

* `product:"Apache Tomcat"`
* `product:"Apache HTTP Server"`
* `product:"Nginx"`
* `product:"Microsoft IIS"`
* `product:"Jetty"`
* `product:"Node.js"`
* `product:"Express"`
* `product:"TwistedWeb"`
* `product:"TornadoServer"`
* `product:"Gunicorn"`
* `product:"Waitress"`
* `product:"uWSGI"`
* `product:"Caddy"`
* `product:"Traefik"`
* `product:"Squid"`
* `product:"Varnish"`
* `product:"HAProxy"`
* `product:"OpenResty"`
* `product:"LiteSpeed"`
* `product:"Cherokee"`
* `product:"Hiawatha"`
* `product:"Monkey"`
* `product:"Boa"`
* `product:"thttpd"`
* `product:"lighttpd"`
* `product:"micro_httpd"`
* `product:"mini_httpd"`
* `product:"GoAhead-Webs"`
* `product:"RomPager"`
* `product:"Allegro-Software-RomPager"`
* `product:"Virata-EmWeb"`
* `product:"WindRiver-WebServer"`
* `product:"Zyxel-RomPager"`
* `product:"D-Link-RomPager"`
* `product:"TP-Link-RomPager"`
* `product:"Netgear-RomPager"`
* `product:"Cisco-RomPager"`
* `product:"Huawei-RomPager"`
* `product:"ZTE-RomPager"`
* `product:"Realtek-RomPager"`
* `product:"PHP"`
* `product:"ASP.NET"`
* `product:"Python"`
* `product:"Java"`
* `product:"Ruby"`
* `product:"Perl"`
* `product:"Erlang"`
* `product:"OpenSSL"`
* `product:"GnuTLS"`
* `product:"LibreSSL"`
* `product:"BoringSSL"`
* `product:"WolfSSL"`
* `product:"MatrixSSL"`
* `product:"Schannel"`
* `product:"SecureTransport"`
* `product:"JSSE"`
* `product:"NSS"`
* `product:"Botan"`
* `product:"Cryptlib"`
* `product:"S2n"`

##  Common Ports Sweep
> **Scan for services running on non-standard ports.**

1.  `port:21` (FTP)
2.  `port:22` (SSH)
3.  `port:23` (Telnet)
4.  `port:25` (SMTP)
5.  `port:53` (DNS)
6.  `port:69` (TFTP)
7.  `port:80` (HTTP)
8.  `port:110` (POP3)
9.  `port:123` (NTP)
10. `port:135` (RPC)
11. `port:139` (NetBIOS)
12. `port:143` (IMAP)
13. `port:161` (SNMP)
14. `port:194` (IRC)
15. `port:389` (LDAP)
16. `port:443` (HTTPS)
17. `port:445` (SMB)
18. `port:465` (SMTPS)
19. `port:514` (Syslog)
20. `port:587` (Submission)
21. `port:631` (CUPS)
22. `port:636` (LDAPS)
23. `port:873` (Rsync)
24. `port:993` (IMAPS)
25. `port:995` (POP3S)
26. `port:1080` (SOCKS)
27. `port:1194` (OpenVPN)
28. `port:1433` (MSSQL)
29. `port:1521` (Oracle)
30. `port:1723` (PPTP)
31. `port:1883` (MQTT)
32. `port:2049` (NFS)
33. `port:2082` (cPanel)
34. `port:2083` (cPanel SSL)
35. `port:2086` (WHM)
36. `port:2087` (WHM SSL)
37. `port:2181` (ZooKeeper)
38. `port:2222` (DirectAdmin)
39. `port:2375` (Docker)
40. `port:2376` (Docker SSL)
41. `port:2480` (OrientDB)
42. `port:2638` (Sybase)
43. `port:3000` (Rails/Node)
44. `port:3050` (Firebird)
45. `port:3128` (Squid)
46. `port:3306` (MySQL)
47. `port:3389` (RDP)
48. `port:3690` (SVN)
49. `port:4369` (Erlang)
50. `port:4500` (IPsec)
51. `port:4848` (GlassFish)
52. `port:5000` (Flask/Synology)
53. `port:5060` (SIP)
54. `port:5222` (XMPP)
55. `port:5432` (PostgreSQL)
56. `port:5555` (ADB)
57. `port:5601` (Kibana)
58. `port:5672` (RabbitMQ)
59. `port:5800` (VNC HTTP)
60. `port:5900` (VNC)
61. `port:5938` (TeamViewer)
62. `port:5984` (CouchDB)
63. `port:6000` (X11)
64. `port:6379` (Redis)
65. `port:6666` (IRC)
66. `port:6667` (IRC)
67. `port:7001` (WebLogic)
68. `port:7474` (Neo4j)
69. `port:8000` (Alt HTTP)
70. `port:8006` (Proxmox)
71. `port:8008` (Chromecast)
72. `port:8080` (Alt HTTP)
73. `port:8081` (Alt HTTP)
74. `port:8086` (InfluxDB)
75. `port:8088` (Hadoop)
76. `port:8089` (Splunk)
77. `port:8161` (ActiveMQ)
78. `port:8291` (WinBox)
79. `port:8333` (Bitcoin)
80. `port:8443` (Alt HTTPS)
81. `port:8500` (Consul)
82. `port:8883` (MQTT SSL)
83. `port:8888` (Alt HTTP)
84. `port:9000` (Portainer/Sonar)
85. `port:9001` (Tor/Supervisord)
86. `port:9042` (Cassandra)
87. `port:9090` (Prometheus)
88. `port:9092` (Kafka)
89. `port:9100` (Printer)
90. `port:9200` (Elasticsearch)
91. `port:9300` (Elasticsearch)
92. `port:9418` (Git)
93. `port:9999` (Urchin)
94. `port:10000` (Webmin)
95. `port:11211` (Memcached)
96. `port:27017` (MongoDB)
97. `port:27018` (MongoDB)
98. `port:27019` (MongoDB)
99. `port:50000` (SAP)
100. `port:50070` (Hadoop)





##  Network Infrastructure (Routers & Switches)

| Vendor / Device | Shodan Query |
| :--- | :--- |
| **Cisco IOS** | `server:"cisco-ios" "last-modified"` |
| **Cisco IOS-XE** | `server:"cisco-ios" "web ui"` |
| **Cisco ASA** | `product:"Cisco ASA" "Set-Cookie"` |
| **Juniper JunOS** | `title:"Juniper Web Device Manager"` |
| **Huawei Home Gateway** | `title:"Huawei Home Gateway"` |
| **Huawei Router** | `product:"Huawei Home Gateway"` |
| **MikroTik RouterOS** | `port:8291 os:"MikroTik RouterOS"` |
| **Ubiquiti EdgeRouter** | `title:"EdgeRouter" "Ubiquiti"` |
| **Ubiquiti AirOS** | `title:"AirOS" "Login"` |
| **Zyxel Modem** | `title:"Zyxel" "Welcome"` |
| **Technicolor Gateway** | `title:"Technicolor Gateway"` |
| **Arris Cable Modem** | `title:"Touchstone Status"` |
| **Netgear Router** | `title:"NETGEAR Router" -401` |
| **TP-Link Router** | `title:"TP-LINK" "Login"` |
| **D-Link Router** | `title:"D-Link" "Home"` |
| **Linksys Smart Wi-Fi** | `title:"Linksys Smart Wi-Fi"` |
| **ASUS Router** | `server:"httpd" "ASUS"` |
| **DrayTek Vigor** | `title:"Vigor" "Login"` |
| **Fortinet FortiGate** | `server:"x-content-type-options"` |
| **Palo Alto PAN-OS** | `server:"PanOS"` |
| **SonicWall** | `server:"SonicWALL"` |
| **Sophos XG** | `title:"Sophos" "User Portal"` |
| **WatchGuard** | `server:"WatchGuard"` |
| **F5 BIG-IP** | `server:"BigIP"` |
| **Citrix NetScaler** | `server:"NetScaler"` |
| **Brocade** | `title:"Brocade Web Tools"` |
| **Ruckus Wireless** | `title:"Ruckus Wireless Admin"` |
| **Aruba Networks** | `title:"Aruba Networks"` |
| **Cambium Networks** | `title:"Cambium"` |

## VoIP & Telephony Systems
> **PBX, SIP Trunks, and IP Phones.**

| System | Port | Query |
| :--- | :--- | :--- |
| **SIP Protocol** | 5060 | `port:5060 "SIP/2.0"` |
| **Asterisk PBX** | 5038 | `port:5038 "Asterisk Call Manager"` |
| **FreePBX** | 80 | `title:"FreePBX Administration"` |
| **3CX Phone System** | 5001 | `title:"3CX Phone System Management Console"` |
| **Cisco IP Phone** | 80 | `title:"Cisco IP Phone"` |
| **Polycom Phone** | 80 | `title:"Polycom" "SoundPoint"` |
| **Yealink Phone** | 80 | `title:"Yealink" "Logon"` |
| **Grandstream** | 80 | `title:"Grandstream" "Login"` |
| **Avaya IP Office** | 80 | `title:"Avaya IP Office"` |
| **Mitel** | 80 | `title:"Mitel" "Login"` |
| **Snom Phone** | 80 | `title:"snom" "login"` |
| **Fanvil** | 80 | `title:"Fanvil"` |
| **WebRTC** | 443 | `"WebRTC" "Session"` |
| **Kamailio** | 5060 | `product:"Kamailio"` |

##  Remote Access & Virtualization
> **RDP, VNC, and Hypervisors.**

| Service | Query |
| :--- | :--- |
| **Windows RDP** | `port:3389 "Remote Desktop"` |
| **VNC (No Auth)** | `port:5900 "RFB 003.008"` |
| **TeamViewer** | `port:5938 "TeamViewer"` |
| **AnyDesk** | `port:7070 "AnyDesk"` |
| **PCAnywhere** | `port:5632 "pcAnywhere"` |
| **Citrix ICA** | `port:1494 "Citrix"` |
| **VMware Horizon** | `title:"VMware Horizon"` |
| **VMware vSphere** | `title:"VMware vSphere"` |
| **Proxmox VE** | `title:"Proxmox Virtual Environment"` |
| **Xen Orchestra** | `title:"Xen Orchestra"` |
| **oVirt** | `title:"oVirt Engine"` |
| **KVM (via Cockpit)** | `title:"Cockpit" "Virtual Machines"` |
| **VirtualBox (Web)** | `title:"phpVirtualBox"` |
| **Guacamole** | `title:"Apache Guacamole"` |
| **Nomachine** | `port:4000 "NX"` |

##  Printers & Multi-Function Devices
> **Often unsecured and leaking documents.**

| Brand | Query |
| :--- | :--- |
| **HP JetDirect** | `port:9100 "HP JetDirect"` |
| **HP EWS** | `title:"HP" "Embedded Web Server"` |
| **Canon ImageRunner** | `title:"Canon" "Remote UI"` |
| **Epson** | `title:"Epson" "WebConfig"` |
| **Xerox WorkCentre** | `title:"Xerox" "WorkCentre"` |
| **Brother** | `title:"Brother" "NetAdmin"` |
| **Kyocera** | `title:"Kyocera" "Command Center"` |
| **Ricoh** | `title:"Ricoh" "Web Image Monitor"` |
| **Konica Minolta** | `title:"Konica Minolta" "PageScope"` |
| **Lexmark** | `title:"Lexmark" "Virtual Operator Panel"` |
| **OKI** | `title:"OKI" "Configuration"` |
| **Samsung Printer** | `title:"Samsung SyncThru"` |
| **Zebra Label Printer** | `title:"Zebra" "Print Server"` |
| **CUPS Server** | `port:631 "CUPS"` |

## File Servers & Sharing (FTP/SMB)
> **Open directories and storage.**

| Protocol | Query |
| :--- | :--- |
| **FTP (Anon)** | `port:21 "230 Login successful"` |
| **SMB (Windows)** | `port:445 "Windows 6.1" (Win7)` |
| **SMB (Samba)** | `port:445 "Samba"` |
| **Apple Filing (AFP)** | `port:548 "AFP"` |
| **NFS** | `port:2049 "NFS"` |
| **WebDAV** | `port:80 "DAV"` |
| **Synology File Station** | `title:"File Station" "Synology"` |
| **QNAP File Station** | `title:"File Station" "QNAP"` |
| **Nextcloud** | `title:"Nextcloud"` |
| **ownCloud** | `title:"ownCloud"` |
| **Seafile** | `title:"Seafile"` |
| **Pydio** | `title:"Pydio"` |
| **HFS (HTTP File Server)** | `product:"HFS"` |
| **Vsftpd** | `product:"vsftpd"` |
| **ProFTPD** | `product:"ProFTPD"` |
| **Pure-FTPd** | `product:"Pure-FTPd"` |
| **FileZilla Server** | `product:"FileZilla Server"` |

## Misconfigured & Default Pages
> **Signs of fresh or neglected installs.**

| Type | Query |
| :--- | :--- |
| **Apache Default** | `title:"Apache2 Ubuntu Default Page"` |
| **Nginx Default** | `title:"Welcome to nginx!"` |
| **IIS Default** | `title:"IIS Windows Server"` |
| **Open Directory** | `title:"Index of /"` |
| **Django Debug** | `title:"DisallowedHost at /"` |
| **Laravel Debug** | `title:"Whoops! There was an error."` |
| **PHP Info** | `title:"phpinfo()"` |
| **Tomcat Manager** | `title:"Apache Tomcat" "Manager"` |
| **XAMPP Dashboard** | `title:"Welcome to XAMPP"` |
| **WAMP Server** | `title:"WAMPSERVER Homepage"` |
| **MAMP** | `title:"Welcome to MAMP"` |
| **Swagger UI** | `title:"Swagger UI"` |
| **Spring Boot** | `title:"Whitelabel Error Page"` |

##  Cryptocurrency & Blockchain
> **Nodes, Miners, and Wallets.**

| Coin / Service | Port | Query |
| :--- | :--- | :--- |
| **Bitcoin Node** | 8333 | `port:8333 "Satoshi"` |
| **Ethereum Node** | 30303 | `port:30303 "Geth"` |
| **Monero Node** | 18080 | `port:18080` |
| **Litecoin Node** | 9333 | `port:9333` |
| **Dogecoin Node** | 22556 | `port:22556` |
| **Ripple (XRP)** | 51235 | `port:51235` |
| **EOS** | 9876 | `port:9876` |
| **Stellar** | 11625 | `port:11625` |
| **Antminer** | 80 | `title:"Antminer"` |
| **Claymore** | 3333 | `port:3333` |
| **EthOS** | 80 | `title:"ethOS"` |
| **HiveOS** | 80 | `title:"HiveOS"` |
| **NiceHash** | 80 | `title:"NiceHash"` |



##  Game Servers & Voice Chat
> **Hosted game worlds and communication servers.**

| Game / Service | Port | Query |
| :--- | :--- | :--- |
| **Minecraft (Java)** | 25565 | `port:25565 "Minecraft Server"` |
| **Minecraft (Bedrock)** | 19132 | `port:19132 "MCPE"` |
| **Counter-Strike (Source)** | 27015 | `port:27015 "Source Engine"` |
| **Team Fortress 2** | 27015 | `port:27015 "Team Fortress"` |
| **ARK: Survival Evolved** | 7777 | `port:7777 "ARK"` |
| **Rust** | 28015 | `port:28015 "Rust"` |
| **FiveM (GTA V)** | 30120 | `port:30120 "FiveM"` |
| **Terraria** | 7777 | `port:7777 "Terraria"` |
| **Factorio** | 34197 | `port:34197 "Factorio"` |
| **Valheim** | 2456 | `port:2456 "Valheim"` |
| **7 Days to Die** | 26900 | `port:26900 "7 Days to Die"` |
| **TeamSpeak 3** | 9987 | `port:9987 "TeamSpeak"` |
| **Mumble** | 64738 | `port:64738 "Mumble"` |
| **Ventrilo** | 3784 | `port:3784` |

##  Smart Home & IoT Devices
> **Consumer electronics connected to the web.**

| Device | Query |
| :--- | :--- |
| **Google Home/Chromecast** | `port:8008 "Chromecast"` |
| **Apple AirPlay** | `port:7000 "AirPlay"` |
| **Amazon Echo (Alexa)** | `port:80 "Amazon Echo"` |
| **Philips Hue Bridge** | `title:"Philips Hue"` |
| **Sonos Speakers** | `port:1400 "Sonos"` |
| **Samsung Smart TV** | `port:8001 "Samsung"` |
| **LG Smart TV** | `port:1601 "LG Smart TV"` |
| **Roku Device** | `port:8060 "Roku"` |
| **Crestron Control** | `port:41794 "Crestron"` |
| **Lutron Lighting** | `title:"Lutron"` |
| **MQTT Brokers (IoT)** | `port:1883 -authentication` |
| **CoAP Devices** | `port:5683` |
| **Roomba Vacuums** | `title:"Roomba"` |
| **Fritz!Box** | `title:"FRITZ!Box"` |

## Mail Servers & Webmail
> **Infrastructure handling email traffic.**

| Software | Query |
| :--- | :--- |
| **Microsoft Exchange** | `port:443 title:"Outlook Web App"` |
| **Zimbra Collaboration** | `title:"Zimbra Web Client"` |
| **Roundcube Webmail** | `title:"Roundcube Webmail"` |
| **SquirrelMail** | `title:"SquirrelMail"` |
| **RainLoop** | `title:"RainLoop Webmail"` |
| **Horde Groupware** | `title:"Horde Application Framework"` |
| **Postfix Admin** | `title:"Postfix Admin"` |
| **Exim** | `product:"Exim httpd"` |
| **Sendmail** | `product:"Sendmail"` |
| **IBM Domino** | `product:"Lotus Domino"` |
| **MailCow** | `title:"mailcow UI"` |
| **iRedMail** | `title:"iRedMail"` |

## Big Data & Analytics Tools
> **Data science environments.**

| Tool | Query |
| :--- | :--- |
| **Jupyter Notebook** | `title:"Jupyter Notebook"` |
| **RStudio Server** | `title:"RStudio"` |
| **Apache Zeppelin** | `title:"Zeppelin"` |
| **Apache Airflow** | `title:"Airflow - Dags"` |
| **Mlflow** | `title:"MLflow"` |
| **TensorBoard** | `title:"TensorBoard"` |
| **Shiny Server** | `title:"Shiny Server"` |
| **Metabase** | `title:"Metabase"` |
| **Redash** | `title:"Login to Redash"` |
| **Superset** | `title:"Superset"` |

##  SSL/TLS & Certificates
> **Search by certificate properties.**

| Filter Type | Query Structure |
| :--- | :--- |
| **Expired Certs** | `ssl.cert.expired:true` |
| **Self-Signed** | `ssl.cert.issuer.cn:example.com ssl.cert.subject.cn:example.com` |
| **By Issuer** | `ssl.cert.issuer.cn:"Let's Encrypt"` |
| **By Subject** | `ssl.cert.subject.cn:"google.com"` |
| **By Serial** | `ssl.cert.serial:123456789` |
| **By Fingerprint** | `ssl.cert.fingerprint:sha256:HASH` |
| **Weak Cipher** | `ssl.version:sslv3` |

## Operating System Fingerprints
> **Target specific OS versions.**

| OS Family | Query |
| :--- | :--- |
| **Windows XP** | `os:"Windows XP"` |
| **Windows 7** | `os:"Windows 7"` |
| **Windows 10** | `os:"Windows 10"` |
| **Windows Server 2008** | `os:"Windows Server 2008"` |
| **Windows Server 2012** | `os:"Windows Server 2012"` |
| **Windows Server 2016** | `os:"Windows Server 2016"` |
| **Windows Server 2019** | `os:"Windows Server 2019"` |
| **Linux (Generic)** | `os:"Linux"` |
| **Ubuntu** | `os:"Ubuntu"` |
| **Debian** | `os:"Debian"` |
| **CentOS** | `os:"CentOS"` |
| **Red Hat** | `os:"Red Hat"` |
| **FreeBSD** | `os:"FreeBSD"` |
| **Android** | `os:"Android"` |
| **iOS** | `os:"iOS"` |

#  THE CLOUD NATIVE & SECRETS EDITION (Part 6)

##  Docker & Container Ecosystem
> **Exposed container orchestration and registries.**

| Asset | Port | Shodan Query |
| :--- | :--- | :--- |
| **Docker Daemon (Unsecured)** | 2375 | `port:2375 "Docker Containers"` |
| **Docker Registry (v2)** | 5000 | `"Docker-Distribution-Api-Version: registry/2.0"` |
| **Docker Swarm Manager** | 2377 | `port:2377` |
| **Portainer (Docker UI)** | 9000 | `title:"Portainer"` |
| **Harbor Registry** | 80/443 | `title:"Harbor"` |
| **Nexus Repository (Docker)** | 8081 | `title:"Nexus Repository Manager"` |
| **Artifactory (Docker)** | 8081 | `title:"Artifactory"` |
| **Rancher (Kubernetes Mgmt)** | 80/443 | `title:"Rancher"` |
| **Weave Scope (Monitoring)** | 4040 | `title:"Weave Scope"` |
| **cAdvisor (Google)** | 8080 | `title:"cAdvisor"` |
| **Docker Compose Leak** | 80 | `http.title:"Index of /" http.html:"docker-compose.yml"` |

## Kubernetes (K8s) Cluster Components
> **The heart of modern cloud infrastructure.**

| Component | Port | Shodan Query |
| :--- | :--- | :--- |
| **Kubernetes API Server** | 6443 | `port:6443 "Kubernetes"` |
| **Kubelet API (Read-Only)** | 10255 | `port:10255 http.html:"/pods"` |
| **Kubelet API (Read-Write)** | 10250 | `port:10250 404` |
| **Etcd (K8s Database)** | 2379 | `port:2379 "etcd"` |
| **Kube-Proxy** | 10256 | `port:10256` |
| **Calico (Networking)** | 9099 | `port:9099` |
| **Cilium (Networking)** | 4240 | `port:4240` |
| **Rook Ceph** | 9283 | `port:9283` |
| **Longhorn UI** | 80 | `title:"Longhorn"` |
| **Argo Workflows** | 2746 | `title:"Argo"` |
| **Tekton Dashboard** | 9097 | `title:"Tekton Dashboard"` |

## Secret Files & Key Leaks
> **Finding "keys to the kingdom" left in open directories.**

| File Type | Shodan Query |
| :--- | :--- |
| **SSH Private Keys** | `http.title:"Index of /" http.html:"id_rsa"` |
| **OpenVPN Configs** | `http.title:"Index of /" http.html:".ovpn"` |
| **KeePass Databases** | `http.title:"Index of /" http.html:".kdbx"` |
| **Putty Private Keys** | `http.title:"Index of /" http.html:".ppk"` |
| **MacOS Keychains** | `http.title:"Index of /" http.html:".keychain"` |
| **PGP/GPG Private Keys** | `http.title:"Index of /" http.html:".asc"` |
| **PKCS#12 Certificates** | `http.title:"Index of /" http.html:".p12"` |
| **Java Keystores** | `http.title:"Index of /" http.html:".jks"` |
| **Android Signing Keys** | `http.title:"Index of /" http.html:".keystore"` |
| **Slack Tokens (In logs)** | `http.title:"Index of /" http.html:"xoxb-"` |
| **AWS Credentials (In logs)** | `http.title:"Index of /" http.html:"AKIA"` |
| **Google Cloud Keys** | `http.title:"Index of /" http.html:".json" "private_key_id"` |

##  HashiCorp Stack Exposure
> **Infrastructure as Code (IaC) tools.**

| Tool | Port | Query |
| :--- | :--- | :--- |
| **Vault (Secrets)** | 8200 | `title:"Vault" port:8200` |
| **Consul (Networking)** | 8500 | `title:"Consul" port:8500` |
| **Nomad (Scheduling)** | 4646 | `title:"Nomad" port:4646` |
| **Terraform State** | 80 | `http.title:"Index of /" http.html:".tfstate"` |
| **Vagrantfile** | 80 | `http.title:"Index of /" http.html:"Vagrantfile"` |
| **Packer Template** | 80 | `http.title:"Index of /" http.html:".pkr.hcl"` |

##  Message Queues & Brokers
> **Critical data pipelines often left open.**

| Service | Port | Query |
| :--- | :--- | :--- |
| **Apache Kafka** | 9092 | `port:9092` |
| **RabbitMQ** | 5672 | `port:5672` |
| **RabbitMQ Mgmt** | 15672 | `port:15672 "RabbitMQ"` |
| **ActiveMQ** | 61616 | `port:61616` |
| **ActiveMQ Web** | 8161 | `port:8161 "ActiveMQ"` |
| **Mosquitto MQTT** | 1883 | `port:1883 -authentication` |
| **NATS Messaging** | 4222 | `port:4222 "nats"` |
| **Redis** | 6379 | `port:6379 -authentication` |
| **Beanstalkd** | 11300 | `port:11300` |
| **ZeroMQ** | 5555 | `port:5555` |

##  Remote Monitoring & Management (RMM)
> **Tools used by MSPs to control fleets of computers.**

| RMM Tool | Query |
| :--- | :--- |
| **Kaseya VSA** | `title:"Kaseya"` |
| **ConnectWise Automate** | `title:"ConnectWise Automate"` |
| **SolarWinds N-central** | `title:"N-central"` |
| **NinjaRMM** | `title:"NinjaRMM"` |
| **MeshCentral** | `title:"MeshCentral"` |
| **Tactical RMM** | `title:"Tactical RMM"` |
| **Action1** | `title:"Action1"` |
| **RustDesk Server** | `title:"RustDesk"` |
| **AnyDesk (TCP)** | `port:7070` |
| **TeamViewer (TCP)** | `port:5938` |


##  CMS Specifics (Web Tech)
> **Targeting specific Content Management Systems.**

| CMS | Query |
| :--- | :--- |
| **WordPress** | `http.component:"WordPress"` |
| **Joomla** | `http.component:"Joomla"` |
| **Drupal** | `http.component:"Drupal"` |
| **Magento** | `http.component:"Magento"` |
| **Ghost** | `http.component:"Ghost"` |
| **Wix** | `http.component:"Wix"` |
| **Squarespace** | `http.component:"Squarespace"` |
| **Shopify** | `http.component:"Shopify"` |
| **PrestaShop** | `http.component:"PrestaShop"` |
| **OpenCart** | `http.component:"OpenCart"` |
| **BigCommerce** | `http.component:"BigCommerce"` |
| **vBulletin** | `http.component:"vBulletin"` |
| **XenForo** | `http.component:"XenForo"` |
| **Moodle** | `http.component:"Moodle"` |

<div align="center">

#  LEGAL DISCLAIMER & WARNING

**PLEASE READ BEFORE USING THIS REPOSITORY**

</div>

> [!CAUTION]
> **ACCESSING COMPUTERS WITHOUT AUTHORIZATION IS A CRIME.**
>
> The search queries ("dorks") contained in this repository are strictly for **Educational Research**, **Authorized Bug Bounty Hunting**, and **Red Team/Pentesting** operations where the user has explicit permission from the target organization.











