package main

import (
	"os"
	"fmt"
	"log"
	"net"
	"time"
	"strings"
	"strconv"
	"math/big"
	mathrand "math/rand"
	"crypto/rand"
	"encoding/hex"
	"encoding/base64"

	"gopkg.in/yaml.v3"
	"github.com/spf13/cobra"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// 常量定义
const (
	// 端口范围常量
	MinRandomPort   = 20000
	MaxPort         = 65535
	RandomPortRange = MaxPort - MinRandomPort + 1

	// 时间间隔常量（毫秒）
	DefaultPacketInterval = 100

	// 默认值常量
	DefaultPort = 0
	DefaultTTL  = 64
)

// Config 配置文件结构
type Config struct {
	Info           InfoItem        `yaml:"info"`
	HTTP           []HTTPPair      `yaml:"-"` // 改为切片以支持多个HTTP块
	DNS            []DNSPair       `yaml:"-"` // 改为切片以支持多个DNS块
	TCP            []TCPPair       `yaml:"-"` // 改为切片以支持多个TCP块
	UDP            []UDPPair       `yaml:"-"` // 改为切片以支持多个UDP块
	ProtocolOrder  []string        `yaml:"-"` // 保存协议在YAML中的出现顺序
	ProtocolBlocks []ProtocolBlock `yaml:"-"` // 保存协议块的详细顺序信息
}

// ProtocolBlock 表示一个协议块，包含协议类型和在该块中的数据索引
type ProtocolBlock struct {
	ProtocolType string // "http", "dns", "tcp", "udp"
	StartIndex   int    // 在对应协议数组中的起始索引
	EndIndex     int    // 在对应协议数组中的结束索引（不包含）
}

type InfoItem struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// UnmarshalYAML 自定义解析info部分的特殊格式
func (info *InfoItem) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.SequenceNode {
		// 处理数组格式: ["name: xxx", "description: xxx"]
		for _, item := range value.Content {
			if item.Kind == yaml.MappingNode {
				var tempMap map[string]string
				if err := item.Decode(&tempMap); err != nil {
					return err
				}
				if name, ok := tempMap["name"]; ok {
					info.Name = name
				}
				if description, ok := tempMap["description"]; ok {
					info.Description = description
				}
			}
		}
	} else if value.Kind == yaml.MappingNode {
		// 处理对象格式: {name: xxx, description: xxx}
		type InfoItemAlias InfoItem
		var alias InfoItemAlias
		if err := value.Decode(&alias); err != nil {
			return err
		}
		*info = InfoItem(alias)
	}
	return nil
}

// IP地址对配置
type IPPair struct {
	SrcIP   string `yaml:"src_ip"`
	SrcPort string `yaml:"src_port"`
	DstIP   string `yaml:"dst_ip"`
	DstPort string `yaml:"dst_port"`
}

// 通用请求结构
type Request struct {
	Format  string `yaml:"format"`
	ReqData string `yaml:"req_data"`
	// DNS特有字段
	ReqType string `yaml:"req_type,omitempty"`
	Domain  string `yaml:"domain,omitempty"`
}

// 通用响应结构
type Response struct {
	Format         string `yaml:"format"`
	RespData       string `yaml:"resp_data"`
	RespStatusCode string `yaml:"resp_status_code,omitempty"` // DNS特有字段
}

// 通用协议数据结构
type ProtocolData struct {
	Description string   `yaml:"description,omitempty"` // 描述此数据块实现的功能
	IPPair      IPPair   `yaml:"ip_pair"`
	Request     Request  `yaml:"request"`
	Response    Response `yaml:"response"`
}

// 数据对结构，用于支持多个请求响应对
type DataPair struct {
	Description string   `yaml:"description,omitempty"` // 描述此数据对实现的功能
	Request     Request  `yaml:"request"`
	Response    Response `yaml:"response"`
}

// TCP数据结构，支持新的data_pair格式
type TCPData struct {
	Description string     `yaml:"description,omitempty"` // 描述此数据块实现的功能
	IPPair      IPPair     `yaml:"ip_pair"`
	DataPair    []DataPair `yaml:"data_pair"` // 支持多个数据对
}

// 各协议对结构
type HTTPPair struct {
	Data []ProtocolData `yaml:"data"`
}

type DNSPair struct {
	Data []ProtocolData `yaml:"data"`
}

type TCPPair struct {
	Data []TCPData `yaml:"data"`
}

type UDPPair struct {
	Data []ProtocolData `yaml:"data"`
}

// PacketGenerator 数据包生成器
type PacketGenerator struct {
	configs         []Config
	writer          *pcapgo.Writer
	globalTimestamp time.Time // 全局时间戳管理
}

// 全局变量
var (
	configFile string
	outputFile string
	verbose    bool
)

// 主命令
var rootCmd = &cobra.Command{
	Use:   "text2pcap",
	Short: "将配置文件转换为PCAP格式的网络数据包生成工具",
	Long: `Text2PCAP是一个基于配置文件的网络数据包生成工具，
能够将文本配置转换为标准的PCAP格式文件。
支持HTTP、DNS、TCP、UDP协议的数据包构造和生成。`,
	Run: func(cmd *cobra.Command, args []string) {
		// 检查配置文件参数是否为空
		if configFile == "" {
			cmd.Help()
			return
		}

		if err := generatePCAP(); err != nil {
			log.Fatalf("生成PCAP文件失败: %v", err)
		}
	},
}

func init() {
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "", "YAML配置文件路径")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "输出PCAP文件路径（不设置则默认自动生成）")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "详细输出模式")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// generatePCAP 生成PCAP文件的主函数
func generatePCAP() error {
	if verbose {
		log.Printf("开始读取配置文件: %s", configFile)
	}

	// 读取配置文件
	configs, err := loadConfig(configFile)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	if verbose {
		log.Printf("成功读取 %d 个配置项", len(configs))
	}

	// 如果没有指定输出文件名，则自动生成
	if outputFile == "" {
		var err error
		outputFile, err = generateDefaultFilename(configs[0])
		if err != nil {
			return fmt.Errorf("生成默认输出文件名失败: %v", err)
		}
		if verbose {
			log.Printf("自动生成输出文件名: %s", outputFile)
		}
	}

	// 创建输出文件
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %v", err)
	}
	defer file.Close()

	// 创建PCAP写入器
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return fmt.Errorf("写入PCAP文件头失败: %v", err)
	}

	// 创建数据包生成器
	generator := &PacketGenerator{
		configs: configs,
		writer:  writer,
	}

	// 生成数据包
	if err := generator.generatePackets(); err != nil {
		return fmt.Errorf("生成数据包失败: %v", err)
	}

	if verbose {
		log.Printf("PCAP文件生成完成: %s", outputFile)
	}

	return nil
}

// loadConfig 加载配置文件
func loadConfig(filename string) ([]Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// 首先解析YAML节点来获取协议顺序
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("解析YAML节点失败: %v", err)
	}

	// 使用自定义解析来处理重复的协议键
	config, err := parseConfigWithDuplicateKeys(&node)
	if err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 获取协议在YAML中的出现顺序
	config.ProtocolOrder = extractProtocolOrder(&node)

	// 验证配置
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("配置验证失败: %v", err)
	}

	return []Config{config}, nil
}

// parseConfigWithDuplicateKeys 解析包含重复协议键的YAML配置
func parseConfigWithDuplicateKeys(node *yaml.Node) (Config, error) {
	var config Config

	// 遍历根节点的内容
	if node.Kind != yaml.DocumentNode || len(node.Content) == 0 {
		return config, fmt.Errorf("无效的YAML文档结构")
	}

	mappingNode := node.Content[0]
	if mappingNode.Kind != yaml.MappingNode {
		return config, fmt.Errorf("根节点不是映射类型")
	}

	// 用于记录协议块的顺序
	var protocolBlocks []ProtocolBlock

	// 遍历所有键值对
	for i := 0; i < len(mappingNode.Content); i += 2 {
		keyNode := mappingNode.Content[i]
		valueNode := mappingNode.Content[i+1]

		switch keyNode.Value {
		case "info":
			if err := valueNode.Decode(&config.Info); err != nil {
				return config, fmt.Errorf("解析info失败: %v", err)
			}
		case "http":
			var httpPair HTTPPair
			if err := valueNode.Decode(&httpPair); err != nil {
				return config, fmt.Errorf("解析http失败: %v", err)
			}
			// 计算在HTTP切片中的索引
			startIndex := len(config.HTTP)
			config.HTTP = append(config.HTTP, httpPair)
			protocolBlocks = append(protocolBlocks, ProtocolBlock{
				ProtocolType: "http",
				StartIndex:   startIndex,
				EndIndex:     startIndex + 1,
			})
		case "dns":
			var dnsPair DNSPair
			if err := valueNode.Decode(&dnsPair); err != nil {
				return config, fmt.Errorf("解析dns失败: %v", err)
			}
			// 计算在DNS切片中的索引
			startIndex := len(config.DNS)
			config.DNS = append(config.DNS, dnsPair)
			protocolBlocks = append(protocolBlocks, ProtocolBlock{
				ProtocolType: "dns",
				StartIndex:   startIndex,
				EndIndex:     startIndex + 1,
			})
		case "tcp":
			var tcpPair TCPPair
			if err := valueNode.Decode(&tcpPair); err != nil {
				return config, fmt.Errorf("解析tcp失败: %v", err)
			}
			// 计算在TCP切片中的索引
			startIndex := len(config.TCP)
			config.TCP = append(config.TCP, tcpPair)
			protocolBlocks = append(protocolBlocks, ProtocolBlock{
				ProtocolType: "tcp",
				StartIndex:   startIndex,
				EndIndex:     startIndex + 1,
			})
		case "udp":
			var udpPair UDPPair
			if err := valueNode.Decode(&udpPair); err != nil {
				return config, fmt.Errorf("解析udp失败: %v", err)
			}
			// 计算在UDP切片中的索引
			startIndex := len(config.UDP)
			config.UDP = append(config.UDP, udpPair)
			protocolBlocks = append(protocolBlocks, ProtocolBlock{
				ProtocolType: "udp",
				StartIndex:   startIndex,
				EndIndex:     startIndex + 1,
			})
		}
	}

	// 将收集的数据赋值给配置
	config.ProtocolBlocks = protocolBlocks

	return config, nil
}

// extractProtocolOrder 从YAML节点中提取协议的出现顺序
func extractProtocolOrder(node *yaml.Node) []string {
	var order []string
	protocols := []string{"http", "dns", "tcp", "udp"}

	// 遍历文档节点
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		mapNode := node.Content[0]
		if mapNode.Kind == yaml.MappingNode {
			// 遍历映射节点的键值对
			for i := 0; i < len(mapNode.Content); i += 2 {
				keyNode := mapNode.Content[i]
				if keyNode.Kind == yaml.ScalarNode {
					key := keyNode.Value
					// 检查是否是协议键
					for _, protocol := range protocols {
						if key == protocol {
							order = append(order, protocol)
							break
						}
					}
				}
			}
		}
	}

	return order
}

// validateConfig 验证配置参数
func validateConfig(config *Config) error {
	// 验证info字段中的name必须设置
	if config.Info.Name == "" {
		return fmt.Errorf("配置文件中info字段的name必须设置")
	}

	// 验证至少有一种协议配置
	if len(config.HTTP) == 0 && len(config.DNS) == 0 && len(config.TCP) == 0 && len(config.UDP) == 0 {
		return fmt.Errorf("配置文件中必须包含至少一种协议的配置")
	}

	// 统一验证所有协议的IP对
	for i, httpPair := range config.HTTP {
		if err := validateProtocolData(httpPair.Data, fmt.Sprintf("HTTP[%d]", i)); err != nil {
			return err
		}
	}
	for i, dnsPair := range config.DNS {
		if err := validateProtocolData(dnsPair.Data, fmt.Sprintf("DNS[%d]", i)); err != nil {
			return err
		}
	}
	for i, udpPair := range config.UDP {
		if err := validateProtocolData(udpPair.Data, fmt.Sprintf("UDP[%d]", i)); err != nil {
			return err
		}
	}

	// 单独验证TCP，因为其数据结构不同
	for i, tcpPair := range config.TCP {
		for j, tcpData := range tcpPair.Data {
			if err := validateIPPair(tcpData.IPPair, fmt.Sprintf("TCP[%d]", i), j); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateProtocolData 验证通用协议数据切片
func validateProtocolData(data []ProtocolData, protocolName string) error {
	for i, d := range data {
		if err := validateIPPair(d.IPPair, protocolName, i); err != nil {
			return err
		}
	}
	return nil
}

// validateIPAddress 验证IP地址
func validateIPAddress(ip, fieldName, protocolName string, index int) error {
	if strings.TrimSpace(ip) == "" {
		return fmt.Errorf("%s协议第%d个配置的%s不能为空", protocolName, index+1, fieldName)
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("%s协议第%d个配置的%s格式无效: %s", protocolName, index+1, fieldName, ip)
	}
	return nil
}

// validatePort 验证端口
func validatePort(portStr, fieldName, protocolName string, index int) error {
	if strings.TrimSpace(portStr) == "" {
		return fmt.Errorf("%s协议第%d个配置的%s不能为空", protocolName, index+1, fieldName)
	}
	if portStr != "RANDOM" {
		if port, err := strconv.Atoi(portStr); err != nil || port < 0 || port > MaxPort {
			return fmt.Errorf("%s协议第%d个配置的%s无效: %s (范围0-%d或RANDOM)", protocolName, index+1, fieldName, portStr, MaxPort)
		}
	}
	return nil
}

// validateIPPair 验证IP地址和端口配置
func validateIPPair(ipPair IPPair, protocolName string, index int) error {
	if err := validateIPAddress(ipPair.SrcIP, "源IP地址", protocolName, index); err != nil {
		return err
	}
	if err := validateIPAddress(ipPair.DstIP, "目的IP地址", protocolName, index); err != nil {
		return err
	}
	if err := validatePort(ipPair.SrcPort, "源端口", protocolName, index); err != nil {
		return err
	}
	if err := validatePort(ipPair.DstPort, "目的端口", protocolName, index); err != nil {
		return err
	}
	return nil
}

// generatePackets 生成数据包
func (pg *PacketGenerator) generatePackets() error {

	for i, config := range pg.configs {
		// 为每个配置重置时间戳，确保pcap文件的时间戳从当前时间开始
		pg.globalTimestamp = time.Now()

		var configName string
		if config.Info.Name != "" {
			configName = config.Info.Name
		}
		if configName == "" {
			configName = "未命名配置"
		}

		if verbose {
			log.Printf("处理配置 %d: %s", i+1, configName)
		}

		// 按照配置文件中协议出现的顺序处理
		if err := pg.processProtocolsInOrder(config); err != nil {
			return err
		}
	}

	return nil
}

// processProtocolsInOrder 按照配置文件中协议出现的顺序处理协议
func (pg *PacketGenerator) processProtocolsInOrder(config Config) error {
	// 如果有ProtocolBlocks信息，使用精确的顺序处理
	if len(config.ProtocolBlocks) > 0 {
		return pg.processProtocolBlocksInOrder(config)
	}

	// 否则使用原有的协议顺序处理逻辑
	protocolOrder := pg.getProtocolOrder(config)

	protocolsProcessed := 0

	for _, protocolType := range protocolOrder {
		if protocolsProcessed > 0 {
			if verbose {
				log.Printf("等待3秒后处理下一个协议...")
			}
			time.Sleep(3 * time.Second)
		}

		switch protocolType {

		}

		protocolsProcessed++
	}

	return nil
}

// getProtocolOrder 获取协议在配置文件中的出现顺序
// processProtocolBlocksInOrder 按照ProtocolBlocks的精确顺序处理协议
func (pg *PacketGenerator) processProtocolBlocksInOrder(config Config) error {
	for i, block := range config.ProtocolBlocks {
		if verbose {
			log.Printf("开始处理协议块 %d/%d: %s", i+1, len(config.ProtocolBlocks), block.ProtocolType)
		}
		switch block.ProtocolType {
		case "http":
			if verbose {
				log.Printf("生成HTTP数据包块，协议块索引[%d]", block.StartIndex)
			}
			if block.StartIndex >= len(config.HTTP) {
				return fmt.Errorf("HTTP协议块索引无效: %d, 总块数: %d", block.StartIndex, len(config.HTTP))
			}
			// 获取对应的HTTP协议块
			httpPair := config.HTTP[block.StartIndex]
			if err := pg.generateTCPBasedProtocolPackets(httpPair.Data); err != nil {
				return err
			}
		case "dns":
			if verbose {
				log.Printf("生成DNS数据包块，协议块索引[%d]", block.StartIndex)
			}
			if block.StartIndex >= len(config.DNS) {
				return fmt.Errorf("DNS协议块索引无效: %d, 总块数: %d", block.StartIndex, len(config.DNS))
			}
			// 获取对应的DNS协议块
			dnsPair := config.DNS[block.StartIndex]
			if err := pg.generateDNSBasedProtocolPackets(dnsPair.Data, "DNS"); err != nil {
				return err
			}
		case "tcp":
			if verbose {
				log.Printf("生成TCP数据包块，协议块索引[%d]", block.StartIndex)
			}
			if block.StartIndex >= len(config.TCP) {
				return fmt.Errorf("TCP协议块索引无效: %d, 总块数: %d", block.StartIndex, len(config.TCP))
			}
			// 获取对应的TCP协议块
			tcpPair := config.TCP[block.StartIndex]

			// 处理TCP数据
			if len(tcpPair.Data) > 0 {
				if verbose {
					log.Printf("[DEBUG] 处理TCP数据，共 %d 项", len(tcpPair.Data))
				}
				for j, tcpData := range tcpPair.Data {
					if verbose {
						log.Printf("[DEBUG] 处理TCP数据项 %d: %s, 数据对数量: %d", j, tcpData.Description, len(tcpData.DataPair))
					}
					if err := pg.generateTCPDataPackets(tcpData); err != nil {
						return err
					}
				}
			}
		case "udp":
			if verbose {
				log.Printf("生成UDP数据包块，协议块索引[%d]", block.StartIndex)
			}
			if block.StartIndex >= len(config.UDP) {
				return fmt.Errorf("UDP协议块索引无效: %d, 总块数: %d", block.StartIndex, len(config.UDP))
			}
			// 获取对应的UDP协议块
			udpPair := config.UDP[block.StartIndex]
			if err := pg.generateUDPBasedProtocolPackets(udpPair.Data, "UDP"); err != nil {
				return err
			}
		}
	}

	return nil
}

func (pg *PacketGenerator) getProtocolOrder(config Config) []string {
	var order []string

	// 使用从YAML中提取的协议顺序，只包含实际存在数据的协议
	for _, protocol := range config.ProtocolOrder {
		switch protocol {
		case "http":
			if len(config.HTTP) > 0 {
				order = append(order, protocol)
			}
		case "dns":
			if len(config.DNS) > 0 {
				order = append(order, protocol)
			}
		case "tcp":
			if len(config.TCP) > 0 {
				order = append(order, protocol)
			}
		case "udp":
			if len(config.UDP) > 0 {
				order = append(order, protocol)
			}
		}
	}

	return order
}

// formatProtocolError 格式化协议错误信息的通用函数
func formatProtocolError(protocolName string, operation string, index int, err error) error {
	return fmt.Errorf("%s%s失败 (第%d个): %v", operation, protocolName, index+1, err)
}

// parseIPAndPorts 解析IP地址和端口的通用函数
func parseIPAndPorts(ipPair IPPair) (srcIP, dstIP net.IP, srcPort, dstPort uint16, err error) {
	// 解析IP地址
	srcIP = net.ParseIP(ipPair.SrcIP)
	dstIP = net.ParseIP(ipPair.DstIP)
	if srcIP == nil || dstIP == nil {
		err = fmt.Errorf("无效的IP地址: src=%s, dst=%s", ipPair.SrcIP, ipPair.DstIP)
		return
	}

	// 解析端口
	srcPort = parsePort(ipPair.SrcPort, true)
	dstPort = parsePort(ipPair.DstPort, false)
	return
}

// sameIPPair 检查两个IP对是否相同
func sameIPPair(ip1, ip2 IPPair) bool {
	return ip1.SrcIP == ip2.SrcIP && ip1.DstIP == ip2.DstIP && ip1.SrcPort == ip2.SrcPort && ip1.DstPort == ip2.DstPort
}

// generateRandomPort 生成随机端口
func generateRandomPort(isSourcePort bool) uint16 {
	if isSourcePort {
		// 源端口范围: 25000-65000
		return uint16(mathrand.Intn(40001) + 25000)
	} else {
		// 目的端口范围: 20-10000
		return uint16(mathrand.Intn(9981) + 20)
	}
}

// parsePort 解析端口配置
func parsePort(portStr string, isSourcePort bool) uint16 {
	if portStr == "RANDOM" {
		return generateRandomPort(isSourcePort)
	}

	// 解析具体端口号
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > MaxPort {
		return DefaultPort // 返回默认端口
	}

	return uint16(port)
}

// generateDefaultFilename 生成默认的输出文件名
func generateDefaultFilename(config Config) (string, error) {
	// 生成时间戳（格式：yyyyMMddHHmmss）
	timestamp := time.Now().Format("20060102150405")

	// 统一使用info.name字段_时间.pcap格式
	var name string
	if config.Info.Name != "" {
		name = config.Info.Name
	} else {
		// 如果没有name字段，使用默认名称
		name = "generated_pcap"
	}

	return fmt.Sprintf("%s_%s.pcap", name, timestamp), nil
}
// isHTTPRequest 判断HTTP数据是请求还是响应
// HTTP请求的第一行格式：METHOD PATH HTTP/VERSION
// HTTP响应的第一行格式：HTTP/VERSION STATUS_CODE STATUS_TEXT
func isHTTPRequest(httpData string) bool {
	headerLines := strings.Split(httpData, "\r\n")
	if len(headerLines) == 0 {
		return false
	}
	
	firstLine := strings.TrimSpace(headerLines[0])
	if firstLine == "" {
		return false
	}
	
	// HTTP响应以"HTTP/"开头
	if strings.HasPrefix(firstLine, "HTTP/") {
		return false
	}
	
	// HTTP请求的第一行应该包含HTTP方法
	parts := strings.Fields(firstLine)
	if len(parts) >= 3 && strings.HasPrefix(parts[2], "HTTP/") {
		return true
	}
	
	return false
}
// updateHostHeader 更新HTTP请求头中的Host字段
// isIPAddress 检查字符串是否为有效的IP地址
func isIPAddress(host string) bool {
	// 移除端口号（如果存在）
	if colonIndex := strings.LastIndex(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}
	return net.ParseIP(host) != nil
}

func updateHostHeader(httpData string, ipPair IPPair) string {
	// 分离HTTP头部和消息体
	headerBodySeparator := "\r\n\r\n"
	parts := strings.SplitN(httpData, headerBodySeparator, 2)
	if len(parts) < 1 {
		return httpData // 不是有效的HTTP请求
	}

	headers := parts[0]
	body := ""
	if len(parts) > 1 {
		body = parts[1]
	}

	// 根据端口确定Host头的值
	hostValue := ipPair.DstIP
	if ipPair.DstPort != "80" {
		hostValue = fmt.Sprintf("%s:%s", ipPair.DstIP, ipPair.DstPort)
	}

	headerLines := strings.Split(headers, "\r\n")
	hostHeaderFound := false
	for i, line := range headerLines {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			// 提取现有的Host值
			existingHost := strings.TrimSpace(line[5:]) // 移除"host:"前缀
			// 只有当现有Host为IP地址时才进行修改
			if isIPAddress(existingHost) {
				headerLines[i] = fmt.Sprintf("Host: %s", hostValue)
			}
			hostHeaderFound = true
			break
		}
	}

	if !hostHeaderFound {
		// 如果没有Host头，则在请求行下添加一个
		firstLine := headerLines[0]
		newHeaders := []string{firstLine, fmt.Sprintf("Host: %s", hostValue)}
		newHeaders = append(newHeaders, headerLines[1:]...)
		headerLines = newHeaders
	}

	newHeaderStr := strings.Join(headerLines, "\r\n")
	if body != "" {
		return newHeaderStr + headerBodySeparator + body
	} else {
		return newHeaderStr
	}
}

// decodePayload 解码载荷数据
func decodePayload(format, data string, ipPair IPPair, protocolType string) ([]byte, error) {
	switch strings.ToLower(format) {
	case "hex":
		// 移除十六进制字符串中的所有非十六进制字符
		cleanedData := removeNonHexChars(data)
		decodedData, err := hex.DecodeString(cleanedData)
		if err != nil {
			return nil, err
		}
		decodedStr := string(decodedData)
		// 只有HTTP协议才进行TrimSpace操作
		if protocolType == "http" {
			decodedStr = strings.TrimSpace(decodedStr)
		}
		if strings.Contains(decodedStr, "HTTP/") {
			decodedStr = strings.ReplaceAll(decodedStr, "\r\n", "\n")
			decodedStr = strings.ReplaceAll(decodedStr, "\n", "\r\n")
			// 只对HTTP请求更新Host头，不对HTTP响应处理
			if isHTTPRequest(decodedStr) {
				decodedStr = updateHostHeader(decodedStr, ipPair)
			}
			decodedStr = fixHTTPContentLength(decodedStr)
			decodedStr = removeHTTPHeaders(decodedStr, []string{"Date", "Transfer-Encoding"})
		}
		return []byte(decodedStr), nil
	case "base64":
		decodedData, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, err
		}
		// 将解码后的数据转换为字符串进行HTTP协议处理
		decodedStr := string(decodedData)
		// 只有HTTP协议才进行TrimSpace操作
		if protocolType == "http" {
			decodedStr = strings.TrimSpace(decodedStr)
		}
		// 对于HTTP数据，需要将LF转换为CRLF以符合HTTP协议标准
		if strings.Contains(decodedStr, "HTTP/") {
			// 检测是否为HTTP数据，如果是则转换换行符并修正Content-Length
			decodedStr = strings.ReplaceAll(decodedStr, "\r\n", "\n") // 先统一为LF
			decodedStr = strings.ReplaceAll(decodedStr, "\n", "\r\n") // 再转换为CRLF
			/// 只对HTTP请求更新Host头，不对HTTP响应处理
			if isHTTPRequest(decodedStr) {
				decodedStr = updateHostHeader(decodedStr, ipPair)
			}
			// 自动修正Content-Length
			decodedStr = fixHTTPContentLength(decodedStr)
			// 移除Date头和Transfer-Encoding头
			decodedStr = removeHTTPHeaders(decodedStr, []string{"Date", "Transfer-Encoding"})
		}
		return []byte(decodedStr), nil
	case "plain":
		// 只有HTTP协议才进行TrimSpace操作
		if protocolType == "http" {
			data = strings.TrimSpace(data)
		}
		// 对于HTTP数据，需要将LF转换为CRLF以符合HTTP协议标准
		if strings.Contains(data, "HTTP/") {
			// 检测是否为HTTP数据，如果是则转换换行符并修正Content-Length
			data = strings.ReplaceAll(data, "\r\n", "\n") // 先统一为LF
			data = strings.ReplaceAll(data, "\n", "\r\n") // 再转换为CRLF
			// 只对HTTP请求更新Host头，不对HTTP响应处理
			if isHTTPRequest(data) {
				data = updateHostHeader(data, ipPair)
			}
			// 自动修正Content-Length
			data = fixHTTPContentLength(data)
			// 移除Date头和Transfer-Encoding头
			data = removeHTTPHeaders(data, []string{"Date", "Transfer-Encoding"})
		}
		return []byte(data), nil
	default:
		return nil, fmt.Errorf("unsupported format: %s, only 'plain', 'base64' and 'hex' are supported", format)
	}
}

// removeNonHexChars 移除字符串中的非十六进制字符
func removeNonHexChars(s string) string {
	var builder strings.Builder
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

// removeHTTPHeaders 移除HTTP响应中的指定头部
func removeHTTPHeaders(httpData string, headersToRemove []string) string {
	headerBodySeparator := "\r\n\r\n"
	parts := strings.SplitN(httpData, headerBodySeparator, 2)
	if len(parts) < 1 {
		return httpData
	}

	headers := parts[0]
	body := ""
	if len(parts) > 1 {
		body = parts[1]
	}

	lines := strings.Split(headers, "\r\n")
	var newLines []string
	for _, line := range lines {
		remove := false
		for _, header := range headersToRemove {
			if strings.HasPrefix(strings.ToLower(line), strings.ToLower(header)+":") {
				remove = true
				break
			}
		}
		if !remove {
			newLines = append(newLines, line)
		}
	}

	newHeaders := strings.Join(newLines, "\r\n")
	if body != "" {
		return newHeaders + headerBodySeparator + body
	} else {
		return newHeaders
	}
}

// fixHTTPContentLength 根据HTTP方法处理Content-Length头部
// POST和PUT请求：重新计算Content-Length
// 其他请求：移除Content-Length头部
func fixHTTPContentLength(httpData string) string {
	// 分离HTTP头部和消息体
	headerBodySeparator := "\r\n\r\n"
	parts := strings.SplitN(httpData, headerBodySeparator, 2)
	if len(parts) != 2 {
		// 如果没有找到头部和消息体的分隔符，假设只有头部没有消息体
		// 这种情况下，我们仍然需要处理Content-Length头部
		headers := httpData
		body := ""

		// 解析HTTP请求行获取方法
		headerLines := strings.Split(headers, "\r\n")
		if len(headerLines) == 0 {
			return httpData
		}

		// 获取HTTP方法（请求行的第一个单词）
		requestLine := headerLines[0]
		requestParts := strings.Fields(requestLine)
		if len(requestParts) == 0 {
			return httpData
		}

		httpMethod := strings.ToUpper(requestParts[0])

		// 根据HTTP方法处理Content-Length头部
		var updatedHeaderLines []string
		contentLengthFound := false

		for _, line := range headerLines {
			if strings.HasPrefix(strings.ToLower(line), "content-length:") {
				contentLengthFound = true
				// 对于POST和PUT请求，重新计算Content-Length
				if httpMethod == "POST" || httpMethod == "PUT" {
					actualContentLength := len([]byte(body))
					updatedHeaderLines = append(updatedHeaderLines, fmt.Sprintf("Content-Length: %d", actualContentLength))
				}
				// 对于其他方法，跳过此行（移除Content-Length）
			} else {
				updatedHeaderLines = append(updatedHeaderLines, line)
			}
		}

		// 如果POST或PUT请求没有Content-Length头部，则添加一个
		if !contentLengthFound && (httpMethod == "POST" || httpMethod == "PUT") {
			actualContentLength := len([]byte(body))
			updatedHeaderLines = append(updatedHeaderLines, fmt.Sprintf("Content-Length: %d", actualContentLength))
		}

		// 重新组装HTTP消息（只有头部）
		return strings.Join(updatedHeaderLines, "\r\n")
	}

	headers := parts[0]
	body := parts[1]

	// 解析HTTP请求行获取方法
	headerLines := strings.Split(headers, "\r\n")
	if len(headerLines) == 0 {
		return httpData
	}

	// 获取HTTP方法（请求行的第一个单词）
	requestLine := headerLines[0]
	requestParts := strings.Fields(requestLine)
	if len(requestParts) == 0 {
		return httpData
	}

	httpMethod := strings.ToUpper(requestParts[0])

	// 根据HTTP方法处理Content-Length头部
	var updatedHeaderLines []string
	contentLengthFound := false

	for _, line := range headerLines {
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			contentLengthFound = true
			// 对于POST和PUT请求，重新计算Content-Length
			if httpMethod == "POST" || httpMethod == "PUT" {
				actualContentLength := len([]byte(body))
				updatedHeaderLines = append(updatedHeaderLines, fmt.Sprintf("Content-Length: %d", actualContentLength))
			}
			// 对于其他方法，跳过此行（移除Content-Length）
		} else {
			updatedHeaderLines = append(updatedHeaderLines, line)
		}
	}

	// 如果POST或PUT请求没有Content-Length头部，则添加一个
	if !contentLengthFound && (httpMethod == "POST" || httpMethod == "PUT") {
		actualContentLength := len([]byte(body))
		updatedHeaderLines = append(updatedHeaderLines, fmt.Sprintf("Content-Length: %d", actualContentLength))
	}

	// 重新组装HTTP消息
	updatedHeaders := strings.Join(updatedHeaderLines, "\r\n")
	return updatedHeaders + headerBodySeparator + body
}

// TCPState TCP连接状态跟踪
type TCPState struct {
	clientSeq uint32
	serverSeq uint32
	timestamp time.Time
}

// generateRandomISN 生成随机初始序列号
func generateRandomISN() uint32 {
	n, err := rand.Int(rand.Reader, big.NewInt(0xffffffff))
	if err != nil {
		// 如果加密随机数生成失败，使用数学随机数
		mathrand.Seed(time.Now().UnixNano())
		return mathrand.Uint32()
	}
	return uint32(n.Uint64())
}

// generateRandomMAC 生成随机MAC地址
func generateRandomMAC() net.HardwareAddr {
	mac := make([]byte, 6)
	_, err := rand.Read(mac)
	if err != nil {
		// 如果随机生成失败，使用固定MAC
		return net.HardwareAddr{0x00, 0x0c, 0x29, 0x12, 0x34, 0x56}
	}
	// 设置本地管理位，清除组播位
	mac[0] = (mac[0] & 0xfe) | 0x02
	return net.HardwareAddr(mac)
}

// getNextTimestamp 获取下一个时间戳，确保时间戳连续递增
func (pg *PacketGenerator) getNextTimestamp() time.Time {
	pg.globalTimestamp = pg.globalTimestamp.Add(DefaultPacketInterval * time.Millisecond)
	return pg.globalTimestamp
}

// generateTCPHandshakeWithState 生成TCP三次握手（带状态跟踪）
func (pg *PacketGenerator) generateTCPHandshakeWithState(srcIP, dstIP net.IP, srcPort, dstPort uint16, state *TCPState) error {
	// SYN包
	synPacket := pg.createTCPPacketWithTimestamp(srcIP, dstIP, srcPort, dstPort, state.clientSeq, 0, true, false, false, nil, state)
	if err := pg.writePacket(synPacket); err != nil {
		return err
	}
	state.clientSeq++ // SYN消耗一个序列号

	// SYN-ACK包
	state.timestamp = pg.getNextTimestamp() // 更新时间戳确保连续性
	synAckPacket := pg.createTCPPacketWithTimestamp(dstIP, srcIP, dstPort, srcPort, state.serverSeq, state.clientSeq, true, true, false, nil, state)
	if err := pg.writePacket(synAckPacket); err != nil {
		return err
	}
	state.serverSeq++ // SYN消耗一个序列号

	// ACK包
	state.timestamp = pg.getNextTimestamp() // 更新时间戳确保连续性
	ackPacket := pg.createTCPPacketWithTimestamp(srcIP, dstIP, srcPort, dstPort, state.clientSeq, state.serverSeq, false, true, false, nil, state)
	if err := pg.writePacket(ackPacket); err != nil {
		return err
	}

	return nil
}

// generateTCPDataPacketWithState 生成TCP数据包（带状态跟踪）
func (pg *PacketGenerator) generateTCPDataPacketWithState(srcIP, dstIP net.IP, srcPort, dstPort uint16, data []byte, state *TCPState, isRequest bool) error {
	var seq, ack uint32

	if isRequest {
		// 客户端发送数据
		seq = state.clientSeq
		ack = state.serverSeq
		state.clientSeq += uint32(len(data)) // 更新客户端序列号
	} else {
		// 服务端发送数据
		seq = state.serverSeq
		ack = state.clientSeq
		state.serverSeq += uint32(len(data)) // 更新服务端序列号
	}

	// 更新时间戳确保连续性
	state.timestamp = pg.getNextTimestamp()
	dataPacket := pg.createTCPPacketWithTimestamp(srcIP, dstIP, srcPort, dstPort, seq, ack, false, true, false, data, state)
	return pg.writePacket(dataPacket)
}

// generateTCPBasedProtocolPackets 生成基于TCP的协议数据包（HTTP、TCP）
func (pg *PacketGenerator) generateTCPBasedProtocolPackets(pairs []ProtocolData) error {

	for i, pair := range pairs {
		// 解析IP地址和端口
		srcIP, dstIP, srcPort, dstPort, err := parseIPAndPorts(pair.IPPair)
		if err != nil {
			return fmt.Errorf("TCP %v", err)
		}

		// 初始化TCP状态
		tcpState := &TCPState{
			clientSeq: generateRandomISN(),
			serverSeq: generateRandomISN(),
			timestamp: pg.getNextTimestamp(),
		}

		// 生成TCP三次握手
		if err := pg.generateTCPHandshakeWithState(srcIP, dstIP, srcPort, dstPort, tcpState); err != nil {
			return err
		}

		// 处理请求
		if pair.Request.ReqData != "" {
			reqData, err := decodePayload(pair.Request.Format, pair.Request.ReqData, pair.IPPair, "http")
			if err != nil {
				return formatProtocolError("TCP", "解码", i, fmt.Errorf("请求数据: %v", err))
			}
			if len(reqData) > 0 {
				// 客户端发送请求数据
				if err := pg.generateTCPDataPacketWithState(srcIP, dstIP, srcPort, dstPort, reqData, tcpState, true); err != nil {
					return err
				}

				// 服务器确认请求
				tcpState.timestamp = pg.getNextTimestamp() // 更新时间戳确保连续性
				serverAckPacket := pg.createTCPPacketWithTimestamp(dstIP, srcIP, dstPort, srcPort, tcpState.serverSeq, tcpState.clientSeq, false, true, false, nil, tcpState)
				if err := pg.writePacket(serverAckPacket); err != nil {
					return err
				}
			}
		}

		// 处理响应
		if pair.Response.RespData != "" {
			respData, err := decodePayload(pair.Response.Format, pair.Response.RespData, pair.IPPair, "http")
			if err != nil {
				return formatProtocolError("TCP", "解码", i, fmt.Errorf("响应数据: %v", err))
			}
			if len(respData) > 0 {
				// 服务器发送响应数据
				if err := pg.generateTCPDataPacketWithState(dstIP, srcIP, dstPort, srcPort, respData, tcpState, false); err != nil {
					return err
				}

				// 客户端确认响应
				tcpState.timestamp = pg.getNextTimestamp() // 更新时间戳确保连续性
				clientAckPacket := pg.createTCPPacketWithTimestamp(srcIP, dstIP, srcPort, dstPort, tcpState.clientSeq, tcpState.serverSeq, false, true, false, nil, tcpState)
				if err := pg.writePacket(clientAckPacket); err != nil {
					return err
				}
			}
		}

		// 生成TCP连接关闭
		if err := pg.generateTCPCloseWithState(srcIP, dstIP, srcPort, dstPort, tcpState); err != nil {
			return err
		}
	}
	return nil
}

// generateTCPCloseWithState 生成TCP连接关闭（带状态跟踪）- 标准四次挥手
func (pg *PacketGenerator) generateTCPCloseWithState(srcIP, dstIP net.IP, srcPort, dstPort uint16, state *TCPState) error {
	// 第一步：客户端发送FIN+ACK包
	state.timestamp = pg.getNextTimestamp()
	finPacket := pg.createTCPPacketWithTimestamp(srcIP, dstIP, srcPort, dstPort, state.clientSeq, state.serverSeq, false, true, true, nil, state)
	if err := pg.writePacket(finPacket); err != nil {
		return err
	}
	state.clientSeq++ // FIN消耗一个序列号

	// 第二步：服务端发送ACK包确认客户端的FIN
	state.timestamp = pg.getNextTimestamp()
	finAckPacket := pg.createTCPPacketWithTimestamp(dstIP, srcIP, dstPort, srcPort, state.serverSeq, state.clientSeq, false, true, false, nil, state)
	if err := pg.writePacket(finAckPacket); err != nil {
		return err
	}

	// 第三步：服务端发送FIN+ACK包
	state.timestamp = pg.getNextTimestamp()
	serverFinPacket := pg.createTCPPacketWithTimestamp(dstIP, srcIP, dstPort, srcPort, state.serverSeq, state.clientSeq, false, true, true, nil, state)
	if err := pg.writePacket(serverFinPacket); err != nil {
		return err
	}
	state.serverSeq++ // FIN消耗一个序列号

	// 第四步：客户端发送最终ACK包
	state.timestamp = pg.getNextTimestamp()
	finalAckPacket := pg.createTCPPacketWithTimestamp(srcIP, dstIP, srcPort, dstPort, state.clientSeq, state.serverSeq, false, true, false, nil, state)
	return pg.writePacket(finalAckPacket)
}

// generateTCPDataPackets 处理新格式的TCP数据（包含多个data_pair）
func (pg *PacketGenerator) generateTCPDataPackets(tcpData TCPData) error {
	if len(tcpData.DataPair) == 0 {
		return nil
	}

	// 使用IP信息作为连接信息
	srcIP, dstIP, srcPort, dstPort, err := parseIPAndPorts(tcpData.IPPair)
	if err != nil {
		return fmt.Errorf("解析IP和端口失败: %v", err)
	}

	// 初始化TCP状态
	tcpState := &TCPState{
		clientSeq: generateRandomISN(),
		serverSeq: generateRandomISN(),
		timestamp: pg.getNextTimestamp(),
	}

	// 生成三次握手
	if err := pg.generateTCPHandshakeWithState(srcIP, dstIP, srcPort, dstPort, tcpState); err != nil {
		return err
	}

	// 处理所有data_pair，使用同一条流
	for _, dataPair := range tcpData.DataPair {
		// 解码请求数据
		reqData, err := decodePayload(dataPair.Request.Format, dataPair.Request.ReqData, tcpData.IPPair, "tcp")
		if err != nil {
			return fmt.Errorf("解码请求数据失败: %v", err)
		}

		// 发送请求数据
		if len(reqData) > 0 {
			if err := pg.generateTCPDataPacketWithState(srcIP, dstIP, srcPort, dstPort, reqData, tcpState, true); err != nil {
				return err
			}

			// 服务器确认请求
			serverAckPacket := pg.createTCPPacketWithTimestamp(dstIP, srcIP, dstPort, srcPort, tcpState.serverSeq, tcpState.clientSeq, false, true, false, nil, tcpState)
			if err := pg.writePacket(serverAckPacket); err != nil {
				return err
			}
		}

		// 解码响应数据
		respData, err := decodePayload(dataPair.Response.Format, dataPair.Response.RespData, tcpData.IPPair, "tcp")
		if err != nil {
			return fmt.Errorf("解码响应数据失败: %v", err)
		}

		// 发送响应数据
		if len(respData) > 0 {
			if err := pg.generateTCPDataPacketWithState(dstIP, srcIP, dstPort, srcPort, respData, tcpState, false); err != nil {
				return err
			}

			// 客户端确认响应
			clientAckPacket := pg.createTCPPacketWithTimestamp(srcIP, dstIP, srcPort, dstPort, tcpState.clientSeq, tcpState.serverSeq, false, true, false, nil, tcpState)
			if err := pg.writePacket(clientAckPacket); err != nil {
				return err
			}
		}
	}

	// 生成四次挥手
	if err := pg.generateTCPCloseWithState(srcIP, dstIP, srcPort, dstPort, tcpState); err != nil {
		return err
	}

	return nil
}

// createTCPPacketWithTimestamp 创建带时间戳的TCP数据包
func (pg *PacketGenerator) createTCPPacketWithTimestamp(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, syn, ackFlag, fin bool, payload []byte, state *TCPState) []byte {
	// 使用全局时间戳管理器获取下一个时间戳
	state.timestamp = pg.getNextTimestamp()

	// 创建网络层
	eth := pg.createEthernetLayer()
	ip := pg.createIPLayer(srcIP, dstIP, layers.IPProtocolTCP)

	// 创建TCP层
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ack,
		SYN:     syn,
		ACK:     ackFlag,
		FIN:     fin,
		PSH:     payload != nil, // 当有数据时设置PSH标志，这对HTTP协议识别很重要
		Window:  65535,
	}

	// 设置校验和
	tcp.SetNetworkLayerForChecksum(ip)

	// 序列化数据包
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if payload != nil {
		gopacket.SerializeLayers(buffer, opts, eth, ip, tcp, gopacket.Payload(payload))
	} else {
		gopacket.SerializeLayers(buffer, opts, eth, ip, tcp)
	}

	return buffer.Bytes()
}

// generateUDPBasedProtocolPackets 生成基于UDP的协议数据包（UDP、DNS）
func (pg *PacketGenerator) generateUDPBasedProtocolPackets(pairs []ProtocolData, protocolName string) error {
	// 为协议块生成固定的MAC地址
	srcMAC := generateRandomMAC()
	dstMAC := generateRandomMAC()

	for i, pair := range pairs {
		// 解析IP地址和端口
		srcIP, dstIP, srcPort, dstPort, err := parseIPAndPorts(pair.IPPair)
		if err != nil {
			return fmt.Errorf("%s %v", protocolName, err)
		}

		// 处理请求
		if pair.Request.ReqData != "" {
			reqData, err := decodePayload(pair.Request.Format, pair.Request.ReqData, pair.IPPair, "udp")
			if err != nil {
				return formatProtocolError(protocolName, "解码", i, fmt.Errorf("请求数据: %v", err))
			}
			if len(reqData) > 0 {
				requestPacket := pg.createUDPPacketWithMAC(srcIP, dstIP, srcPort, dstPort, reqData, srcMAC, dstMAC)
				if err := pg.writePacket(requestPacket); err != nil {
					return formatProtocolError(protocolName, "写入", i, fmt.Errorf("请求包: %v", err))
				}
			}
		}

		// 处理响应
		if pair.Response.RespData != "" {
			respData, err := decodePayload(pair.Response.Format, pair.Response.RespData, pair.IPPair, "udp")
			if err != nil {
				return formatProtocolError(protocolName, "解码", i, fmt.Errorf("响应数据: %v", err))
			}
			if len(respData) > 0 {
				responsePacket := pg.createUDPPacketWithMAC(dstIP, srcIP, dstPort, srcPort, respData, dstMAC, srcMAC)
				if err := pg.writePacket(responsePacket); err != nil {
					return formatProtocolError(protocolName, "写入", i, fmt.Errorf("响应包: %v", err))
				}
			}
		}
	}
	return nil
}

// createEthernetLayer 创建以太网层
func (pg *PacketGenerator) createEthernetLayer() *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       generateRandomMAC(),
		DstMAC:       generateRandomMAC(),
		EthernetType: layers.EthernetTypeIPv4,
	}
}

// createEthernetLayerWithMAC 创建带有指定MAC地址的以太网层
func (pg *PacketGenerator) createEthernetLayerWithMAC(srcMAC, dstMAC net.HardwareAddr) *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
}

// createIPLayer 创建IP层
func (pg *PacketGenerator) createIPLayer(srcIP, dstIP net.IP, protocol layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: protocol,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
}

// createUDPPacket 创建UDP数据包
func (pg *PacketGenerator) createUDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	// 创建网络层
	eth := pg.createEthernetLayer()
	ip := pg.createIPLayer(srcIP, dstIP, layers.IPProtocolUDP)

	// 创建UDP层
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}

	// 设置校验和
	udp.SetNetworkLayerForChecksum(ip)

	// 序列化数据包
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	gopacket.SerializeLayers(buffer, opts, eth, ip, udp, gopacket.Payload(payload))
	return buffer.Bytes()
}

// createUDPPacketWithMAC 创建带有指定MAC地址的UDP数据包
func (pg *PacketGenerator) createUDPPacketWithMAC(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte, srcMAC, dstMAC net.HardwareAddr) []byte {
	// 创建网络层
	eth := pg.createEthernetLayerWithMAC(srcMAC, dstMAC)
	ip := pg.createIPLayer(srcIP, dstIP, layers.IPProtocolUDP)

	// 创建UDP层
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}

	// 设置校验和
	udp.SetNetworkLayerForChecksum(ip)

	// 序列化数据包
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	gopacket.SerializeLayers(buffer, opts, eth, ip, udp, gopacket.Payload(payload))
	return buffer.Bytes()
}

// createDNSQuery 创建DNS查询包
func (pg *PacketGenerator) generateDNSBasedProtocolPackets(pairs []ProtocolData, protocolName string) error {
	// 为整个DNS协议块生成固定的源MAC和目的MAC地址
	srcMAC := generateRandomMAC()
	dstMAC := generateRandomMAC()

	// 处理多个DNS请求响应对
	for i, pair := range pairs {
		// 解析IP地址和端口
		srcIP, dstIP, srcPort, dstPort, err := parseIPAndPorts(pair.IPPair)
		if err != nil {
			return fmt.Errorf("%s %v", protocolName, err)
		}

		// 生成统一的transaction ID
		transactionID := uint16(mathrand.Intn(65536))

		// 处理DNS查询
		if pair.Request.Domain != "" {
			domain := pair.Request.Domain
			reqType := pair.Request.ReqType
			queryPacket := pg.createDNSQuery(srcIP, dstIP, srcPort, dstPort, domain, reqType, transactionID, srcMAC, dstMAC)
			if err := pg.writePacket(queryPacket); err != nil {
				return formatProtocolError(protocolName, "写入", i, fmt.Errorf("请求包: %v", err))
			}
		}

		// 处理DNS响应
		if pair.Response.RespData != "" {
			domain := pair.Request.Domain // 使用对应请求的域名
			respData := pair.Response.RespData
			reqType := pair.Request.ReqType // 获取请求类型
			// 生成DNS响应数据包
			responsePacket := pg.createDNSResponse(dstIP, srcIP, dstPort, srcPort, domain, respData, reqType, transactionID, dstMAC, srcMAC)
			if err := pg.writePacket(responsePacket); err != nil {
				return formatProtocolError(protocolName, "写入", i, fmt.Errorf("响应包: %v", err))
			}
		}

		// 添加数据包间隔
		time.Sleep(DefaultPacketInterval * time.Millisecond)
	}
	return nil
}

func (pg *PacketGenerator) createDNSQuery(srcIP, dstIP net.IP, srcPort, dstPort uint16, domain, qtype string, transactionID uint16, macs ...net.HardwareAddr) []byte {
	// 创建网络层
	var eth *layers.Ethernet
	if len(macs) == 2 {
		eth = pg.createEthernetLayerWithMAC(macs[0], macs[1])
	} else {
		eth = pg.createEthernetLayer()
	}
	ip := pg.createIPLayer(srcIP, dstIP, layers.IPProtocolUDP)

	// 创建UDP层
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}

	// 创建DNS层
	dns := &layers.DNS{
		ID:      transactionID,
		QR:      false,
		OpCode:  layers.DNSOpCodeQuery,
		RD:      true,
		QDCount: 1,
	}

	// 添加DNS问题
	var dnsType layers.DNSType
	switch strings.ToUpper(qtype) {
	case "AAAA":
		dnsType = layers.DNSTypeAAAA
	case "CNAME":
		dnsType = layers.DNSTypeCNAME
	case "MX":
		dnsType = layers.DNSTypeMX
	case "TXT":
		dnsType = layers.DNSTypeTXT
	default:
		dnsType = layers.DNSTypeA
	}

	dns.Questions = []layers.DNSQuestion{{
		Name:  []byte(domain),
		Type:  dnsType,
		Class: layers.DNSClassIN,
	}}

	// 设置校验和
	udp.SetNetworkLayerForChecksum(ip)

	// 序列化数据包
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	gopacket.SerializeLayers(buffer, opts, eth, ip, udp, dns)
	return buffer.Bytes()
}

// createDNSResponse 创建DNS响应包，可选MAC地址
func (pg *PacketGenerator) createDNSResponse(srcIP, dstIP net.IP, srcPort, dstPort uint16, domain, answer, qtype string, transactionID uint16, macs ...net.HardwareAddr) []byte {
	var eth *layers.Ethernet
	if len(macs) == 2 {
		eth = pg.createEthernetLayerWithMAC(macs[0], macs[1])
	} else {
		eth = pg.createEthernetLayer()
	}
	ip := pg.createIPLayer(srcIP, dstIP, layers.IPProtocolUDP)

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}

	// 创建DNS层
	dns := &layers.DNS{
		ID:      transactionID,
		QR:      true,
		OpCode:  layers.DNSOpCodeQuery,
		RD:      true,
		RA:      true,
		QDCount: 1,
		ANCount: 1,
	}

	// 根据请求类型设置DNS问题类型
	var dnsType layers.DNSType
	switch strings.ToUpper(qtype) {
	case "AAAA":
		dnsType = layers.DNSTypeAAAA
	case "CNAME":
		dnsType = layers.DNSTypeCNAME
	case "MX":
		dnsType = layers.DNSTypeMX
	case "TXT":
		dnsType = layers.DNSTypeTXT
	default:
		dnsType = layers.DNSTypeA
	}

	// 添加DNS问题
	dns.Questions = []layers.DNSQuestion{{
		Name:  []byte(domain),
		Type:  dnsType,
		Class: layers.DNSClassIN,
	}}

	// 添加DNS答案
	if answer != "" {
		var dnsAnswer layers.DNSResourceRecord
		dnsAnswer.Name = []byte(domain)
		dnsAnswer.Type = dnsType
		dnsAnswer.Class = layers.DNSClassIN
		dnsAnswer.TTL = DefaultTTL

		switch dnsType {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			answerIP := net.ParseIP(answer)
			if answerIP != nil {
				dnsAnswer.IP = answerIP
				dns.Answers = []layers.DNSResourceRecord{dnsAnswer}
			}
		case layers.DNSTypeCNAME:
			cnameValues := strings.Fields(answer) // 只使用空格分隔
			var allAnswers []layers.DNSResourceRecord

			// 构建CNAME链：原域名指向第一个值，第一个值指向第二个值，以此类推
			currentDomain := domain // 从查询的原域名开始

			for _, cnameValue := range cnameValues {
				cnameValue = strings.TrimSpace(cnameValue)
				if cnameValue == "" {
					continue
				}

				// 检查是否为IP地址（最终解析结果）
				if net.ParseIP(cnameValue) != nil {
					// 最终IP作为A记录，域名为当前域名
					aRecord := dnsAnswer
					aRecord.Type = layers.DNSTypeA
					aRecord.Name = []byte(currentDomain)
					aRecord.IP = net.ParseIP(cnameValue)
					allAnswers = append(allAnswers, aRecord)
				} else {
					// CNAME记录：当前域名指向下一个域名
					cnameAnswer := dnsAnswer
					cnameAnswer.Name = []byte(currentDomain)
					cnameAnswer.CNAME = []byte(cnameValue)
					allAnswers = append(allAnswers, cnameAnswer)
					// 更新当前域名为下一个域名
					currentDomain = cnameValue
				}
			}

			if len(allAnswers) > 0 {
				dns.Answers = allAnswers
				dns.ANCount = uint16(len(allAnswers))
			}
		case layers.DNSTypeMX:
			// MX记录格式: "优先级 邮件服务器" 例如: "10 mail.example.com"
			// 或者只有邮件服务器，默认优先级为10
			parts := strings.SplitN(answer, " ", 2)
			if len(parts) == 2 {
				// 包含优先级和邮件服务器
				if priority, err := strconv.ParseUint(parts[0], 10, 16); err == nil {
					dnsAnswer.MX.Preference = uint16(priority)
					dnsAnswer.MX.Name = []byte(parts[1])
					dns.Answers = []layers.DNSResourceRecord{dnsAnswer}
				}
			} else if len(parts) == 1 && strings.TrimSpace(parts[0]) != "" {
				// 只有邮件服务器，默认优先级为10
				dnsAnswer.MX.Preference = 10
				dnsAnswer.MX.Name = []byte(strings.TrimSpace(parts[0]))
				dns.Answers = []layers.DNSResourceRecord{dnsAnswer}
			}
		case layers.DNSTypeTXT:
			dnsAnswer.TXTs = [][]byte{[]byte(answer)}
			dns.Answers = []layers.DNSResourceRecord{dnsAnswer}
		default:
			answerIP := net.ParseIP(answer)
			if answerIP != nil {
				dnsAnswer.IP = answerIP
				dns.Answers = []layers.DNSResourceRecord{dnsAnswer}
			}
		}
	}

	udp.SetNetworkLayerForChecksum(ip)

	// 序列化数据包
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	gopacket.SerializeLayers(buffer, opts, eth, ip, udp, dns)
	return buffer.Bytes()
}

func (pg *PacketGenerator) writePacket(data []byte) error {
	ci := gopacket.CaptureInfo{
		Timestamp:     pg.getNextTimestamp(),
		CaptureLength: len(data),
		Length:        len(data),
	}

	return pg.writer.WritePacket(ci, data)
}
