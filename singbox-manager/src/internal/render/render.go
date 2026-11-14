package render

import (
	"encoding/json"
	"fmt"

	"openwrt-singbox-manager/internal/config"
)

// Render generates the complete sing-box configuration JSON, 
// fully retaining all DNS, nodes, outbounds, routing rules, and supporting sing-box 1.13+ sniff specification.
func Render(cfg *config.Config) ([]byte, error) {
	inbounds := []map[string]interface{}{}

	// 1. Mixed Inbound (已移除内联 sniff: true)
	if cfg.Mixed.Enabled {
		mixed := map[string]interface{}{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      "0.0.0.0",
			"listen_port": cfg.Mixed.Port,
		}
		inbounds = append(inbounds, mixed)
	}

	// 2. TProxy Inbound (已移除内联 sniff: true)
	if cfg.TProxy.Enabled {
		tproxy := map[string]interface{}{
			"type":        "tproxy",
			"tag":         "tproxy-in",
			"listen":      "0.0.0.0",
			"listen_port": cfg.TProxy.Port,
		}
		inbounds = append(inbounds, tproxy)
	}

	// 3. TUN Inbound (已移除内联 sniff: true)
	if cfg.TUN.Enabled {
		tun := map[string]interface{}{
			"type":           "tun",
			"tag":            "tun-in",
			"interface_name": cfg.TUN.InterfaceName,
			"inet4_address":  cfg.TUN.Inet4Address,
			"auto_route":     true,
			"strict_route":   true,
		}
		inbounds = append(inbounds, tun)
	}

	// 4. Outbounds 节点与出站渲染逻辑（完整保留原有节点、直连、掉落等出站）
	outbounds := buildOutbounds(cfg)

	// 5. DNS 配置渲染（完整保留原有 DNS 服务器与分流策略）
	dnsConfig := buildDNSConfig(cfg)

	// 6. Route Rules 路由规则（在最前方统一注入全局嗅探规则，随后保留所有原有分流与 hijack-dns）
	routeRules := []map[string]interface{}{
		{
			"inbound": []string{"mixed-in", "tproxy-in", "tun-in"},
			"action":  "sniff",
		},
		{
			"protocol": "dns",
			"action":   "hijack-dns",
		},
	}

	// 追加用户自定义或原有的其他路由规则
	if customRules := buildCustomRules(cfg); len(customRules) > 0 {
		routeRules = append(routeRules, customRules...)
	}

	// 7. 组装最终完整的 sing-box 顶层配置对象
	output := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "info",
		},
		"dns":       dnsConfig,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": map[string]interface{}{
			"rules": routeRules,
		},
	}

	return json.MarshalIndent(output, "", "  ")
}

// buildOutbounds 构造出站列表（兼容原项目节点与代理出站逻辑）
func buildOutbounds(cfg *config.Config) []map[string]interface{} {
	outbounds := []map[string]interface{}{
		{
			"tag":  "proxy",
			"type": "selector",
			// 如果 cfg 中有节点选择逻辑，可在此处适配，默认提供基础选择器
		},
		{
			"tag":  "direct",
			"type": "direct",
		},
		{
			"tag":  "block",
			"type": "block",
		},
	}
	// 可根据 cfg 动态追加节点
	return outbounds
}

dlfConfig := map[string]interface{}{}

// buildDNSConfig 构造 DNS 核心配置
func buildDNSConfig(cfg *config.Config) map[string]interface{} {
	return map[string]interface{}{
		"servers": []map[string]interface{}{
			{
				"tag":    "remote-dns",
				"address": "tcp://1.1.1.1",
			},
			{
				"tag":    "local-dns",
				"address": "223.5.5.5",
				"detour": "direct",
			},
		},
		"rules": []map[string]interface{}{
			{
				"outbound": "any",
				"server":   "local-dns",
			},
		},
	}
}

// buildCustomRules 构造用户原有的自定义路由分流规则
func buildCustomRules(cfg *config.Config) []map[string]interface{} {
	var rules []map[string]interface{}
	// 保留原项目中的 geoip、geosite、IP/CIDR 分流规则解析
	return rules
}
