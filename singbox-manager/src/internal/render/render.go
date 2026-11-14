package render

import (
	"encoding/json"
	"fmt"
	"os"

	"openwrt-singbox-manager/internal/config"
)

// Render generates the complete sing-box configuration JSON.
func Render(cfg *config.Config) ([]byte, error) {
	inbounds := []map[string]interface{}{}

	// 1. Mixed Inbound
	if cfg.Mixed.Enabled {
		mixed := map[string]interface{}{
			"type": "mixed",
			"tag":  "mixed-in",
			"listen": "0.0.0.0",
			"listen_port": cfg.Mixed.Port,
		}
		// 移除了内联 "sniff": true，符合 sing-box 1.13+ 规范
		inbounds = append(inbounds, mixed)
	}

	// 2. TProxy Inbound
	if cfg.TProxy.Enabled {
		tproxy := map[string]interface{}{
			"type": "tproxy",
			"tag":  "tproxy-in",
			"listen": "0.0.0.0",
			"listen_port": cfg.TProxy.Port,
		}
		inbounds = append(inbounds, tproxy)
	}

	// 3. TUN Inbound
	if cfg.TUN.Enabled {
		tun := map[string]interface{}{
			"type": "tun",
			"tag":  "tun-in",
			"interface_name": cfg.TUN.InterfaceName,
			"inet4_address":  cfg.TUN.Inet4Address,
			"auto_route":     true,
			"strict_route":   true,
		}
		inbounds = append(inbounds, tun)
	}

	// 4. Route Rules (在最前方加入全局统一嗅探规则)
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

	// 组装最终配置对象
	output := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "info",
		},
		"inbounds": inbounds,
		"route": map[string]interface{}{
			"rules": routeRules,
		},
	}

	return json.MarshalIndent(output, "", "  ")
}
