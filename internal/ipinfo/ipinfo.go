package ipinfo

import (
	"fmt"
	"net"

	"github.com/ipinfo/go/v2/ipinfo"

	"github.com/skpr/waf-notification-lambda/internal/types"
)

// IPInfoClient defines the interface for fetching IP information in batches.
type IPInfoClient interface {
	GetIPInfoBatch([]net.IP, ipinfo.BatchReqOpts) (ipinfo.BatchCore, error)
}

// DecorateBlockedIPs enriches the given IPs with additional information using the provided IPInfoClient.
func DecorateBlockedIPs(client IPInfoClient, in map[string]types.BlockedIP) ([]types.BlockedIP, error) {
	input := make([]net.IP, 0, len(in))

	for ip := range in {
		input = append(input, net.ParseIP(ip))
	}

	infos, err := client.GetIPInfoBatch(input, ipinfo.BatchReqOpts{})
	if err != nil {
		return nil, fmt.Errorf("failed to get batch info: %w", err)
	}

	var out []types.BlockedIP

	// Decorate our list of IPs with info.
	for _, info := range infos {
		if info == nil {
			continue
		}

		if _, exists := in[info.IP.String()]; !exists {
			continue
		}

		out = append(out, types.BlockedIP{
			IP:      info.IP.String(),
			Count:   in[info.IP.String()].Count,
			City:    info.City,
			Region:  info.Region,
			Country: info.Country,
			Org:     info.Org,
		})
	}

	return out, nil
}
