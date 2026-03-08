package client

import "github.com/koltyakov/expose/internal/traffic"

func (c *Client) recordTraffic(direction traffic.Direction, bytes int64) {
	if c == nil || c.trafficSink == nil || bytes <= 0 {
		return
	}
	c.trafficSink.RecordTraffic(direction, bytes)
}
