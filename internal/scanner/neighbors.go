package scanner

import (
  "fmt"
  "net"
)

func ExpandNeighbors(baseIP string, rangeSize int) []string {
  ip := net.ParseIP(baseIP)
  if ip == nil {
    return nil
  }
  
  ipv4 := ip.To4()
  if ipv4 == nil {
    return nil
  }
  
  lastOctet := int(ipv4[3])
  var results []string
  
  for i := lastOctet - rangeSize; i <= lastOctet + rangeSize; i++ {
    if i >= 0 && i <= 255 {
      newIP := fmt.Sprintf("%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], i)
      results = append(results, newIP)
    }
  }
  
  return results
}
