package sqlite

// SetReservedHostnames reserves server-owned routes without persisting them.
// Call before accepting traffic. Removing a route from the server config releases
// its reservation on the next start without modifying existing client records.
func (s *Store) SetReservedHostnames(hosts []string) {
	reserved := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		reserved[normalizeHostname(host)] = struct{}{}
	}
	s.reservedHostnames.Store(reserved)
}

func (s *Store) isReservedHostname(host string) bool {
	reserved, _ := s.reservedHostnames.Load().(map[string]struct{})
	_, ok := reserved[normalizeHostname(host)]
	return ok
}
