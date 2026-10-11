//go:build !race

package socket

func (m *Message) raceRead() {
}
func (m *Message) raceWrite() {
}
