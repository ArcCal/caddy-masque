package bpf

// A Setter is a type which can attach a compiled BPF filter to itself.
type Setter interface {
	SetBPF(filter []RawInstruction) error
}
