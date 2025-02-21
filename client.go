package ethtool

import (
	"fmt"

	"github.com/siderolabs/gen/optional"
)

//go:generate stringer -type=Duplex,Port -output=string.go
//go:generate go run mklinkmodes.go

var (
	_ error = &Error{}
	// Ensure compatibility with Go 1.13+ errors package.
	_ interface{ Unwrap() error } = &Error{}
)

// An Error is an error value produced by the kernel due to a bad ethtool
// netlink request. Typically the Err will be of type *netlink.OpError.
type Error struct {
	Message string
	Err     error
}

// Error implements error.
func (e *Error) Error() string {
	// This typically wraps a *netlink.OpError which will contain the error
	// string anyway, so just return the inner error's string.
	return e.Err.Error()
}

// Unwrap unwraps the internal Err field for use with errors.Unwrap.
func (e *Error) Unwrap() error { return e.Err }

// A Client can manipulate the ethtool netlink interface.
type Client struct {
	// The operating system-specific client.
	c *client
}

// New creates a Client which can issue ethtool commands.
func New() (*Client, error) {
	c, err := newClient()
	if err != nil {
		return nil, err
	}

	return &Client{c: c}, nil
}

// An Interface is an ethtool netlink Ethernet interface. Interfaces are used to
// identify an Ethernet interface being queried by its index and/or name.
type Interface struct {
	// Callers may choose to set either Index, Name, or both fields. Note that
	// if both are set, the kernel will verify that both Index and Name are
	// associated with the same interface. If they are not, an error will be
	// returned.
	Index int
	Name  string
}

// LinkInfo contains link settings for an Ethernet interface.
type LinkInfo struct {
	Interface Interface
	Port      Port
}

// A Port is the port type for a LinkInfo structure.
type Port int

// Possible Port type values.
const (
	TwistedPair  Port = 0x00
	AUI          Port = 0x01
	MII          Port = 0x02
	Fibre        Port = 0x03
	BNC          Port = 0x04
	DirectAttach Port = 0x05
	None         Port = 0xef
	Other        Port = 0xff
)

// LinkInfos fetches LinkInfo structures for each ethtool-supported interface
// on this system.
func (c *Client) LinkInfos() ([]*LinkInfo, error) {
	return c.c.LinkInfos()
}

// LinkInfo fetches LinkInfo for the specified Interface.
//
// If the requested device does not exist or is not supported by the ethtool
// interface, an error compatible with errors.Is(err, os.ErrNotExist) will be
// returned.
func (c *Client) LinkInfo(ifi Interface) (*LinkInfo, error) {
	return c.c.LinkInfo(ifi)
}

// LinkMode contains link mode information for an Ethernet interface.
type LinkMode struct {
	Interface     Interface
	SpeedMegabits int
	Ours, Peer    []AdvertisedLinkMode
	Duplex        Duplex
}

// A Duplex is the link duplex type for a LinkMode structure.
type Duplex int

// Possible Duplex type values.
const (
	Half    Duplex = 0x00
	Full    Duplex = 0x01
	Unknown Duplex = 0xff
)

// An AdvertisedLinkMode is a link mode that an interface advertises it is
// capable of using.
type AdvertisedLinkMode struct {
	Index int
	Name  string
}

// LinkModes fetches LinkMode structures for each ethtool-supported interface
// on this system.
func (c *Client) LinkModes() ([]*LinkMode, error) {
	return c.c.LinkModes()
}

// LinkMode fetches LinkMode data for the specified Interface.
//
// If the requested device does not exist or is not supported by the ethtool
// interface, an error compatible with errors.Is(err, os.ErrNotExist) will be
// returned.
func (c *Client) LinkMode(ifi Interface) (*LinkMode, error) {
	return c.c.LinkMode(ifi)
}

// LinkState contains link state information for an Ethernet interface.
type LinkState struct {
	Interface Interface
	Link      bool
}

// LinkStates fetches LinkState structures for each ethtool-supported interface
// on this system.
func (c *Client) LinkStates() ([]*LinkState, error) {
	return c.c.LinkStates()
}

// LinkState fetches LinkState data for the specified Interface.
//
// If the requested device does not exist or is not supported by the ethtool
// interface, an error compatible with errors.Is(err, os.ErrNotExist) will be
// returned.
func (c *Client) LinkState(ifi Interface) (*LinkState, error) {
	return c.c.LinkState(ifi)
}

// FEC fetches the forward error correction (FEC) setting for the specified
// Interface.
func (c *Client) FEC(ifi Interface) (*FEC, error) {
	return c.c.FEC(ifi)
}

// SetFEC sets the forward error correction (FEC) parameters for the Interface
// in fec.
//
// Setting FEC parameters requires elevated privileges and if the caller
// does not have permission, an error compatible with errors.Is(err,
// os.ErrPermission) will be returned.
//
// If the requested device does not exist or is not supported by the ethtool
// interface, an error compatible with errors.Is(err, os.ErrNotExist) will be
// returned.
func (c *Client) SetFEC(fec FEC) error {
	return c.c.SetFEC(fec)
}

// A FEC contains the forward error correction (FEC) parameters for an
// interface.
type FEC struct {
	Interface Interface
	Modes     FECModes
	Active    FECMode
	Auto      bool
}

// A FECMode is a FEC mode bit value (single element bitmask) specifying the
// active mode of an interface.
type FECMode int

// A FECModes is a FEC mode bitmask of mode(s) supported by an interface.
type FECModes FECMode

// A WakeOnLAN contains the Wake-on-LAN parameters for an interface.
type WakeOnLAN struct {
	Interface Interface
	Modes     WOLMode
}

// A WOLMode is a Wake-on-LAN mode bitmask of mode(s) supported by an interface.
type WOLMode int

// Possible Wake-on-LAN mode bit flags.
const (
	PHY         WOLMode = 1 << 0
	Unicast     WOLMode = 1 << 1
	Multicast   WOLMode = 1 << 2
	Broadcast   WOLMode = 1 << 3
	ARP         WOLMode = 1 << 4
	Magic       WOLMode = 1 << 5
	MagicSecure WOLMode = 1 << 6
	Filter      WOLMode = 1 << 7
)

// String returns the string representation of a WOLMode bitmask.
func (m WOLMode) String() string {
	names := []string{
		"PHY",
		"Unicast",
		"Multicast",
		"Broadcast",
		"ARP",
		"Magic",
		"MagicSecure",
		"Filter",
	}

	var s string
	left := uint(m)
	for i, name := range names {
		if m&(1<<uint(i)) != 0 {
			if s != "" {
				s += "|"
			}

			s += name

			left ^= (1 << uint(i))
		}
	}

	if s == "" && left == 0 {
		s = "0"
	}

	if left > 0 {
		if s != "" {
			s += "|"
		}
		s += fmt.Sprintf("%#x", left)
	}

	return s
}

// WakeOnLANs fetches WakeOnLAN information for each ethtool-supported interface
// on this system.
func (c *Client) WakeOnLANs() ([]*WakeOnLAN, error) {
	return c.c.WakeOnLANs()
}

// WakeOnLAN fetches WakeOnLAN parameters for the specified Interface.
//
// Fetching Wake-on-LAN information requires elevated privileges and if the
// caller does not have permission, an error compatible with errors.Is(err,
// os.ErrPermission) will be returned.
//
// If the requested device does not exist or is not supported by the ethtool
// interface, an error compatible with errors.Is(err, os.ErrNotExist) will be
// returned.
func (c *Client) WakeOnLAN(ifi Interface) (*WakeOnLAN, error) {
	return c.c.WakeOnLAN(ifi)
}

// SetWakeOnLAN sets the WakeOnLAN parameters for the Interface in wol.
//
// Setting Wake-on-LAN parameters requires elevated privileges and if the caller
// does not have permission, an error compatible with errors.Is(err,
// os.ErrPermission) will be returned.
//
// If the requested device does not exist or is not supported by the ethtool
// interface, an error compatible with errors.Is(err, os.ErrNotExist) will be
// returned.
func (c *Client) SetWakeOnLAN(wol WakeOnLAN) error {
	return c.c.SetWakeOnLAN(wol)
}

// PrivateFlags is a list of driver-specific flags which are either on or off.
// These are used to control behavior specific to a specific driver or device
// for which no generic API exists.
//
// The flags which go in here are mostly undocumented other than in kernel
// source code, you can get the list of supported flags by calling
// PrivateFlags() and then searching for the returned names in Linux kernel
// sources.
//
// This is technically a bitset but as the bit positions are not stable across
// kernel versions there is no reason to use that functionality, thus it is not
// exposed.
//
// Note that these flags are in practice not fully covered by Linux's userspace
// ABI guarantees, it should be expected that a flag can go away.
type PrivateFlags struct {
	Interface Interface
	// Flags is a map of flag names to their active state, i.e. if the flag
	// is on or off.
	Flags map[string]bool
}

// AllPrivateFlags returns Private Flags for each ethtool-supported interface
// on this system.
func (c *Client) AllPrivateFlags() ([]*PrivateFlags, error) {
	return c.c.AllPrivateFlags()
}

// PrivateFlags returns Private Flags for a single interface. See the type for
// a more in-depth explanation.
//
// If the requested device does not exist or is not supported by the ethtool
// interface, an error compatible with errors.Is(err, os.ErrNotExist) will be
// returned.
func (c *Client) PrivateFlags(ifi Interface) (*PrivateFlags, error) {
	return c.c.PrivateFlags(ifi)
}

// SetPrivateFlags attempts to set the given private flags on the given
// interface. Flags does not need to contain the all flags, those not
// in it are left as-is.
//
// Setting Private Flags requires elevated privileges and if the caller
// does not have permission, an error compatible with errors.Is(err,
// os.ErrPermission) will be returned.
//
// Note that not all flags can be changed in all interface states, some might
// only be settable if the interface is down or are only settable once.
//
// If the requested device does not exist or is not supported by the ethtool
// interface, an error compatible with errors.Is(err, os.ErrNotExist) will be
// returned.
func (c *Client) SetPrivateFlags(p PrivateFlags) error {
	return c.c.SetPrivateFlags(p)
}

// Rings contains ring buffer configuration for an interface.
type Rings struct {
	Interface Interface

	// Read-only settings reported by the driver.
	RXMax           optional.Optional[uint32]
	RXMiniMax       optional.Optional[uint32]
	RXJumboMax      optional.Optional[uint32]
	TXMax           optional.Optional[uint32]
	TXPushBufLenMax optional.Optional[uint32]

	// Current settings (read-write).
	RX           optional.Optional[uint32]
	RXMini       optional.Optional[uint32]
	RXJumbo      optional.Optional[uint32]
	TX           optional.Optional[uint32]
	RXBufLen     optional.Optional[uint32]
	CQESize      optional.Optional[uint32]
	TXPush       optional.Optional[bool]
	RXPush       optional.Optional[bool]
	TXPushBufLen optional.Optional[uint32]
	TCPDataSplit optional.Optional[bool]
}

// Channels contains channel configuration for an interface.
type Channels struct {
	Interface Interface

	// Read-only settings reported by the driver.
	RXMax       optional.Optional[uint32]
	TXMax       optional.Optional[uint32]
	OtherMax    optional.Optional[uint32]
	CombinedMax optional.Optional[uint32]

	// Current settings (read-write).
	RXCount       optional.Optional[uint32]
	TXCount       optional.Optional[uint32]
	OtherCount    optional.Optional[uint32]
	CombinedCount optional.Optional[uint32]
}

// Rings returns the Ring configuration for the specified Interface.
func (c *Client) Rings(ifi Interface) (*Rings, error) {
	return c.c.Rings(ifi)
}

// SetRings configures rings for a single interface.
func (c *Client) SetRings(r Rings) error {
	return c.c.SetRings(r)
}

// Channels returns the Channel configuration for the specified Interface.
func (c *Client) Channels(ifi Interface) (*Channels, error) {
	return c.c.Channels(ifi)
}

// SetChannels configures channels for a single interface.
func (c *Client) SetChannels(ch Channels) error {
	return c.c.SetChannels(ch)
}

// StringSet is a set of strings with index-based access.
type StringSet map[uint32]string

// FeaturesStringSet returns a string set describing the feature bits.
func (c *Client) FeaturesStringSet() (StringSet, error) {
	return c.c.FeaturesStringSet()
}

// FeatureInfo describes the current of features for an interface.
type FeatureInfo struct {
	Name      string
	Supported bool
	Wanted    bool
	Active    bool
	NoChange  bool
}

func (f FeatureInfo) State() string {
	switch f.Active {
	case true:
		return "on"
	default:
		return "off"
	}
}

func (f FeatureInfo) Suffix() string {
	switch {
	case !f.Supported || f.NoChange:
		return " [fixed]"
	case f.Active != f.Wanted:
		if f.Wanted {
			return " [requested on]"
		} else {
			return " [requested off]"
		}
	default:
		return ""
	}
}

// Features returns the feature information for the specified Interface.
func (c *Client) Features(ifi Interface) ([]FeatureInfo, error) {
	return c.c.Features(ifi)
}

// SetFeatures sets the features for the specified Interface.
func (c *Client) SetFeatures(ifi Interface, features map[string]bool) error {
	return c.c.SetFeatures(ifi, features)
}

// Close cleans up the Client's resources.
func (c *Client) Close() error { return c.c.Close() }
