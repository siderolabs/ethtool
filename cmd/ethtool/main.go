package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/mdlayher/ethtool"
	"github.com/siderolabs/gen/optional"
	"golang.org/x/sys/unix"
)

func main() {
	if err := run(); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: ethtool <interface>")
	}

	linkName := os.Args[1]

	cli, err := ethtool.New()
	if err != nil {
		return fmt.Errorf("failed to create ethtool client: %v", err)
	}

	defer cli.Close()

	li, err := cli.LinkInfo(ethtool.Interface{
		Name: linkName,
	})
	if err != nil {
		return fmt.Errorf("failed to get link info: %v", err)
	}

	fmt.Printf("Link info for %s: %s\n", linkName, li.Port)

	lm, err := cli.LinkMode(ethtool.Interface{Name: linkName})
	if err != nil {
		return fmt.Errorf("failed to get link mode: %v", err)
	}

	fmt.Printf("Link mode for %s: duplex %s our %v theirs %v\n", linkName, lm.Duplex, lm.Ours, lm.Peer)

	ls, err := cli.LinkState(ethtool.Interface{Name: linkName})
	if err != nil {
		return fmt.Errorf("failed to get link state: %v", err)
	}

	fmt.Printf("Link state for %s: %v\n", linkName, ls.Link)

	privFlags, err := cli.PrivateFlags(ethtool.Interface{Name: linkName})
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			fmt.Printf("Private flags are not supported for %s\n", linkName)
		} else {
			return fmt.Errorf("failed to get private flags: %v", err)
		}
	} else {
		fmt.Printf("Private flags for %s: %v\n", linkName, privFlags.Flags)
	}

	rings, err := cli.Rings(ethtool.Interface{Name: linkName})
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			fmt.Printf("Rings are not supported for %s\n", linkName)
		} else {
			return fmt.Errorf("failed to get rings: %v", err)
		}
	} else {
		fmt.Printf("Rings for %s: RX %d TX %d, all %#+v\n", linkName, rings.RX.ValueOrZero(), rings.TX.ValueOrZero(), rings)
	}

	// err = cli.SetRings(ethtool.Rings{
	// 	Interface: ethtool.Interface{Name: linkName},
	// 	RX:        optional.Some[uint32](64),
	// })
	// if err != nil {
	// 	return fmt.Errorf("failed to set rings: %v", err)
	// }

	featuresSS, err := cli.FeaturesStringSet()
	if err != nil {
		return fmt.Errorf("failed to get features string set: %v", err)
	}

	fmt.Printf("Features string set for %s: %v\n", linkName, featuresSS)

	features, err := cli.Features(ethtool.Interface{Name: linkName})
	if err != nil {
		return fmt.Errorf("failed to get features: %v", err)
	}

	fmt.Printf("Features for %s: %v\n", linkName, features)

	for _, f := range features {
		fmt.Printf("%s: %s%s\n", f.Name, f.State(), f.Suffix())

	}

	err = cli.SetFeatures(ethtool.Interface{Name: linkName}, map[string]bool{"tx-checksum-ipv4": true})
	if err != nil {
		return fmt.Errorf("failed to set features: %v", err)
	}

	err = cli.SetFeatures(ethtool.Interface{Name: linkName}, map[string]bool{"tx-checksum-ipv4": false})
	if err != nil {
		return fmt.Errorf("failed to set features: %v", err)
	}

	channels, err := cli.Channels(ethtool.Interface{Name: linkName})
	if err != nil {
		return fmt.Errorf("failed to get channels: %v", err)
	}

	fmt.Printf("Channels for %s: %#+v\n", linkName, channels)

	pause, err := cli.Pause(ethtool.Interface{Name: linkName})
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			fmt.Printf("Pause (flow control) is not supported for %s\n", linkName)
		} else {
			return fmt.Errorf("failed to get pause settings: %v", err)
		}
	} else {
		fmt.Printf("Pause for %s: RX %v TX %v Autoneg %v, all %#+v\n", linkName, pause.RX.ValueOrZero(), pause.TX.ValueOrZero(), pause.Autoneg.ValueOrZero(), pause)
	}

	err = cli.SetPause(ethtool.Pause{
		Interface: ethtool.Interface{Name: linkName},
		RX:        optional.Some[bool](false),
		TX:        optional.Some[bool](false),
	})
	if err != nil {
		return fmt.Errorf("failed to set pause: %v", err)
	}

	err = cli.SetPause(ethtool.Pause{
		Interface: ethtool.Interface{Name: linkName},
		RX:        optional.Some[bool](true),
		TX:        optional.Some[bool](true),
	})
	if err != nil {
		return fmt.Errorf("failed to set pause: %v", err)
	}

	err = cli.SetPause(ethtool.Pause{
		Interface: ethtool.Interface{Name: linkName},
		Autoneg:   optional.Some[bool](true),
	})
	if err != nil {
		return fmt.Errorf("failed to set pause: %v", err)
	}

	return nil
}
