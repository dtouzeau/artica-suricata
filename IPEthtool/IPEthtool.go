package IPEthtool

import (
	"bytes"
	"context"
	"fmt"
	"futils"
	"os/exec"
	"strings"
	"time"
)

// DisableOffloading disables hardware offloading features on a network interface
// This is required for proper packet capture with Suricata/PF_RING
func DisableOffloading(interfaceName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Build the ethtool command
	args := []string{
		"-K", interfaceName,
		"rx", "off",
		"tx", "off",
		"sg", "off",
		"tso", "off",
		"ufo", "off",
		"gso", "off",
		"gro", "off",
		"lro", "off",
	}

	cmd := exec.CommandContext(ctx, "ethtool", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("ethtool failed: %w\nStderr: %s", err, stderr.String())
		}
		return fmt.Errorf("ethtool failed: %w", err)
	}

	return nil
}

// DisableOffloadingWithOutput disables offloading and returns command output
func DisableOffloadingWithOutput(interfaceName string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args := []string{
		"-K", interfaceName,
		"rx", "off",
		"tx", "off",
		"sg", "off",
		"tso", "off",
		"ufo", "off",
		"gso", "off",
		"gro", "off",
		"lro", "off",
	}
	ethtool := futils.FindProgram("ethtool")
	cmd := exec.CommandContext(ctx, ethtool, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		output := stdout.String()
		if stderr.Len() > 0 {
			output += "\nStderr: " + stderr.String()
		}
		return output, fmt.Errorf("ethtool failed: %w", err)
	}

	return stdout.String(), nil
}

// DisableOffloadingMultiple disables offloading on multiple interfaces
func DisableOffloadingMultiple(interfaces []string) error {
	for _, iface := range interfaces {
		if err := DisableOffloading(iface); err != nil {
			return fmt.Errorf("failed to disable offloading on %s: %w", iface, err)
		}
	}
	return nil
}

// GetOffloadStatus retrieves current offloading status for an interface
func GetOffloadStatus(interfaceName string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ethtool := futils.FindProgram("ethtool")
	cmd := exec.CommandContext(ctx, ethtool, "-k", interfaceName)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("ethtool -k failed: %w\nStderr: %s", err, stderr.String())
		}
		return nil, fmt.Errorf("ethtool -k failed: %w", err)
	}

	// Parse output into map
	status := make(map[string]string)
	lines := strings.Split(stdout.String(), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Look for "feature: status" pattern
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				feature := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				status[feature] = value
			}
		}
	}

	return status, nil
}

// VerifyOffloadingDisabled checks if all offloading features are disabled
func VerifyOffloadingDisabled(interfaceName string) (bool, []string, error) {
	status, err := GetOffloadStatus(interfaceName)
	if err != nil {
		return false, nil, err
	}

	// Features that should be disabled
	requiredOff := []string{
		"rx-checksumming",
		"tx-checksumming",
		"scatter-gather",
		"tcp-segmentation-offload",
		"udp-fragmentation-offload",
		"generic-segmentation-offload",
		"generic-receive-offload",
		"large-receive-offload",
	}

	var stillEnabled []string

	for _, feature := range requiredOff {
		if val, ok := status[feature]; ok {
			// Check if it contains "on" (might be "on" or "on [fixed]")
			if strings.Contains(strings.ToLower(val), "on") {
				stillEnabled = append(stillEnabled, feature)
			}
		}
	}

	return len(stillEnabled) == 0, stillEnabled, nil
}

// DisableOffloadingWithVerify disables offloading and verifies it worked
func DisableOffloadingWithVerify(interfaceName string) error {
	// Disable offloading
	if err := DisableOffloading(interfaceName); err != nil {
		return err
	}

	// Verify
	allOff, stillEnabled, err := VerifyOffloadingDisabled(interfaceName)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	if !allOff {
		return fmt.Errorf("some features still enabled: %v", stillEnabled)
	}

	return nil
}

// DisableSpecificOffloads allows disabling specific offload features
func DisableSpecificOffloads(interfaceName string, features []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Build args: ethtool -K interface feature1 off feature2 off ...
	args := []string{"-K", interfaceName}
	for _, feature := range features {
		args = append(args, feature, "off")
	}
	ethtool := futils.FindProgram("ethtool")
	cmd := exec.CommandContext(ctx, ethtool, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("ethtool failed: %w\nStderr: %s", err, stderr.String())
		}
		return fmt.Errorf("ethtool failed: %w", err)
	}

	return nil
}

// Example usage and testing
func TestExample() {
	interfaceName := "ens224"

	fmt.Printf("=== Disabling Hardware Offloading on %s ===\n\n", interfaceName)

	// Method 1: Simple disable
	fmt.Println("Method 1: Simple disable")
	err := DisableOffloading(interfaceName)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("✓ Successfully disabled offloading")
	}
	fmt.Println()

	// Method 2: Disable with output
	fmt.Println("Method 2: Disable with output")
	output, err := DisableOffloadingWithOutput(interfaceName)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("✓ Success\nOutput: %s\n", output)
	}
	fmt.Println()

	// Method 3: Get current status
	fmt.Println("Method 3: Get current offload status")
	status, err := GetOffloadStatus(interfaceName)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Current offload features:")
		for feature, value := range status {
			if strings.Contains(feature, "checksum") ||
				strings.Contains(feature, "offload") ||
				strings.Contains(feature, "scatter-gather") {
				fmt.Printf("  %s: %s\n", feature, value)
			}
		}
	}
	fmt.Println()

	// Method 4: Verify offloading is disabled
	fmt.Println("Method 4: Verify offloading is disabled")
	allOff, stillEnabled, err := VerifyOffloadingDisabled(interfaceName)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		if allOff {
			fmt.Println("✓ All offloading features are disabled")
		} else {
			fmt.Printf("✗ Some features still enabled: %v\n", stillEnabled)
		}
	}
	fmt.Println()

	// Method 5: Disable with verification
	fmt.Println("Method 5: Disable with automatic verification")
	err = DisableOffloadingWithVerify(interfaceName)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("✓ Successfully disabled and verified all offloading")
	}
	fmt.Println()

	// Method 6: Disable multiple interfaces
	fmt.Println("Method 6: Disable on multiple interfaces")
	interfaces := []string{"ens224", "ens192"}
	err = DisableOffloadingMultiple(interfaces)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("✓ Successfully disabled offloading on: %v\n", interfaces)
	}
	fmt.Println()

	// Method 7: Disable specific features only
	fmt.Println("Method 7: Disable specific features")
	specificFeatures := []string{"rx", "tx", "gro"}
	err = DisableSpecificOffloads(interfaceName, specificFeatures)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("✓ Disabled features: %v\n", specificFeatures)
	}
}
