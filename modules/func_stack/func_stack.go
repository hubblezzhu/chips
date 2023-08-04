package func_stack

import (
	"os"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"

	log "github.com/sirupsen/logrus"
)

const cpuOnline = "/sys/devices/system/cpu/online"

// Get returns a slice with the online CPUs, for example `[0, 2, 3]`
func GetCpuRange() ([]uint, error) {
	buf, err := os.ReadFile(cpuOnline)
	if err != nil {
		return nil, err
	}
	return ReadCPURange(string(buf))
}

// loosely based on https://github.com/iovisor/bcc/blob/v0.3.0/src/python/bcc/utils.py#L15
func ReadCPURange(cpuRangeStr string) ([]uint, error) {
	var cpus []uint
	cpuRangeStr = strings.Trim(cpuRangeStr, "\n ")
	for _, cpuRange := range strings.Split(cpuRangeStr, ",") {
		rangeOp := strings.SplitN(cpuRange, "-", 2)
		first, err := strconv.ParseUint(rangeOp[0], 10, 32)
		if err != nil {
			return nil, err
		}
		if len(rangeOp) == 1 {
			cpus = append(cpus, uint(first))
			continue
		}
		last, err := strconv.ParseUint(rangeOp[1], 10, 32)
		if err != nil {
			return nil, err
		}
		for n := first; n <= last; n++ {
			cpus = append(cpus, uint(n))
		}
	}
	return cpus, nil
}

func attachPerfEvents(stackBpfObj *stackObjects) error {
	var cpus []uint
	var err error

	var sampleRate int = 97

	if cpus, err = GetCpuRange(); err != nil {
		return fmt.Errorf("get cpuonline: %w", err)
	}
	for _, cpu := range cpus {
		pe, err := newPerfEvent(int(cpu), sampleRate)
		if err != nil {
			return fmt.Errorf("new perf event: %w", err)
		}

		err = pe.attachPerfEvent(stackBpfObj.stackPrograms.DoPerfEvent)
		if err != nil {
			return fmt.Errorf("attach perf event: %w", err)
		}
	}
	return nil
}

func loadStackBpfProg() error {
	var stackBpfObj stackObjects

	opts := &ebpf.CollectionOptions{}
	if err := loadStackObjects(&stackBpfObj, opts); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	log.Info("load bpf objects success.")

	if err := attachPerfEvents(&stackBpfObj); err != nil {
		return fmt.Errorf("attach perf events: %w", err)
	}

	log.Info("attach bpf objects success.")
	return nil
}
