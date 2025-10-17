package articasys

import (
	"context"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/cpu"
	"math"
	"runtime"
	"sockets"
	"strings"
	"sync"
	"time"
)

func getCalleRuntime() string {
	if pc, file, line, ok := runtime.Caller(1); ok {
		file = file[strings.LastIndex(file, "/")+1:]
		funcName := runtime.FuncForPC(pc).Name()
		funcName = strings.ReplaceAll(funcName, "github.com/dtouzeau/articarest/", "")
		return fmt.Sprintf("%s[%s:%d]", file, funcName, line)
	}
	return ""
}

func CpuLoop() {
	var usageSamples []float64
	interval := 10 * time.Second
	duration := 5 * time.Minute

	endTime := time.Now().Add(duration)

	for time.Now().Before(endTime) {
		// Collect CPU usage.
		percent, err := cpu.Percent(interval, false)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%v Error retrieving CPU usage: %v", getCalleRuntime(), err.Error()))
			return
		}
		if len(percent) > 0 {
			sockets.SET_INFO_STR("RT_CPU_AVG", fmt.Sprintf("%.2f", percent[0]))
			usageSamples = append(usageSamples, percent[0])
		}
	}
	var total float64
	for _, sample := range usageSamples {
		total += sample
	}
	averageUsage := total / float64(len(usageSamples))
	Cpu := fmt.Sprintf("%.2f", averageUsage)
	log.Info().Msg(fmt.Sprintf("%v: Average CPU usage over %v: %.2f%%", getCalleRuntime(), duration, averageUsage))
	sockets.SET_INFO_STR("CURRENT_CPU_AVG", Cpu)

}
func CpuUsage() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	averages, err := GetCPUUtilizationAveragesContext(ctx, 0)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		for i, avg := range averages {
			fmt.Printf("Minute %d: %.2f%%\n", i+1, avg)
		}
	}
}

func GetCPUUtilizationAveragesContext(ctx context.Context, numMinutes int) ([]float64, error) {
	if numMinutes < 0 {
		return nil, fmt.Errorf("number of minutes must be non-negative")
	}

	var averages []float64
	var mu sync.Mutex

	_, err := cpu.Percent(0, false)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize CPU monitoring: %v", err)
	}

	for i := 0; numMinutes == 0 || i < numMinutes; i++ {
		var sum float64
		var count int
		start := time.Now()
		end := start.Add(time.Minute)

		for time.Now().Before(end) {
			select {
			case <-ctx.Done():
				return averages, ctx.Err()
			default:
				percent, err := cpu.Percent(time.Second, false)
				if err != nil {
					return averages, fmt.Errorf("failed to get CPU percent at sample %d: %v", count, err)
				}
				if len(percent) > 0 {
					sum += percent[0]
					count++
				}
				time.Sleep(time.Second - time.Since(start.Add(time.Duration(count)*time.Second)))
			}
		}

		if count > 0 {
			avg := sum / float64(count)
			avg = math.Round(avg*100) / 100
			mu.Lock()
			averages = append(averages, avg)
			mu.Unlock()
		} else {
			return averages, fmt.Errorf("no CPU data collected for minute %d", i+1)
		}
	}

	return averages, nil
}
