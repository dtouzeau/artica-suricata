package afirewall

import (
	"IfacesStruct"
	"SqliteConns"
	"bufio"
	"database/sql"
	"fmt"
	"futils"
	"ipclass"
	"iproutes"
	"os"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
)

func CleanFirewallRoutingTables() error {
	filePath := "/etc/iproute2/rt_tables"
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open rt_tables file: %v", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	var newTable []string
	writeFile := false
	scanner := bufio.NewScanner(file)

	routeMarkPattern := regexp.MustCompile(`^RouteMark[0-9]+`)
	linePattern := regexp.MustCompile(`^([0-9]+)\s+(.+)$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		matches := linePattern.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		tableName := matches[2]
		TableID := futils.StrToInt(matches[1])
		if routeMarkPattern.MatchString(tableName) {
			err := iproutes.RemoveTableRules(TableID)
			if err != nil {
				log.Error().Msgf("%v Error removing table rules: %v", futils.GetCalleRuntime(), err)
			}

			writeFile = true
			continue
		}

		newTable = append(newTable, line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading rt_tables file: %v", err)
	}

	if writeFile {
		if err := os.WriteFile(filePath, []byte(strings.Join(newTable, "\n")+"\n"), 0644); err != nil {
			return fmt.Errorf("%v failed to write rt_tables file: %v", futils.GetCalleRuntime(), err)
		}
	}

	return nil
}

func CreateFirewallRoutingTables() error {

	db, err := SqliteConns.FirewallConnectRO()
	if err != nil {
		log.Error().Msgf("%v Error connecting to database: %v", futils.GetCalleRuntime(), err)
		return err
	}

	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	rows, err := db.Query(`SELECT ID,eth,isClient,MARK,ForwardNIC,ForwardTo FROM iptables_main WHERE enabled=1 AND accepttype='MARK' ORDER by zOrder`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return err
	}
	err = CleanFirewallRoutingTables()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return err
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	for rows.Next() {

		var ID, MARK int
		var outface, ForwardNIC, ForwardTo string
		var isClient sql.NullString

		err = rows.Scan(&ID, &outface, &isClient, &MARK, &ForwardNIC, &ForwardTo)
		if err != nil {
			log.Error().Msgf("%v Error SCANNING ROW : %v", futils.GetCalleRuntime(), err)
			return err
		}
		if MARK == 0 {
			log.Warn().Msgf("%v Rule %d mark 0 Invalid", futils.GetCalleRuntime(), ID)
			continue
		}
		if !ipclass.IsIPAddress(ForwardTo) {
			log.Warn().Msgf("%v Rule %d mark %d ForwardTo %v Invalid", futils.GetCalleRuntime(), ID, MARK, ForwardTo)
			continue
		}
		if outface != ForwardNIC {
			outface = ForwardNIC
		}
		rtTablesId := 1000 + ID
		RoutingTableName := fmt.Sprintf("RouteMark%d", rtTablesId)
		err = iproutes.CreatTable(rtTablesId, RoutingTableName)
		if err != nil {
			log.Warn().Msgf("%v Rule %d mark %d ForwardTo %v Unable to create rt_tables %v", futils.GetCalleRuntime(), ID, MARK, ForwardTo, err.Error())
			continue
		}

		err = iproutes.AddDefaultToTable(IfacesStruct.RouteConfig{
			Metric:  0,
			Gateway: ForwardTo,
			Iface:   outface,
			Table:   rtTablesId,
		})
		if err != nil {
			log.Warn().Msgf("%v Rule %d mark %d ForwardTo %v table ID %d Unable to create route", futils.GetCalleRuntime(), ID, MARK, ForwardTo, rtTablesId, err.Error())
			continue
		}
		err := CreateIncomingIPMarkRule(outface, MARK, rtTablesId)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
	}
	return nil
	//
}

// ip rule add iif {$ligne["eth"]} fwmark $MARK table $rt_tables_id
func CreateIncomingIPMarkRule(Interface string, fwmark int, tableID int) error {
	// Get the network link for the incoming interface
	_, err := netlink.LinkByName(Interface)
	if err != nil {
		return fmt.Errorf("could not get link for interface %s: %v", Interface, err)
	}

	// Create a new IP rule
	rule := netlink.NewRule()
	rule.IifName = Interface
	rule.Mark = uint32(fwmark)
	rule.Table = tableID
	rule.Priority = 32766 // Default priority for rules

	// Add the IP rule
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("%v could not add rule: %v", futils.GetCalleRuntime(), err)
	}

	return nil
}
