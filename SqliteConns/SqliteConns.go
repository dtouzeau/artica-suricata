package SqliteConns

//SqliteConns.CertifcatesConnectRW()
import (
	"csqlite"
	"database/sql"
	"fmt"
	"futils"
	"os"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

const MainDir = "/home/artica/SQLITE"

func HotSpotConnectRW() (*sql.DB, error) {
	_ = os.MkdirAll("/home/squid/hotspot", 0755)
	databaseFile := "/home/squid/hotspot/database.db"
	db, err := sql.Open("sqlite3", databaseFile)
	if err != nil {
		log.Error().Msg(err.Error())
		return nil, err
	}
	csqlite.ConfigureDBPool(db)
	return db, nil
}
func SiegeConnectRW() (*sql.DB, error) {
	return connectRW("siege.db")
}
func SSHDConnectRW() (*sql.DB, error) {
	return connectRW("sshd.db")
}
func SSHDConnectRo() (*sql.DB, error) {
	return connectRO("sshd.db")
}
func ClusterConnectDB() (*sql.DB, error) {
	return connectRW("haproxy.db")
}
func SyncthingConnectRW() (*sql.DB, error) {
	return connectRW("syncthing.db")
}
func SyncthingConnectRO() (*sql.DB, error) {
	return connectRO("syncthing.db")
}
func ClusterEventsConnectRW() (*sql.DB, error) {
	return connectRW("clusters_events.db")
}

func SuricataConnectRO() (*sql.DB, error) {
	return connectRO("suricata.db")
}
func SuricataConnectRW() (*sql.DB, error) {
	return connectRW("suricata.db")
}
func WebConsoleConnectRO() (*sql.DB, error) {
	return connectRO("webconsole.db")
}
func WebConsoleConnectRW() (*sql.DB, error) {
	return connectRW("webconsole.db")
}

func CategoriesBackupConnectRW() (*sql.DB, error) {
	return connectRW("categoriesbackup.db")
}
func CategoriesBackupConnectRO() (*sql.DB, error) {
	return connectRO("categoriesbackup.db")
}

func NotifsConnectRO() (*sql.DB, error) {
	return connectRO("system_events.db")
}
func NotifsConnectRW() (*sql.DB, error) {
	return connectRW("system_events.db")
}
func WebFilterConnectRW() (*sql.DB, error) {
	return connectRW("webfilter.db")
}
func WebFilterConnectRO() (*sql.DB, error) {
	return connectRO("webfilter.db")
}
func ClusterConnectRo() (*sql.DB, error) {
	return connectRO("haproxy.db")
}
func ClusterConnectRW() (*sql.DB, error) {
	return connectRW("haproxy.db")
}
func CertifcatesConnectRW() (*sql.DB, error) {
	return connectRW("certificates.db")
}
func CertifcatesConnectRO() (*sql.DB, error) {
	return connectRO("certificates.db")
}
func HaproxyConnectWR() (*sql.DB, error) {
	return ClusterConnectDB()
}
func RPZConnectRO() (*sql.DB, error) {
	return connectRO("rpz.db")
}
func RPZConnectRW() (*sql.DB, error) {
	return connectRW("rpz.db")
}
func IncidentsConnectRW() (*sql.DB, error) {
	databaseFile := "/home/artica/SQLITE_TEMP/system.perf.queue.db"
	FileSize := futils.FileSizeMB(databaseFile)
	if FileSize > 2000 {
		futils.DeleteFile(fmt.Sprintf("%v-shm", databaseFile))
		futils.DeleteFile(fmt.Sprintf("%v-wal", databaseFile))
		futils.DeleteFile(databaseFile)
	}
	_ = os.Mkdir("/home/artica/SQLITE_TEMP", 0755)
	db, err := sql.Open("sqlite3", databaseFile)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return nil, err
	}
	log.Debug().Msgf("%v OPEN %v", futils.GetCalleRuntime(), databaseFile)
	csqlite.ConfigureDBPool(db)
	return db, nil
}

func FtpusersRO() (*sql.DB, error) {
	return connectRW("ftpusers.db")
}
func SysDBConnectRW() (*sql.DB, error) {
	return connectRW("sys.db")
}
func SysDBConnectRO() (*sql.DB, error) {
	return connectRW("sys.db")
}
func SudoersConnectRW() (*sql.DB, error) {
	return connectRW("sudoers.db")
}
func SudoersConnectRO() (*sql.DB, error) {
	return connectRO("sudoers.db")
}
func NginxConnectRW() (*sql.DB, error) {
	return connectRW("nginx.db")
}
func NginxConnectRO() (*sql.DB, error) {
	return connectRO("nginx.db")
}
func UnboundConnectRO() (*sql.DB, error) {
	return connectRO("unbound.db")
}
func UnboundConnectRW() (*sql.DB, error) {
	return connectRW("unbound.db")
}
func DNSConnectRW() (*sql.DB, error) {
	return connectRW("dns.db")
}
func DNSConnectRO() (*sql.DB, error) {
	return connectRO("dns.db")
}
func AclsConnectRW() (*sql.DB, error) {
	return connectRW("acls.db")
}
func SSLDBConnectRW() (*sql.DB, error) {
	return connectRW("ssl_db.db")
}
func SSLDBConnectRO() (*sql.DB, error) {
	return connectRO("ssl_db.db")
}
func NightlyConnectRW() (*sql.DB, error) {
	return connectRW("nightly.db")
}
func AclsConnectRO() (*sql.DB, error) {
	return connectRO("acls.db")
}
func IdentityConnectRO() (*sql.DB, error) {
	return connectRO("identity.db")
}
func ProxConsRW() (*sql.DB, error) {
	return connectRO("ProxCons.db")
}

func DHCPDConnectRO() (*sql.DB, error) {
	return connectRO("dhcpd.db")
}
func DHCPDConnectRW() (*sql.DB, error) {
	return connectRW("dhcpd.db")
}
func InterfacesConnectRO() (*sql.DB, error) {
	return connectRO("interfaces.db")
}

func PgTablesConnectRW() (*sql.DB, error) {
	return connectRW("/home/artica/SQLITE_TEMP/pg_tables.db")
}
func InterfacesConnectRW() (*sql.DB, error) {
	return connectRW("interfaces.db")
}
func CrowdSecAlertRW() (*sql.DB, error) {
	return connectRW("crowdsec-events.db")
}

func AutoFSRO() (*sql.DB, error) {
	return connectRO("autofs.db")
}
func AutoFSRW() (*sql.DB, error) {
	return connectRW("autofs.db")
}
func ProxyConnectRO() (*sql.DB, error) {
	return connectRO("proxy.db")
}
func ProxyConnectRW() (*sql.DB, error) {
	return connectRW("proxy.db")
}
func connectRO(sqlitefile string) (*sql.DB, error) {
	databaseFile := MainDir + "/" + sqlitefile
	dsn := fmt.Sprintf("file:%v?mode=ro&_busy_timeout=5000", databaseFile)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		log.Error().Msg(err.Error())
		return nil, err
	}
	db.SetMaxOpenConns(25)                 // Maximum number of open connections to the database
	db.SetMaxIdleConns(25)                 // Maximum number of idle connections
	db.SetConnMaxLifetime(5 * time.Minute) // Maximum lifetime of a connection (to avoid stale connections)
	return db, nil
}
func connectRW(sqlitefile string) (*sql.DB, error) {
	databaseFile := MainDir + "/" + sqlitefile
	if strings.Contains(sqlitefile, "/") {
		databaseFile = sqlitefile
	}
	dsn := fmt.Sprintf("file:%v?_busy_timeout=5000", databaseFile)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		log.Error().Msg(err.Error())
		return nil, err
	}
	log.Debug().Msgf("%v %v OPEN DB", futils.GetCalleRuntime(), databaseFile)
	csqlite.ConfigureDBPool(db)
	futils.Chmod(databaseFile, 0755)
	futils.ChownFile(databaseFile, "www-data", "www-data")
	if db == nil {
		return nil, fmt.Errorf("%v got nil database connection from SqliteConns.AclsConnectRW()", futils.GetCalleRuntime())
	}

	return db, nil
}
func HaproxyConnectDBRO() (*sql.DB, error) {
	return connectRO("haproxy.db")
}
func FirewallConnectRO() (*sql.DB, error) {
	return connectRO("firewall.db")
}
func FirewallConnectRW() (*sql.DB, error) {
	return connectRW("firewall.db")
}
func PulseReverseConnectDBRO() (*sql.DB, error) {
	return connectRO("PulseReverse.db")
}
func PulseReverseConnectDBRW() (*sql.DB, error) {
	return connectRW("PulseReverse.db")
}
func RDPPRoxyConnectDBRW() (*sql.DB, error) {
	return connectRW("rdpproxy.db")
}
