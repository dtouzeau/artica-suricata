package SuricataTools

import "time"

type SuricataStats struct {
	AppLayer struct {
		Error struct {
			BittorrentDHT struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"bittorrent-dht"`
			DcerpcTCP struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"dcerpc_tcp"`
			DcerpcUDP struct {
				Alloc    int `json:"alloc"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"dcerpc_udp"`
			Dhcp struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"dhcp"`
			Dnp3 struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"dnp3"`
			DNSTCP struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"dns_tcp"`
			DNSUDP struct {
				Alloc    int `json:"alloc"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"dns_udp"`
			Enip struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"enip"`
			FailedTCP struct {
				Gap int `json:"gap"`
			} `json:"failed_tcp"`
			FTP struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"ftp"`
			FTPData struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"ftp-data"`
			HTTP struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"http"`
			HTTP2 struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"http2"`
			IKE struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"ike"`
			IMAP struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"imap"`
			Krb5TCP struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"krb5_tcp"`
			Krb5UDP struct {
				Alloc    int `json:"alloc"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"krb5_udp"`
			Modbus struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"modbus"`
			MQTT struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"mqtt"`
			NFSTCP struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"nfs_tcp"`
			NFSUDP struct {
				Alloc    int `json:"alloc"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"nfs_udp"`
			NTP struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"ntp"`
			Pgsql struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"pgsql"`
			Quic struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"quic"`
			RDP struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"rdp"`
			RFB struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"rfb"`
			SIP struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"sip"`
			SMB struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"smb"`
			SMTP struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"smtp"`
			SNMP struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"snmp"`
			SSH struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"ssh"`
			Telnet struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"telnet"`
			TFTP struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"tftp"`
			TLS struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"tls"`
		} `json:"error"`
		Expectations int            `json:"expectations"`
		Flow         map[string]int `json:"flow"`
		Tx           map[string]int `json:"tx"`
	} `json:"app_layer"`
	Capture struct {
		Bypassed      int `json:"bypassed"`
		KernelDrops   int `json:"kernel_drops"`
		KernelPackets int `json:"kernel_packets"`
	} `json:"capture"`
	Decoder struct {
		ARP              int                       `json:"arp"`
		AvgPktSize       int                       `json:"avg_pkt_size"`
		Bytes            int                       `json:"bytes"`
		Chdlc            int                       `json:"chdlc"`
		Erspan           int                       `json:"erspan"`
		Esp              int                       `json:"esp"`
		Ethernet         int                       `json:"ethernet"`
		Event            map[string]map[string]int `json:"event"`
		Geneve           int                       `json:"geneve"`
		Gre              int                       `json:"gre"`
		Icmpv4           int                       `json:"icmpv4"`
		Icmpv6           int                       `json:"icmpv6"`
		Ieee8021ah       int                       `json:"ieee8021ah"`
		Invalid          int                       `json:"invalid"`
		IPv4             int                       `json:"ipv4"`
		IPv4InIPv6       int                       `json:"ipv4_in_ipv6"`
		IPv6             int                       `json:"ipv6"`
		IPv6InIPv6       int                       `json:"ipv6_in_ipv6"`
		MaxMacAddrsDst   int                       `json:"max_mac_addrs_dst"`
		MaxMacAddrsSrc   int                       `json:"max_mac_addrs_src"`
		MaxPktSize       int                       `json:"max_pkt_size"`
		Mpls             int                       `json:"mpls"`
		Nsh              int                       `json:"nsh"`
		Null             int                       `json:"null"`
		Pkts             int                       `json:"pkts"`
		Ppp              int                       `json:"ppp"`
		Pppoe            int                       `json:"pppoe"`
		Raw              int                       `json:"raw"`
		Sctp             int                       `json:"sctp"`
		Sll              int                       `json:"sll"`
		Tcp              int                       `json:"tcp"`
		Teredo           int                       `json:"teredo"`
		TooManyLayers    int                       `json:"too_many_layers"`
		Udp              int                       `json:"udp"`
		UnknownEthertype int                       `json:"unknown_ethertype"`
		Vlan             int                       `json:"vlan"`
		VlanQinq         int                       `json:"vlan_qinq"`
		VlanQinqinq      int                       `json:"vlan_qinqinq"`
		Vntag            int                       `json:"vntag"`
		Vxlan            int                       `json:"vxlan"`
	} `json:"decoder"`
	Defrag struct {
		IPv4 struct {
			Fragments   int `json:"fragments"`
			Reassembled int `json:"reassembled"`
		} `json:"ipv4"`
		IPv6 struct {
			Fragments   int `json:"fragments"`
			Reassembled int `json:"reassembled"`
		} `json:"ipv6"`
		MaxFragHits int `json:"max_frag_hits"`
	} `json:"defrag"`
	Detect struct {
		Alert              int `json:"alert"`
		AlertQueueOverflow int `json:"alert_queue_overflow"`
		AlertsSuppressed   int `json:"alerts_suppressed"`
		Engines            []struct {
			ID           int       `json:"id"`
			LastReload   time.Time `json:"last_reload"`
			RulesFailed  int       `json:"rules_failed"`
			RulesLoaded  int       `json:"rules_loaded"`
			RulesSkipped int       `json:"rules_skipped"`
		} `json:"engines"`
	} `json:"detect"`
	Flow struct {
		Active           int `json:"active"`
		EmergModeEntered int `json:"emerg_mode_entered"`
		EmergModeOver    int `json:"emerg_mode_over"`
		End              struct {
			State struct {
				CaptureBypassed int `json:"capture_bypassed"`
				Closed          int `json:"closed"`
				Established     int `json:"established"`
				LocalBypassed   int `json:"local_bypassed"`
				New             int `json:"new"`
			} `json:"state"`
			TCPLiberal int `json:"tcp_liberal"`
			TCPState   struct {
				CloseWait   int `json:"close_wait"`
				Closed      int `json:"closed"`
				Closing     int `json:"closing"`
				Established int `json:"established"`
				FinWait1    int `json:"fin_wait1"`
				FinWait2    int `json:"fin_wait2"`
				LastAck     int `json:"last_ack"`
				None        int `json:"none"`
				SynRecv     int `json:"syn_recv"`
				SynSent     int `json:"syn_sent"`
				TimeWait    int `json:"time_wait"`
			} `json:"tcp_state"`
		} `json:"end"`
		GetUsed           int `json:"get_used"`
		GetUsedEval       int `json:"get_used_eval"`
		GetUsedEvalBusy   int `json:"get_used_eval_busy"`
		GetUsedEvalReject int `json:"get_used_eval_reject"`
		GetUsedFailed     int `json:"get_used_failed"`
		Icmpv4            int `json:"icmpv4"`
		Icmpv6            int `json:"icmpv6"`
		Memcap            int `json:"memcap"`
		Memuse            int `json:"memuse"`
		Mgr               struct {
			FlowsChecked          int `json:"flows_checked"`
			FlowsEvicted          int `json:"flows_evicted"`
			FlowsEvictedNeedsWork int `json:"flows_evicted_needs_work"`
			FlowsNotimeout        int `json:"flows_notimeout"`
			FlowsTimeout          int `json:"flows_timeout"`
			FullHashPass          int `json:"full_hash_pass"`
			RowsMaxlen            int `json:"rows_maxlen"`
			RowsPerSec            int `json:"rows_per_sec"`
		} `json:"mgr"`
		Recycler struct {
			QueueAvg int `json:"queue_avg"`
			QueueMax int `json:"queue_max"`
			Recycled int `json:"recycled"`
		} `json:"recycler"`
		Spare    int `json:"spare"`
		TCP      int `json:"tcp"`
		TCPReuse int `json:"tcp_reuse"`
		Total    int `json:"total"`
		UDP      int `json:"udp"`
		Wrk      struct {
			FlowsEvicted          int `json:"flows_evicted"`
			FlowsEvictedNeedsWork int `json:"flows_evicted_needs_work"`
			FlowsEvictedPktInject int `json:"flows_evicted_pkt_inject"`
			FlowsInjected         int `json:"flows_injected"`
			FlowsInjectedMax      int `json:"flows_injected_max"`
			SpareSync             int `json:"spare_sync"`
			SpareSyncAvg          int `json:"spare_sync_avg"`
			SpareSyncEmpty        int `json:"spare_sync_empty"`
			SpareSyncIncomplete   int `json:"spare_sync_incomplete"`
		} `json:"wrk"`
	} `json:"flow"`
	FlowBypassed struct {
		Bytes             int `json:"bytes"`
		Closed            int `json:"closed"`
		LocalBytes        int `json:"local_bytes"`
		LocalCaptureBytes int `json:"local_capture_bytes"`
		LocalCapturePkts  int `json:"local_capture_pkts"`
		LocalPkts         int `json:"local_pkts"`
		Pkts              int `json:"pkts"`
	} `json:"flow_bypassed"`
	FTP struct {
		Memcap int `json:"memcap"`
		Memuse int `json:"memuse"`
	} `json:"ftp"`
	HTTP struct {
		Memcap int `json:"memcap"`
		Memuse int `json:"memuse"`
	} `json:"http"`
	MemcapPressure    int `json:"memcap_pressure"`
	MemcapPressureMax int `json:"memcap_pressure_max"`
	TCP               struct {
		AckUnseenData         int `json:"ack_unseen_data"`
		ActiveSessions        int `json:"active_sessions"`
		InsertDataNormalFail  int `json:"insert_data_normal_fail"`
		InsertDataOverlapFail int `json:"insert_data_overlap_fail"`
		InvalidChecksum       int `json:"invalid_checksum"`
		MidstreamPickups      int `json:"midstream_pickups"`
		Overlap               int `json:"overlap"`
		OverlapDiffData       int `json:"overlap_diff_data"`
		PktOnWrongThread      int `json:"pkt_on_wrong_thread"`
		Pseudo                int `json:"pseudo"`
		PseudoFailed          int `json:"pseudo_failed"`
		ReassemblyGap         int `json:"reassembly_gap"`
		ReassemblyMemuse      int `json:"reassembly_memuse"`
		Rst                   int `json:"rst"`
		SegmentFromCache      int `json:"segment_from_cache"`
		SegmentFromPool       int `json:"segment_from_pool"`
		SegmentMemcapDrop     int `json:"segment_memcap_drop"`
		Sessions              int `json:"sessions"`
		SsnFromCache          int `json:"ssn_from_cache"`
		SsnFromPool           int `json:"ssn_from_pool"`
		SsnMemcapDrop         int `json:"ssn_memcap_drop"`
		StreamDepthReached    int `json:"stream_depth_reached"`
		Syn                   int `json:"syn"`
		Synack                int `json:"synack"`
		Urg                   int `json:"urg"`
		UrgentOobData         int `json:"urgent_oob_data"`
	} `json:"tcp"`
	Threads map[string]struct {
		AppLayer struct {
			Error map[string]struct {
				Alloc    int `json:"alloc"`
				Gap      int `json:"gap"`
				Internal int `json:"internal"`
				Parser   int `json:"parser"`
			} `json:"error"`
			Flow map[string]int `json:"flow"`
			Tx   map[string]int `json:"tx"`
		} `json:"app_layer"`
		Capture struct {
			Bypassed      int `json:"bypassed"`
			KernelDrops   int `json:"kernel_drops"`
			KernelPackets int `json:"kernel_packets"`
		} `json:"capture"`
		Decoder struct {
			ARP              int                       `json:"arp"`
			AvgPktSize       int                       `json:"avg_pkt_size"`
			Bytes            int                       `json:"bytes"`
			Chdlc            int                       `json:"chdlc"`
			Erspan           int                       `json:"erspan"`
			Esp              int                       `json:"esp"`
			Ethernet         int                       `json:"ethernet"`
			Event            map[string]map[string]int `json:"event"`
			Geneve           int                       `json:"geneve"`
			Gre              int                       `json:"gre"`
			Icmpv4           int                       `json:"icmpv4"`
			Icmpv6           int                       `json:"icmpv6"`
			Ieee8021ah       int                       `json:"ieee8021ah"`
			Invalid          int                       `json:"invalid"`
			IPv4             int                       `json:"ipv4"`
			IPv4InIPv6       int                       `json:"ipv4_in_ipv6"`
			IPv6             int                       `json:"ipv6"`
			IPv6InIPv6       int                       `json:"ipv6_in_ipv6"`
			MaxMacAddrsDst   int                       `json:"max_mac_addrs_dst"`
			MaxMacAddrsSrc   int                       `json:"max_mac_addrs_src"`
			MaxPktSize       int                       `json:"max_pkt_size"`
			Mpls             int                       `json:"mpls"`
			Nsh              int                       `json:"nsh"`
			Null             int                       `json:"null"`
			Pkts             int                       `json:"pkts"`
			Ppp              int                       `json:"ppp"`
			Pppoe            int                       `json:"pppoe"`
			Raw              int                       `json:"raw"`
			Sctp             int                       `json:"sctp"`
			Sll              int                       `json:"sll"`
			Tcp              int                       `json:"tcp"`
			Teredo           int                       `json:"teredo"`
			TooManyLayers    int                       `json:"too_many_layers"`
			Udp              int                       `json:"udp"`
			UnknownEthertype int                       `json:"unknown_ethertype"`
			Vlan             int                       `json:"vlan"`
			VlanQinq         int                       `json:"vlan_qinq"`
			VlanQinqinq      int                       `json:"vlan_qinqinq"`
			Vntag            int                       `json:"vntag"`
			Vxlan            int                       `json:"vxlan"`
		} `json:"decoder"`
		Defrag struct {
			IPv4 struct {
				Fragments   int `json:"fragments"`
				Reassembled int `json:"reassembled"`
			} `json:"ipv4"`
			IPv6 struct {
				Fragments   int `json:"fragments"`
				Reassembled int `json:"reassembled"`
			} `json:"ipv6"`
			MaxFragHits int `json:"max_frag_hits"`
		} `json:"defrag"`
		Detect struct {
			Alert              int `json:"alert"`
			AlertQueueOverflow int `json:"alert_queue_overflow"`
			AlertsSuppressed   int `json:"alerts_suppressed"`
			Engines            []struct {
				ID           int       `json:"id"`
				LastReload   time.Time `json:"last_reload"`
				RulesFailed  int       `json:"rules_failed"`
				RulesLoaded  int       `json:"rules_loaded"`
				RulesSkipped int       `json:"rules_skipped"`
			} `json:"engines"`
		} `json:"detect"`
		Flow struct {
			Active int `json:"active"`
			End    struct {
				State struct {
					CaptureBypassed int `json:"capture_bypassed"`
					Closed          int `json:"closed"`
					Established     int `json:"established"`
					LocalBypassed   int `json:"local_bypassed"`
					New             int `json:"new"`
				} `json:"state"`
				TCPLiberal int `json:"tcp_liberal"`
				TCPState   struct {
					CloseWait   int `json:"close_wait"`
					Closed      int `json:"closed"`
					Closing     int `json:"closing"`
					Established int `json:"established"`
					FinWait1    int `json:"fin_wait1"`
					FinWait2    int `json:"fin_wait2"`
					LastAck     int `json:"last_ack"`
					None        int `json:"none"`
					SynRecv     int `json:"syn_recv"`
					SynSent     int `json:"syn_sent"`
					TimeWait    int `json:"time_wait"`
				} `json:"tcp_state"`
			} `json:"end"`
			GetUsed           int `json:"get_used"`
			GetUsedEval       int `json:"get_used_eval"`
			GetUsedEvalBusy   int `json:"get_used_eval_busy"`
			GetUsedEvalReject int `json:"get_used_eval_reject"`
			GetUsedFailed     int `json:"get_used_failed"`
			Icmpv4            int `json:"icmpv4"`
			Icmpv6            int `json:"icmpv6"`
			Memcap            int `json:"memcap"`
			TCP               int `json:"tcp"`
			TCPReuse          int `json:"tcp_reuse"`
			Total             int `json:"total"`
			UDP               int `json:"udp"`
			Wrk               struct {
				FlowsEvicted          int `json:"flows_evicted"`
				FlowsEvictedNeedsWork int `json:"flows_evicted_needs_work"`
				FlowsEvictedPktInject int `json:"flows_evicted_pkt_inject"`
				FlowsInjected         int `json:"flows_injected"`
				FlowsInjectedMax      int `json:"flows_injected_max"`
				SpareSync             int `json:"spare_sync"`
				SpareSyncAvg          int `json:"spare_sync_avg"`
				SpareSyncEmpty        int `json:"spare_sync_empty"`
				SpareSyncIncomplete   int `json:"spare_sync_incomplete"`
			} `json:"wrk"`
		} `json:"flow"`
		FlowBypassed struct {
			LocalBytes        int `json:"local_bytes"`
			LocalCaptureBytes int `json:"local_capture_bytes"`
			LocalCapturePkts  int `json:"local_capture_pkts"`
			LocalPkts         int `json:"local_pkts"`
		} `json:"flow_bypassed"`
		TCP struct {
			AckUnseenData         int `json:"ack_unseen_data"`
			ActiveSessions        int `json:"active_sessions"`
			InsertDataNormalFail  int `json:"insert_data_normal_fail"`
			InsertDataOverlapFail int `json:"insert_data_overlap_fail"`
			InvalidChecksum       int `json:"invalid_checksum"`
			MidstreamPickups      int `json:"midstream_pickups"`
			Overlap               int `json:"overlap"`
			OverlapDiffData       int `json:"overlap_diff_data"`
			PktOnWrongThread      int `json:"pkt_on_wrong_thread"`
			Pseudo                int `json:"pseudo"`
			PseudoFailed          int `json:"pseudo_failed"`
			ReassemblyGap         int `json:"reassembly_gap"`
			Rst                   int `json:"rst"`
			SegmentFromCache      int `json:"segment_from_cache"`
			SegmentFromPool       int `json:"segment_from_pool"`
			SegmentMemcapDrop     int `json:"segment_memcap_drop"`
			Sessions              int `json:"sessions"`
			SsnFromCache          int `json:"ssn_from_cache"`
			SsnFromPool           int `json:"ssn_from_pool"`
			SsnMemcapDrop         int `json:"ssn_memcap_drop"`
			StreamDepthReached    int `json:"stream_depth_reached"`
			Syn                   int `json:"syn"`
			Synack                int `json:"synack"`
			Urg                   int `json:"urg"`
			UrgentOobData         int `json:"urgent_oob_data"`
		} `json:"tcp"`
	} `json:"threads"`
	Uptime int `json:"uptime"`
}
