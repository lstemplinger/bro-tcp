@load base/bif/plugins/Bro_TCP.events.bif
@load base/utils/site
@load base/protocols/conn

module retransmissions;

export{
	redef Site::local_nets+={10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16};

	redef enum Log::ID+={LOG1, LOG2};

	type retransmission_log_entry: record{
	conn_uid: string		&log;
	ts: time				&log;
	from_orig: bool			&log;
	bytes: count			&log;
	};

	type retransmission_score_log_entry: record{
	conn_uid: string		&log;
	ts: time				&log;
	from_orig: bool			&log;
	score: double 			&log;
	};
}

type retransmission_info: record{
	max_seq: count;
	bytes_retransmitted: count;
	total_bytes: count;
	logged: bool;
};

global orig_info: table[string] of retransmission_info;
global resp_info: table[string] of retransmission_info;

function log_scores(info_table: table[string] of retransmission_info, from_orig: bool, ts: time){
	local retr_double: double;
	local total_double: double;
	local new_score: double;
	local log_entry: retransmission_score_log_entry;
	for (uid in info_table){
		if (!info_table[uid]$logged){
			info_table[uid]$logged=T;
			retr_double=to_double(fmt("%d", info_table[uid]$bytes_retransmitted));
			total_double=to_double(fmt("%d", info_table[uid]$total_bytes));
			new_score=retr_double/total_double;
			log_entry=retransmission_score_log_entry($conn_uid=uid, $ts=ts, $from_orig=from_orig, $score=new_score);
			Log::write(retransmissions::LOG2, log_entry);
		}
	}
}

event tcp_packet(c: connection, is_orig:bool, flags: string, seq: count, ack: count, len: count, payload: string){ 
	if (len==0){
		return;
	}
	local timestamp=network_time();
	local info_table=resp_info;
	if (is_orig){
		info_table=orig_info;
	}
	if (c$uid !in info_table){
		info_table[c$uid]=retransmission_info($max_seq=seq, $bytes_retransmitted=0, $total_bytes=len, $logged=F);
		return;
	}
	info_table[c$uid]$total_bytes+=len;
	info_table[c$uid]$logged=F;
	if (seq <= info_table[c$uid]$max_seq){
		info_table[c$uid]$bytes_retransmitted+=len;
		local log_entry=retransmission_log_entry($conn_uid=c$uid, $ts=timestamp, $from_orig=is_orig, $bytes=len);
		Log::write(retransmissions::LOG1, log_entry);
		return;
	}
	info_table[c$uid]$max_seq=seq;
}

event score_log_trigger(){
	local ts=network_time();
	log_scores(orig_info, T, ts);
	log_scores(resp_info, F, ts);
	schedule 0.1sec {score_log_trigger()};
}

event bro_init(){
	Log::create_stream(retransmissions::LOG1, [$columns=retransmission_log_entry, $path="retransmission_series"]);
	Log::create_stream(retransmissions::LOG2, [$columns=retransmission_score_log_entry, $path="retransmission_scores"]);
	schedule 0.1sec {score_log_trigger()};
}

event connection_state_remove(c: connection){
	if (c$uid in orig_info){
		delete orig_info[c$uid];
	}
	if (c$uid in resp_info){
		delete resp_info[c$uid];
	}
}