@load base/bif/plugins/Bro_TCP.events.bif
@load base/utils/site
@load base/protocols/conn

module ack;

export{
	redef Site::local_nets+={10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16};

	redef enum Log::ID+={LOG};

	type ack_log_entry: record{
		conn_uid: string			&log;
		ts: time 					&log;
		from_orig: bool				&log;
		ack: count					&log;
		bytes_acknowledged: count	&log;
		ack_interval: interval 		&log;
	};
}

type ack_time: record{
	ack: count;
	timestamp: time;
};

global last_orig_acks: table[string] of ack_time;
global last_resp_acks: table[string] of ack_time;

function handle_ack(last_ack: ack_time, ack: count, ts: time, from_orig: bool, c: connection, first_ack: bool){
	local num_acknowledged=ack-last_ack$ack;
	local time_diff=(ts-last_ack$timestamp);
	local log_entry=ack_log_entry($conn_uid=c$uid, $ts=ts, $from_orig=from_orig, $ack=ack, $bytes_acknowledged=num_acknowledged, $ack_interval=time_diff);
	Log::write(ack::LOG, log_entry);
	flush_all();
}

event bro_init(){
	Log::create_stream(ack::LOG, [$columns=ack_log_entry, $path="acks"]);
}

event tcp_packet(c: connection, is_orig:bool, flags: string, seq: count, ack: count, len: count, payload: string){
	if ("A" !in flags){
		return;
	}
	local timestamp=network_time();
	local first_ack: bool;
	local last_acks=last_resp_acks;
	if (is_orig){
		last_acks=last_orig_acks;
	}
	first_ack=(c$uid !in last_acks);
	if (first_ack){
		last_acks[c$uid]=ack_time($ack=ack, $timestamp=timestamp);
	}
	if (ack <= last_acks[c$uid]$ack && !first_ack){
			return;
	}
	handle_ack(last_acks[c$uid], ack, timestamp, is_orig, c, first_ack);
	last_acks[c$uid]=ack_time($ack=ack, $timestamp=timestamp);
}


event connection_state_remove(c: connection){
	if (c$uid in last_orig_acks){
		delete last_orig_acks[c$uid];
	}
	if (c$uid in last_resp_acks){
		delete last_resp_acks[c$uid];
	}
}


