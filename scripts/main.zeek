module Export_Test;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## Record type containing the column fields of the Export_Test log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## Direction.
		is_orig: bool &log;
		## Content.
		content: A &log;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Default hook into Export_Test logging.
	global log_export_test: event(rec: Info);
}

const ports = {
	2323/tcp
};

redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(Export_Test::LOG, [
		$columns=Info,
		$ev=log_export_test,
		$path="export_test",
		$policy=log_policy]);
	}

event Export_Test::seen_a(c: connection, is_orig: bool, a: A)
	{
	local info = Info(
		$ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig, $content=a);

	Log::write(Export_Test::LOG, info);
	}
