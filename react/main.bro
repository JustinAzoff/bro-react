module React;

export {
    redef enum Log::ID += { LOG };

    type Action: enum {
        SHUNT_CONN,
        SHUNT_ORIG,
        SHUNT_RESP,
    };

    global do_shunt: hook(c: connection, action: Action);
    global shunt: function(c: connection, reason: string, action: Action);

    type Info: record {
        ## Time
        ts:          time            &log;
        ## Unique ID for the connection
        uid:         string          &log;
        ## The connection's 4-tuple of endpoint addresses/ports.
        id:          conn_id         &log;

        ## Why
        reason:      string          &log;

        ## The action taken
        action:      Action          &log;
    };

}

event bro_init()
{
    Log::create_stream(LOG, [$columns=Info]);
}

function shunt(c: connection, reason: string, action: Action)
{
    hook do_shunt(c, action);
    Log::write(LOG, [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $reason=reason,
        $action=action
    ]);
}
