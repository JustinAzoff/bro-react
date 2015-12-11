##! A detection script for Bulk Flows

@load base/protocols/conn

module Bulk;

export {
    ## Number of bytes transferred before marking a connection as bulk
    const size_threshold = 134217728 &redef; #128 megabytes

    ## Max number of times to check whether a connection's size exceeds the
    ## :bro:see:`Bulk::size_threshold`.
    const max_poll_count = 30 &redef;

    ## Base amount of time between checking whether a data connection
    ## has transferred more than :bro:see:`Bulk::size_threshold` bytes.
    const poll_interval_1 = 500msec &redef;
    const poll_interval_2 = 30sec &redef;

    ## Raised when a Bulk data channel is detected.
    ##
    ## c: The connection pertaining to the Bulk data channel.
    global connection_detected: event(c: connection);

    ## The initial criteria used to determine whether to start polling
    ## the connection for the :bro:see:`Bulk::size_threshold` to have
    ## been exceeded.
    ## c: The connection which may possibly be a Bulk data channel.
    ##
    ## Returns: true if the connection should be further polled for an
    ##          exceeded :bro:see:`Bulk::size_threshold`, else false.
    const bulk_initial_criteria: function(c: connection): bool &redef;

    type PortRange: record {
        ports:    set[port] &optional;
        port_min: port &default=1/tcp;
        port_max: port &default=65535/tcp;
    };
    const hosts: table[subnet] of PortRange = {[0.0.0.0/0] = PortRange()} &redef;
}

redef record Conn::Info += {
    bulk: bool &optional &default=F;
};

function size_callback(c: connection, cnt: count): interval
    {
    if ( c$orig$size > size_threshold || c$resp$size > size_threshold )
        {
        #c$conn$bulk = T;
        event Bulk::connection_detected(c);
        return -1sec;
        }

    if ( cnt >= max_poll_count )
        return -1sec;

    #at first delay for poll_interval_1, later for poll_interval_2
    return (cnt < max_poll_count/3) ? poll_interval_1 : poll_interval_2;
    }


function bulk_initial_criteria(c: connection): bool
    {
    local pr: PortRange;

    if(c$id$orig_h in hosts)
        pr = hosts[c$id$orig_h];
    else if(c$id$resp_h in hosts)
        pr = hosts[c$id$resp_h];
    else
        return F;

    if(pr?$ports) {
        return (c$id$resp_p in pr$ports);
    }

    return (pr$port_min <= c$id$resp_p && c$id$resp_p <= pr$port_max);
    }

event new_connection(c: connection) &priority=-3
    {
    if ( bulk_initial_criteria(c) )
        ConnPolling::watch(c, size_callback, 0, 0secs);
    }

event connection_state_remove(c: connection)
    {
    if(c$conn$bulk)
        return;
    if ( bulk_initial_criteria(c) && (c$orig$size > size_threshold || c$resp$size > size_threshold ))
        c$conn$bulk = T;
    }

event bro_init()
{
    Log::add_filter(Conn::LOG, [
        $name = "conn-bulk",
        $path = "conn_bulk",
        $pred(rec: Conn::Info) = {
            return rec$bulk;
        }
    ]);
}
