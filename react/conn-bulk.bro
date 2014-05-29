@load ./main
@load ../conn-bulk

event Bulk::connection_detected(c: connection)
{
    local action = (c$orig$size > c$resp$size) ? React::SHUNT_ORIG : React::SHUNT_RESP;
    React::shunt(c, "bulk", action);
}
