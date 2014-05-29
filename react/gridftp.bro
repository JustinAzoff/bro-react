@load ./main
@load base/protocols/ftp/gridftp

event GridFTP::data_channel_detected(c: connection)
{
    local action = (c$orig$size > c$resp$size) ? React::SHUNT_ORIG : React::SHUNT_RESP;
    React::shunt(c, "gridftp", action);
}
