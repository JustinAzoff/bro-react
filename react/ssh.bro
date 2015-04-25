@load ./main
event SSH::ssh_auth_successful(c: connection)
{
    React::shunt(c, "ssh", React::SHUNT_CONN);
}

event SSH::heuristic_successful_login(c: connection)
{
    React::shunt(c, "ssh", React::SHUNT_CONN);
}
