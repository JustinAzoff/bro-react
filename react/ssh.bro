@load ./main
event SSH::heuristic_successful_login(c: connection)
{
    React::shunt(c, "ssh", React::SHUNT_CONN);
}
