@load ./main

module React;

hook do_shunt(c: connection, action: Action)
{
    local id = c$id;
    local cmd = fmt("%s/filter-arista-dumbno.py", @DIR);
    local manager_ip = Cluster::nodes["manager"]$ip;
    local stdin = "";

    if(action == SHUNT_ORIG || action == SHUNT_CONN) {
        stdin = fmt("%s\n%s\n%s\n%s\n%s\n", manager_ip, id$orig_h, id$resp_h, id$orig_p, id$resp_p);
        when (local res_a = Exec::run([$cmd=cmd, $stdin=stdin])){
        }
    }
    if(action == SHUNT_RESP || action == SHUNT_CONN) {
        stdin = fmt("%s\n%s\n%s\n%s\n%s\n", manager_ip, id$resp_h, id$orig_h, id$resp_p, id$orig_p);
        when (local res_b = Exec::run([$cmd=cmd, $stdin=stdin])){
        }
    }
}
