global tables: table[addr] of set[string] = table();

event http_entity_data(c:connection,is_orig:bool,length:count,data:string) 
{
	local srcip: addr = c$id$orig_h;
    if (c$http?$user_agent){
	local agent: string = c$http$user_agent;
        if (srcip in tables) 
        {
            add (tables[srcip])[agent];
        } 
        else 
        {
            tables[srcip] = set(agent);
        }
    }
}

event zeek_done() 
{
    for (ip in tables) 
    {
        if (|tables[ip]| >= 3) 
        {
            print(addr_to_uri(ip) +" is a proxy");
        }
    }
}
