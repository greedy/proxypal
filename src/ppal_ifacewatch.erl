-module(ppal_ifacewatch).
-behaviour(gen_statem).

-export([start_link/0]).
-export([init/1,loop/3,callback_mode/0]).

start_link() ->
    gen_statem:start_link(?MODULE,[],[]).

callback_mode() ->
    state_functions.

iflist_to_addrs(Iflist) ->
    iflist_to_addrs(Iflist, sets:new()).

ifopt_to_addrs([{addr, Addr}|T], Addrs) ->
    ifopt_to_addrs(T, sets:add_element(Addr, Addrs));
ifopt_to_addrs([_|T], Addrs) ->
    ifopt_to_addrs(T, Addrs);
ifopt_to_addrs([], Addrs) ->
    Addrs.

iflist_to_addrs([{_Ifname, Ifopt}|T], Addrs) ->
    iflist_to_addrs(T, ifopt_to_addrs(Ifopt, Addrs));
iflist_to_addrs([], Addrs) ->
    Addrs.

init(_Args) ->
    case inet:getifaddrs() of
        {ok, Iflist} ->
            InitialAddrs = iflist_to_addrs(Iflist),
            {ok, loop, InitialAddrs,
             {{timeout, period}, 5000, []}};
        {error, Reason} ->
            {stop, {getifaddrs, Reason}}
    end.

loop({timeout, period}, _, OldAddrs) ->
    case inet:getifaddrs() of
        {ok, Iflist} ->
            CurrentAddrs = iflist_to_addrs(Iflist),
            NewAddrs = sets:subtract(CurrentAddrs, OldAddrs),
            LostAddrs = sets:subtract(OldAddrs, CurrentAddrs),
            NumAdded = sets:size(NewAddrs),
            NumLost = sets:size(LostAddrs),
            if
                NumAdded > 0; NumLost > 0 ->
                    ppal_proxylookup:reload();
                true ->
                    ok
            end,
            {keep_state, CurrentAddrs,
             {{timeout, period}, 5000, []}};
        {error, Reason} ->
            {keep_state_and_data,
             {{timeout, period}, 5000, []}}
    end.
