-module(ppal_sup).
-behaviour(supervisor).

-export([start_link/1]).
-export([init/1]).

-export([start_socks_listener/0, start_http_listener/0]).

start_link(Protocols) ->
    supervisor:start_link(ppal_sup,Protocols).

init(Protocols) ->
    PSpecs = lists:flatmap(fun protocol_specs/1, Protocols),
    {ok,
     {#{strategy => one_for_all},
      PSpecs ++
      [#{id => ppal_ifacewatch,
         start => {ppal_ifacewatch, start_link, []},
         type => worker},
       #{id => ppal_proxylookup,
         start => {ppal_proxylookup, start_link, []},
         type => worker}
      ]}}.

protocol_specs(socks) ->
    [#{id => ppal_socks_master,
       start => {ppal_master, start_link, [{local, ppal_socks_master},
                                           ppal_socks_session]},
       type => supervisor},
     #{id => ppal_socks_listener,
       start => {?MODULE, start_socks_listener, []},
       type => supervisor}];
protocol_specs(http) ->
    [#{id => ppal_http_master,
       start => {ppal_master, start_link, [{local, ppal_http_master},
                                           ppal_http_session]},
       type => supervisor},
     #{id => ppal_http_listener,
       start => {?MODULE, start_http_listener, []},
       type => supervisor}].


start_socks_listener() ->
    {ok, Port} = application:get_env(socksport),
    {ok, AddrStr} = application:get_env(listenaddr),
    {ok, Addr} = inet:parse_address(AddrStr),
    {ok, ListenSocket} = gen_tcp:listen(Port, [binary,
                                               {active, false},
                                               {ip, Addr},
                                               {reuseaddr, true}]),
    ppal_listener:start_link(ListenSocket, ppal_socks_master).

start_http_listener() ->
    {ok, Port} = application:get_env(httpport),
    {ok, AddrStr} = application:get_env(listenaddr),
    {ok, Addr} = inet:parse_address(AddrStr),
    {ok, ListenSocket} = gen_tcp:listen(Port, [binary,
                                               {active, false},
                                               {ip, Addr},
                                               {reuseaddr, true}]),
    ppal_listener:start_link(ListenSocket, ppal_http_master).
