-module(ppal_sup).
-behaviour(supervisor).

-include("linux_socket.hrl").

-export([start_link/1]).
-export([init/1]).

-export([start_socks_listener/0, start_http_listener/0,
         start_http_tproxy_listener/0, start_https_tproxy_listener/0]).

start_link(Protocols) ->
    supervisor:start_link(ppal_sup,Protocols).

init(Protocols) ->
    error_logger:info_msg("Listen FDS is ~p; parsed: ~p~n", [os:getenv("LISTEN_FDNAMES"), sd_listen_fds_with_names()]),
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
       type => supervisor}];
protocol_specs(http_tproxy) ->
    [#{id => ppal_http_tproxy_master,
       start => {ppal_master, start_link, [{local, ppal_http_tproxy_master},
                                           ppal_http_tproxy_session]},
       type => supervisor},
     #{id => ppal_http_tproxy_listener,
       start => {?MODULE, start_http_tproxy_listener, []},
       type => supervisor}];
protocol_specs(https_tproxy) ->
    [#{id => ppal_https_tproxy_master,
       start => {ppal_master, start_link, [{local, ppal_https_tproxy_master},
                                           ppal_https_tproxy_session]},
       type => supervisor},
     #{id => ppal_https_tproxy_listener,
       start => {?MODULE, start_https_tproxy_listener, []},
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

index_proplist([], Result, _N) ->
    Result;
index_proplist([H|T], Result, N) ->
    index_proplist(T, [{H,N}|Result], N+1).

index_proplist(List, Result) ->
    index_proplist(List, Result, 1).

index_proplist(List) ->
    index_proplist(List, []).

sd_listen_fds_with_names() ->
    case os:getenv("LISTEN_FDNAMES") of
        false -> [];
        FdNames ->
            FdNamess = string:tokens(FdNames, ":"),
            index_proplist(FdNamess, [], 3)
    end.

start_http_tproxy_listener() ->
    {ok, ListenSocket} = case proplists:get_value("proxypal-tproxy-http.socket", sd_listen_fds_with_names()) of
                             undefined ->
                                 {ok, Port} = application:get_env(httptproxyport),
                                 gen_tcp:listen(Port, [binary,
                                                       {active, false},
                                                       {ip, any},
                                                       {reuseaddr, true},
                                                       {raw,?IPPROTO_IP,?IP_TRANSPARENT,?IntOpt(1)}]);
                             Fd ->
                                 error_logger:info_msg("Using existing fd ~p for http tproxy~n", [Fd]),
                                 gen_tcp:listen(0, [binary,
                                                    {active, false},
                                                    {fd, Fd}])
                         end,
    error_logger:info_msg("HTTP Transparent Proxy Listening on ~p.~n", [ListenSocket]),
    case inet:getopts(ListenSocket, [{raw,?IPPROTO_IP,?IP_TRANSPARENT,4}]) of
        {ok,[{raw,_,_,?IntOpt(1)}]} -> ppal_listener:start_link(ListenSocket, ppal_http_tproxy_master);
        _ -> ignore
    end.

start_https_tproxy_listener() ->
    {ok, ListenSocket} = case proplists:get_value("proxypal-tproxy-https.socket", sd_listen_fds_with_names()) of
                             undefined ->
                                 {ok, Port} = application:get_env(httpstproxyport),
                                 gen_tcp:listen(Port, [binary,
                                                       {active, false},
                                                       {ip, any},
                                                       {reuseaddr, true},
                                                       {raw,?IPPROTO_IP,?IP_TRANSPARENT,?IntOpt(1)}]);
                             Fd ->
                                 error_logger:info_msg("Using existing fd ~p for https tproxy~n", [Fd]),
                                 gen_tcp:listen(0, [binary,
                                                    {active, false},
                                                    {fd, Fd}])
                         end,
    case inet:getopts(ListenSocket, [{raw,?IPPROTO_IP,?IP_TRANSPARENT,4}]) of
        {ok,[{raw,_,_,?IntOpt(1)}]} -> ppal_listener:start_link(ListenSocket, ppal_https_tproxy_master);
        _ -> ignore
    end.
