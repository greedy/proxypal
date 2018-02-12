-module(ppal_proxylookup).
-behavior(gen_server).

-export([start_link/0]).
-export([init/1,handle_call/3,handle_cast/2,terminate/2]).
-export([proxies_for_url/1,proxies_for_connect/2,reload/0,handle_info/2]).

-define(TIMEOUT,5*60*1000).

start_link() ->
    gen_server:start_link({local,?MODULE},?MODULE,[],[]).

open_cmd_port() ->
    Exe = filename:join([code:priv_dir(proxypal), "bin", "get_proxy"]),
    open_port({spawn_executable, Exe},
              [{packet, 2}, use_stdio]).

init(_Args) ->
    {ok,undefined}.

get_answer(Port, Results) ->
    receive
        {Port,{data,[]}} -> {ok, Results};
        {Port,{data,Proxy}} -> get_answer(Port, [Proxy|Results])
    after 5000 -> timeout
    end.

handle_call({proxies_for_url, Url}, _From, State) ->
    Port = case State of
               undefined -> open_cmd_port();
               _ -> State
           end,
    true = port_command(Port, [Url]),
    case get_answer(Port, []) of
        {ok, Proxies} -> {reply, Proxies, Port, ?TIMEOUT};
        timeout -> {stop, proxy_lookup_timeout, Port}
    end.

handle_cast(reload, State) ->
    NewPort = case State of
                  undefined -> undefined;
                  Port ->
                      port_close(Port),
                      open_cmd_port()
              end,
    {noreply, NewPort, ?TIMEOUT}.

handle_info(timeout, State) ->
    case State of
        undefined -> ok;
        Port -> port_close(Port)
    end,
    {noreply, undefined}.

proxies_for_url(Url) ->
    gen_server:call(?MODULE, {proxies_for_url, Url}).

proxies_for_connect(Host, Port) ->
    if
        Port == 80 ->
            proxies_for_url("http://" ++ Host);
        Port == 443 ->
            proxies_for_url("https://" ++ Host);
        true ->
            ["direct://"]
    end.

reload() ->
    gen_server:cast(?MODULE, reload).

terminate(_Reason, Port) ->
    port_close(Port).
