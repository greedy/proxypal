-module(ppal_listener).
-behavior(supervisor_bridge).

-export([start_link/2]).
-export([init/1, terminate/2]).
-export([acceptor/2]).

start_link(ListenSocket, MasterRef) ->
    supervisor_bridge:start_link(?MODULE, [ListenSocket, MasterRef]).

init([ListenSocket, MasterRef]) ->
    Acceptor = spawn(?MODULE, acceptor, [ListenSocket, MasterRef]),
    {ok, Acceptor, ListenSocket}.

acceptor(ListenSocket, MasterRef) ->
    Accepted = gen_tcp:accept(ListenSocket),
    case Accepted of
        {ok, ClientSocket} ->
            ppal_master:new_client(MasterRef, ClientSocket);
        {error, Reason} ->
            exit({error, {accept_failed, Reason}})
    end,
    acceptor(ListenSocket, MasterRef).

terminate(_Reason, ListenSocket) ->
    gen_tcp:close(ListenSocket).
