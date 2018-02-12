-module(ppal_master).
-behaviour(supervisor).

-export([start_link/2]).
-export([init/1]).

-export([new_client/2]).

start_link(Name, Handler) ->
    supervisor:start_link(Name, ?MODULE, Handler).

init(Handler) ->
    {ok, {#{strategy => simple_one_for_one},
          [#{id => clientldr,
             start => {Handler, start_link, []},
             restart => temporary,
             type => worker}]}}.

new_client(Name, ClientSocket) ->
    Started = supervisor:start_child(Name, [ClientSocket]),
    case Started of
        {ok, Child} ->
            gen_tcp:controlling_process(ClientSocket, Child);
        {ok, Child, _Info} ->
            gen_tcp:controlling_process(ClientSocket, Child);
        _ -> ok
    end,
    Started.
