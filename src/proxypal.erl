-module(proxypal).
-behaviour(application).
-export([start/2, stop/1]).

start(normal, _Args) ->
    case application:get_env(proxypal, enabled_protocols, []) of
        [] -> {error, no_protocols};
        Protocols -> ppal_sup:start_link(Protocols)
    end.

stop(_State) ->
    ok.
