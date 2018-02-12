-module(ppal_socks_session).
-behaviour(gen_statem).

-export([start_link/1]).
-export([init/1, callback_mode/0, handle_event/4,terminate/3]).

-record(data, {clientsocket, destsocket, clientdata = <<>>, nmethods = 0, addrlen = 0}).

-define(CMD_CONNECT, 1).
-define(CMD_BIND, 2).
-define(CMD_UDP_ASSOCIATE, 3).
-define(ATYP_IPV4, 1).
-define(ATYP_DOMAINNAME, 3).
-define(ATYP_IPV6, 4).
-define(REP_SUCCESS, 0).
-define(REP_GENERAL_FAILURE, 1).
-define(REP_NOT_ALLOWED, 2).
-define(REP_NET_UNREACH, 3).
-define(REP_HOST_UNREACH, 4).
-define(REP_CONN_REFUSED, 5).
-define(REP_TTL_EXPIRED, 6).
-define(REP_UNSUPPORTED_CMD, 7).
-define(REP_UNSUPPORTED_ATYP, 8).

start_link(ClientSocket) ->
    gen_statem:start_link(?MODULE, ClientSocket, []).

init(ClientSocket) ->
    inet:setopts(ClientSocket, [{active, once}]),
    {ok, {read_msg, version}, #data{clientsocket=ClientSocket},
     {state_timeout, 1000, []}
    }.

msg_length(version, _Data) -> 1;
msg_length(nmethods, _Data) -> 1;
msg_length(methods, Data) -> Data#data.nmethods;
msg_length(reqhdr, _Data) -> 4;
msg_length(addrlen, _Data) -> 1;
msg_length(dest, Data) -> Data#data.addrlen + 2.

callback_mode() ->
    [handle_event_function, state_enter].

next_msg(MsgType, Data) ->
    MsgLen = msg_length(MsgType, Data),
    case Data#data.clientdata of
        <<Msg:MsgLen/binary,Rest/binary>> ->
            {next_state, MsgType, Data#data{clientdata=Rest},
             {next_event, internal, {msg, Msg}}};
        _ ->
            {next_state, {read_msg, MsgType}, Data,
             {state_timeout, 1000, []}}
    end.

handle_event(info, {tcp, S, Pkt}, {read_msg, MsgType}, Data=#data{clientsocket=S}) ->
    OldData = Data#data.clientdata,
    NewData = <<OldData/binary, Pkt/binary>>,
    MsgLen = msg_length(MsgType, Data),
    case NewData of
        <<Msg:MsgLen/binary,Rest/binary>> ->
            {next_state, MsgType, Data#data{clientdata=Rest},
             {next_event, internal, {msg, Msg}}};
        _ ->
            inet:setopts(Data#data.clientsocket, [{active, once}]),
            {keep_state, Data#data{clientdata=NewData}}
    end;
handle_event(info, {tcp_closed, _S}, {read_msg, _}, _Data) ->
    stop;
handle_event(info, {tcp_error, _S, _Reason}, {read_msg, _}, _Data) ->
    stop;
handle_event(enter, _, {read_msg, _}, Data) ->
    inet:setopts(Data#data.clientsocket, [{active, once}]),
    keep_state_and_data;
handle_event(state_timeout, _, {read_msg, _}, Data) ->
    inet:setopts(Data#data.clientsocket, [{active, false}]),
    stop;
handle_event(internal, {msg, <<Version>>}, version, Data) ->
    if
        Version == 5 ->
            next_msg(nmethods, Data);
        true ->
            stop
    end;
handle_event(internal, {msg, <<NMethods>>}, nmethods, Data) ->
    next_msg(methods, Data#data{nmethods=NMethods});
handle_event(internal, {msg, Methods}, methods, Data) ->
    case binary:match(Methods, <<0>>) of
        nomatch ->
            gen_tcp:send(Data#data.clientsocket, <<5,16#ff>>),
            stop;
        _ ->
            gen_tcp:send(Data#data.clientsocket, <<5,0>>),
            next_msg(reqhdr, Data)
    end;
handle_event(internal, {msg, <<Ver, Cmd, Rsv, ATyp>>}, reqhdr, Data) ->
    Status = if
                 Ver /= 5; Rsv /= 0 ->
                     {error, ?REP_GENERAL_FAILURE};
                 Cmd /= ?CMD_CONNECT ->
                     {error, ?REP_UNSUPPORTED_CMD};
                 ATyp /= ?ATYP_DOMAINNAME ->
                     {error, ?REP_UNSUPPORTED_ATYP};
                 true ->
                     ok
             end,
    case Status of
        {error, Err} ->
            ErrPkt = socks_error_reply(Err),
            io:format("sending error ~p~n", [ErrPkt]),
            gen_tcp:send(Data#data.clientsocket, ErrPkt),
            stop;
        ok -> next_msg(addrlen, Data)
    end;
handle_event(internal, {msg, <<AddrLen>>}, addrlen, Data) ->
    next_msg(dest, Data#data{addrlen=AddrLen});
handle_event(internal, {msg, Msg}, dest, Data) ->
    AddrLen = Data#data.addrlen,
    <<DestHost:AddrLen/binary, DestPort:16>> = Msg,
    DestHostStr = binary:bin_to_list(DestHost),
    [Proxy|_] = ppal_proxylookup:proxies_for_connect(DestHostStr, DestPort),
    io:format("Proxying to ~p:~p via ~p~n", [DestHostStr,DestPort,Proxy]),
    ProxyResult = try
                 connect_via_proxy(Proxy, DestHostStr, DestPort)
             catch
                 throw:Throw -> Throw
             end,
    case ProxyResult of
        {ok,Sock} ->
            {ok, {OutAddr, OutPort}} = inet:sockname(Sock),
            {ATyp, BndAddr} = case OutAddr of
                                  {A,B,C,D} -> {?ATYP_IPV4, <<A,B,C,D>>};
                                  {A,B,C,D,E,F,G,H} ->
                                      {?ATYP_IPV6, <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>}
                              end,
            gen_tcp:send(Data#data.clientsocket,
                         socks_reply(?REP_SUCCESS, ATyp, BndAddr, OutPort)),
            {next_state, forward_data, Data#data{destsocket=Sock}};
        {error, econnrefused} ->
            send_socks_error(Data, ?ATYP_DOMAINNAME, <<AddrLen,DestHost/binary>>, DestPort, ?REP_CONN_REFUSED);
        {error, ehostunreach} ->
            send_socks_error(Data, ?ATYP_DOMAINNAME, <<AddrLen,DestHost/binary>>, DestPort, ?REP_HOST_UNREACH);
        {error, enetunreach} ->
            send_socks_error(Data, ?ATYP_DOMAINNAME, <<AddrLen,DestHost/binary>>, DestPort, ?REP_NET_UNREACH);
        {error, _} ->
            send_socks_error(Data, ?ATYP_DOMAINNAME, <<AddrLen,DestHost/binary>>, DestPort, ?REP_GENERAL_FAILURE)
    end;
handle_event(internal, {error_reply, Rep}, send_error, Data) ->
    gen_tcp:send(Data#data.clientsocket,
                 socks_error_reply(Rep)),
    stop;
handle_event(internal, {error_reply, Rep, ATyp, Addr, Port}, send_error, Data) ->
    gen_tcp:send(Data#data.clientsocket,
                 socks_reply(Rep, ATyp, Addr, Port)),
    stop;
handle_event(enter, _, forward_data, Data) ->
    inet:setopts(Data#data.clientsocket, [{active, once}]),
    inet:setopts(Data#data.destsocket, [{active, once}]),
    keep_state_and_data;
handle_event(info, {tcp, S, Pkt}, forward_data, Data) ->
    OutSock = if
                  S == Data#data.clientsocket ->
                      Data#data.destsocket;
                  S == Data#data.destsocket ->
                      Data#data.clientsocket
              end,
    inet:setopts(S, [{active, once}]),
    case gen_tcp:send(OutSock, Pkt) of 
        ok -> keep_state_and_data;
        {error, closed} -> stop
    end;
handle_event(info, E={tcp_error, _S, _Reason}, forward_data, _Data) ->
    {stop, E};
handle_event(info, {tcp_closed, _S}, forward_data, _Data) ->
    stop;
handle_event(enter, _, _, _Data) ->
    keep_state_and_data.

send_socks_error(Data, ATyp, Addr, Port, Rep) ->
    {next_state, send_error, Data,
     {next_event, internal, {error_reply, Rep, ATyp, Addr, Port}}}.

send_socks_error(Data, Rep) ->
    {next_state, send_error, Data,
     {next_event, internal, {error_reply, Rep}}}.

terminate(_Reason, dest, Data) ->
    gen_tcp:send(Data#data.clientsocket,
                 socks_error_reply(?REP_GENERAL_FAILURE)),
    gen_tcp:close(Data#data.clientsocket);
terminate(_Reason, _, Data) ->
    gen_tcp:close(Data#data.clientsocket),
    case Data#data.destsocket of 
        undefined -> ok;
        Sock -> gen_tcp:close(Sock)
    end.

socks_reply(Rep, Atyp, BndAddr, BndPort) ->
    <<5, Rep, 0, Atyp, BndAddr/binary, BndPort:16>>.

socks_error_reply(Rep) ->
    socks_reply(Rep, ?ATYP_IPV4, <<0, 0, 0, 0>>, 0).

port_or_default(PortStr, Default) ->
    if PortStr == "" -> Default;
       true -> list_to_integer(PortStr)
    end.

skip_headers(Sock) ->
    case gen_tcp:recv(Sock, 0) of
        R={ok, http_eoh} -> R;
        {ok, {http_header, _, _, _, _}} -> skip_headers(Sock)
    end.

connect_via_proxy(Proxy, DestHostStr, DestPort) ->
    Match = re:run(Proxy, "^(?<scheme>[[:alpha:]][[:alnum:]+.-]*)://((?<userinfo>[^@]+)@)?(?<authority>[^/:]*)(:(?<port>[[:digit:]]+))?",
                   [{capture, [scheme, userinfo, authority, port], list}]),
    {match, [Scheme, "", Host, Port]} = Match,
    case Scheme of
        "direct" ->
            gen_tcp:connect(DestHostStr, DestPort,
                            [binary, {active, false}]);
        "http" ->
            io:format("Connecting to proxy ~s:~b~n", [Host, port_or_default(Port, 80)]),
            Sock = case gen_tcp:connect(Host, port_or_default(Port, 80),
                                        [binary, {active, false}]) of
                       {ok, S} -> S;
                       Err -> throw(Err)
                   end,
            if DestPort == 443 ->
                   DestPortStr = integer_to_list(DestPort),
                   ConnectStr = [DestHostStr, ":", DestPortStr],
                   gen_tcp:send(Sock, ["CONNECT ", ConnectStr, " HTTP/1.1\r\nHost: ", ConnectStr, "\r\n\r\n"]),
                   inet:setopts(Sock, [{packet, http}]),
                   {ok, {http_response, _Version, HttpStatus, HttpMsg}} = gen_tcp:recv(Sock, 0),
                   {ok, http_eoh} = skip_headers(Sock),
                   if
                       HttpStatus div 100 == 2 ->
                           inet:setopts(Sock, [{packet, raw}, binary]),
                           {ok, Sock};
                       true ->
                           gen_tcp:close(Sock),
                           {error, {http_connect, HttpStatus, HttpMsg}}
                   end;
               true -> {ok, Sock}
            end
    end.
