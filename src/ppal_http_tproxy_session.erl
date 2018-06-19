-module(ppal_http_tproxy_session).
-behavior(gen_statem).

-include("linux_socket.hrl").

-export([start_link/1]).
-export([init/1, callback_mode/0, terminate/3]).
-export([read_start_line/3,read_headers/3,send_http_error/3,forward_data/3]).

-record(data, {clientsocket, clientdata = <<>>, 
               destsocket, req, hdrs={<<>>,[]}}).

start_link(ClientSocket) ->
    gen_statem:start_link(?MODULE, ClientSocket, []).

callback_mode() ->
    [state_functions, state_enter].

init(ClientSocket) ->
    {ok, read_start_line, #data{clientsocket=ClientSocket},
     {state_timeout, 1000, []}}.

part_before(Binary, Suffix) ->
    binary:part(Binary, 0, byte_size(Binary) - byte_size(Suffix)).

read_start_line(enter, _OldState, _Data) ->
    keep_state_and_data;
read_start_line(state_timeout, _Info, _Data) ->
    stop;
read_start_line(info, own_socket, #data{clientsocket=S}) ->
    inet:setopts(S, [{active, once}, binary, {packet, raw}]),
    keep_state_and_data;
read_start_line(info, {tcp, S, Pkt}, Data=#data{clientsocket=S}) ->
    NewPkt = <<(Data#data.clientdata)/binary, Pkt/binary>>,
    case erlang:decode_packet(http, NewPkt, []) of
        {ok, {http_request, "CONNECT", _, _}, _Rest} ->
            {ok, {Ip, _Port}} = inet:sockname(Data#data.clientsocket),
            direct_connect(Data#data{clientdata=Pkt}, Ip, 80);
        {ok, {http_request, _, {absoluteURI, _, _, _, _}, _}, _Rest} ->
            {ok, {Ip, _Port}} = inet:sockname(Data#data.clientsocket),
            direct_connect(Data#data{clientdata=Pkt}, Ip, 80);
        {ok, ParsedReq={http_request, _, {abs_path, _}, _}, Rest} ->
            RawReq = part_before(NewPkt, Rest),
            {next_state, read_headers, Data#data{clientdata=(<<>>), req={RawReq,ParsedReq}},
             {next_event, info, {tcp, S, Rest}}};
        {more, _Length} ->
            inet:setopts(S, [{active, once}, {packet, raw}]),
            {keep_state, Data#data{clientdata=NewPkt}};
        {http_error, _Unparsed} ->
            {stop, bad_start_line};
        {error, Reason} ->
            {stop, Reason}
    end.

read_headers(enter, _OldState, _Data) ->
    % read_start_line pumps this state with a synthetic tcp pkt
    % so no need to set the socket active
    keep_state_and_data;
read_headers(info, {tcp, S, Pkt},
             Data=#data{clientsocket=S, clientdata=CD, hdrs={RawHdrs, ParsedHdrs}})
->
    NewPkt = <<CD/binary, Pkt/binary>>,
    case erlang:decode_packet(httph, NewPkt, []) of
        {ok, ParsedHdr={http_header, _, _, _, _}, Rest} ->
            RawHdr = part_before(NewPkt, Rest),
            {next_state, read_headers, Data#data{clientdata=(<<>>),
                                                hdrs={<<RawHdrs/binary, RawHdr/binary>>,
                                                      [ParsedHdr|ParsedHdrs]}},
             {next_event, info, {tcp, S, Rest}}};
        {ok, http_eoh, Rest} ->
            handle_request(Data#data{clientdata=Rest,
                                     hdrs={RawHdrs, lists:reverse(ParsedHdrs)}});
        {more, _Length} ->
            inet:setopts(S, [{active, once}, {packet, raw}]),
            {keep_state, Data#data{clientdata=NewPkt}};
        {http_error, _Unparsed} ->
            {stop, bad_header};
        {error, Reason} ->
            {stop, Reason}
    end.

portstr(undefined) -> "";
portstr(Num) -> [":", integer_to_list(Num)].

normalize_connect_uri({scheme, Host, Port}) -> lists:flatten([Host, ":", Port]);
normalize_connect_uri(Str) when is_list(Str) -> Str.

handle_request(Data=#data{req={_RawReq,ParsedReq},hdrs={_RawHdrs,ParsedHdrs}}) ->
    {http_request, _Method, {abs_path, Path}, _Version} = ParsedReq,
    {ok, {Ip, _Port}} = inet:sockname(Data#data.clientsocket),
    % Look for the Host header
    UrlStr = case lists:keyfind('Host', 3, ParsedHdrs) of
        false -> 
            % Fall back to IP of socket
            case inet:ntoa(Ip) of
                IpString when is_list(IpString) ->
                    lists:flatten(["http://", IpString, Path])
            end;
        {http_header, _, 'Host', _, Host} ->
            lists:flatten(["http://", Host, Path])
    end,
    [FirstProxy|_Proxies] = ppal_proxylookup:proxies_for_url(UrlStr),
    {ok, ParsedProxy={ProxyScheme, _UserInfo, _Host, _Port}} = ppal_uri:parse_uri(FirstProxy),
    case ProxyScheme of
        "direct" -> direct_connect(Data, Ip, 80);
        "http" -> http_connect(Data, UrlStr, ParsedProxy)
    end.

start_forwarding(Data, Socket) ->
    Actions = case Data#data.clientdata of
                  <<>> -> [];
                  Pkt -> [{next_event, info,
                           {tcp, Data#data.clientsocket, Pkt}}]
              end,
    {next_state, forward_data,Data#data{destsocket=Socket,
                                        clientdata=(<<>>)},
     Actions}.

direct_connect(Data=#data{hdrs={RawHdrs,_ParsedHdrs}}, Ip, Port) ->
    {ok, Socket} = gen_tcp:connect(Ip, Port,
                                   [binary, {active, false},
                                    {raw, ?SOL_SOCKET, ?SO_MARK, ?IntOpt(101)}]),
    case Data#data.req of
        {RawReq, _ParsedReq} ->
            ok = gen_tcp:send(Socket, RawReq),
            ok = gen_tcp:send(Socket, RawHdrs),
            ok = gen_tcp:send(Socket, "\r\n");
        undefined ->
            ok
    end,
    start_forwarding(Data, Socket).

to_string(Atom) when is_atom(Atom) -> atom_to_list(Atom);
to_string(Other) -> Other.

http_connect(Data, UrlStr, {"http", ProxyUserInfo, ProxyHost, ProxyPort}) ->
    ActualPort = case ProxyPort of undefined -> 80; _ -> list_to_integer(ProxyPort) end,
    {_, {http_request, Method, _, _}} = Data#data.req,
    {RawHdrs, _} = Data#data.hdrs,
    case gen_tcp:connect(ProxyHost, ActualPort,
                         [binary, {active, false},
                          {raw, ?SOL_SOCKET, ?SO_MARK, ?IntOpt(101)}]) of
        {ok, Socket} ->
            error_logger:info_msg("Sending ~p~n", [[to_string(Method), " ", UrlStr, " HTTP/1.1\r\n"]]),
            ok = gen_tcp:send(Socket, [to_string(Method), " ", UrlStr, " HTTP/1.1\r\n"]),
            ok = gen_tcp:send(Socket, RawHdrs),
            case ProxyUserInfo of
                undefined -> ok;
                _ -> ok = gen_tcp:send(Socket, ["Proxy-Authorization: Basic ",
                                                base64:encode(ProxyUserInfo),
                                                "\r\n"])
            end,
            ok = gen_tcp:send(Socket, "\r\n"),
            start_forwarding(Data, Socket)
    end.

send_http_error(enter, _, _) -> keep_state_and_data;
send_http_error(internal, {http_error, Status, Msg, Body}, #data{clientsocket=S}) ->
    ok = gen_tcp:send(S, ["HTTP/1.1 ", integer_to_list(Status), " ", Msg, "\r\n"]),
    ok = gen_tcp:send(S, ["Content-Length: ", integer_to_list(iolist_size(Body)), "\r\n"]),
    ok = gen_tcp:send(S, "\r\n"),
    ok = gen_tcp:send(S, Body),
    stop.

forward_data(enter, _, #data{clientsocket=CS, destsocket=DS}) ->
    inet:setopts(CS, [{active, once}]),
    inet:setopts(DS, [{active, once}]),
    keep_state_and_data;
forward_data(info, {tcp, CS, Pkt}, #data{clientsocket=CS, destsocket=DS}) ->
    ok = gen_tcp:send(DS, Pkt),
    repeat_state_and_data;
forward_data(info, {tcp, DS, Pkt}, #data{clientsocket=CS, destsocket=DS}) ->
    ok = gen_tcp:send(CS, Pkt),
    repeat_state_and_data;
forward_data(info, {tcp_closed, _}, _Data) ->
    stop.

terminate(_Reason, _State, Data) ->
    gen_tcp:close(Data#data.clientsocket),
    case Data#data.destsocket of
        undefined -> ok;
        DS -> gen_tcp:close(DS)
    end.

