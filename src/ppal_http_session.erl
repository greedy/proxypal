-module(ppal_http_session).
-behavior(gen_statem).

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

read_start_line(enter, _OldState, #data{clientsocket=S}) ->
    keep_state_and_data;
read_start_line(info, own_socket, Data=#data{clientsocket=S}) ->
    inet:setopts(S, [{active, once}, binary, {packet, raw}]),
    keep_state_and_data;
read_start_line(info, {tcp, S, Pkt}, Data=#data{clientsocket=S}) ->
    NewPkt = <<(Data#data.clientdata)/binary, Pkt/binary>>,
    case erlang:decode_packet(http, NewPkt, []) of
        {ok, ParsedReq={http_request, _, _, _}, Rest} ->
            RawReq = part_before(NewPkt, Rest),
            {next_state, read_headers, Data#data{clientdata=(<<>>), req={RawReq,ParsedReq}},
             {next_event, info, {tcp, S, Rest}}};
        {more, _Length} ->
            inet:setopts(S, [{active, once}, {packet, raw}]),
            {keep_state, Data#data{clientdata=NewPkt}};
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
        {error, Reason} ->
            {stop, Reason}
    end.

portstr(undefined) -> "";
portstr(Num) -> [":", integer_to_list(Num)].

handle_request(Data=#data{req={_RawReq,ParsedReq}}) ->
    {http_request, _Method, Uri, _Version} = ParsedReq,
    {absoluteURI, Scheme, Host, Port, Path} = Uri,
    UrlStr = lists:flatten([atom_to_list(Scheme), "://", Host, portstr(Port), Path]),
    [FirstProxy|_Proxies] = ppal_proxylookup:proxies_for_url(UrlStr),
    {ok, ParsedProxy={ProxyScheme, _UserInfo, _Host, _Port}} = ppal_uri:parse_uri(FirstProxy),
    case ProxyScheme of
        "direct" -> direct_connect(Data);
        "http" -> http_connect(Data, ParsedProxy)
    end.

start_forwarding(Data, Socket) ->
    Actions = case Data#data.clientdata of
                  <<>> -> [];
                  Pkt -> [{next_event, info,
                           {tcp, Data#data.clientsocket, Pkt}}]
              end,
    R = {next_state, forward_data,Data#data{destsocket=Socket,
                                        clientdata=(<<>>)},
     Actions},
    io:format("Start forwarding ~p~n", [R]),
    R.

direct_connect(Data=#data{req={RawReq,ParsedReq},hdrs={RawHdrs,_}}) ->
    {http_request, _, {absoluteURI, Scheme, DestHost, ParsedPort, _Path}, _} = ParsedReq,
    Port = case {ParsedPort,Scheme} of
               {undefined, http} -> 80;
               {undefined, https} -> 443;
               _ -> ParsedPort
           end,
    case gen_tcp:connect(DestHost, Port,
                         [binary, {active, false}]) of
        {ok, Socket} ->
            % For now try sending the raw request
            ok = gen_tcp:send(Socket, RawReq),
            ok = gen_tcp:send(Socket, RawHdrs),
            ok = gen_tcp:send(Socket, "\r\n"),
            start_forwarding(Data, Socket);
        _Error ->
            {next_state, send_http_error, Data,
             {next_event, internal, {http_error, 500, "Internal Server Error", ""}}}
    end.

http_connect(Data, {http, ProxyUserInfo, ProxyHost, ProxyPort}) ->
    ActualPort = case ProxyPort of undefined -> 80; _ -> ProxyPort end,
    {RawReq, _} = Data#data.req,
    {RawHdrs, _} = Data#data.hdrs,
    case gen_tcp:connect(ProxyHost, ActualPort,
                         [binary, {active, false}]) of
        {ok, Socket} ->
            ok = gen_tcp:send(Socket, RawReq),
            ok = gen_tcp:send(Socket, RawHdrs),
            case ProxyUserInfo of
                undefined -> ok;
                _ -> ok = gen_tcp:send(Socket, ["Proxy-Authorization: Basic ",
                                                base64:encode(ProxyUserInfo),
                                                "\r\n"])
            end,
            ok = gen_tcp:send(Socket, "\r\n"),
            start_forwarding(Data, Socket);
        _Error ->
            {next_state, send_http_error, Data,
             {next_event, internal, {http_error, 500, "Internal Server Error", ""}}}
    end.

send_http_error(enter, _, _) -> keep_state_and_data;
send_http_error(internal, {http_error, Status, Msg, Body}, #data{clientsocket=S}) ->
    ok = gen_tcp:send(S, ["HTTP/1.1 ", integer_to_list(Status), " ", Msg, "\r\n"]),
    ok = gen_tcp:send(S, ["Content-Length: ", integer_to_list(iolist_size(Body)), "\r\n"]),
    ok = gen_tcp:send(S, "\r\n"),
    ok = gen_tcp:send(S, Body),
    stop.

forward_data(enter, _, #data{clientsocket=CS, destsocket=DS}) ->
    io:format("Beginning forwarding ~p <-> ~p~n", [CS,DS]),
    inet:setopts(CS, [{active, once}]),
    inet:setopts(DS, [{active, once}]),
    keep_state_and_data;
forward_data(info, {tcp, CS, Pkt}, #data{clientsocket=CS, destsocket=DS}) ->
    io:format("Forwarding client -> dest ~p~n", [Pkt]),
    ok = gen_tcp:send(DS, Pkt),
    repeat_state_and_data;
forward_data(info, {tcp, DS, Pkt}, #data{clientsocket=CS, destsocket=DS}) ->
    io:format("Forwarding dest -> client ~p~n", [Pkt]),
    ok = gen_tcp:send(CS, Pkt),
    repeat_state_and_data.

terminate(_Reason, _State, Data) ->
    gen_tcp:close(Data#data.clientsocket),
    case Data#data.destsocket of
        undefined -> ok;
        DS -> gen_tcp:close(DS)
    end.
