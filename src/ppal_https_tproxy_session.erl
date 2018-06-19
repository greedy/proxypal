-module(ppal_https_tproxy_session).
-behavior(gen_statem).

-include("linux_socket.hrl").

-export([start_link/1]).
-export([init/1, callback_mode/0, terminate/3]).

-export([wait_for_proxy_response/3, read_resp_headers/3, forward_data/3,
         wait_for_socket_own/3]).

-record(data, {localsocket, remotesocket,
               remotedata = <<>>}).

start_link(ClientSocket) ->
    gen_statem:start_link(?MODULE, ClientSocket, []).

callback_mode() ->
    [state_functions, state_enter].

init(ClientSocket) ->
    {ok, wait_for_socket_own, #data{localsocket=ClientSocket, remotesocket=undefined}}.

wait_for_socket_own(enter, _, _) ->
    keep_state_and_data;
wait_for_socket_own(info, {tcp_closed, _}, _Data) ->
    stop;
wait_for_socket_own(info, own_socket, Data=#data{localsocket=ClientSocket}) ->
    {ok, {Ip, _Port}} = inet:sockname(ClientSocket),
    IpString = inet:ntoa(Ip),
    UrlStr = lists:flatten(["https://", IpString]),
    [FirstProxy|_Proxies] = ppal_proxylookup:proxies_for_url(UrlStr),
    {ok, ParsedProxy={ProxyScheme, _UserInfo, _Host, _PPort}} = ppal_uri:parse_uri(FirstProxy),
    case ProxyScheme of
        "direct" -> direct_connect(Data, Ip, 443);
        "http" -> http_connect(Data, Ip, 443, ParsedProxy)
    end.

direct_connect(Data, Ip, Port) ->
    {ok, Socket} = gen_tcp:connect(Ip, Port,
                                   [binary, {active, false}]),
    {next_state, forward_data, Data#data{remotesocket=Socket}}.

http_connect(Data, Ip, Port, {"http", ProxyUserInfo, ProxyHost, ProxyPort}) ->
    ProxyPortNum = case ProxyPort of undefined -> 80; _ -> list_to_integer(ProxyPort) end,
    {ok, Socket} = gen_tcp:connect(ProxyHost, ProxyPortNum,
                                   [binary, {active, false}]),
    ok = gen_tcp:send(Socket, ["CONNECT ", inet:ntoa(Ip), ":", integer_to_list(Port), " HTTP/1.1\r\n"]),
    case ProxyUserInfo of
        undefined -> ok;
        _ -> ok = gen_tcp:send(Socket, ["Proxy-Authorization: Basic ",
                                        base64:encode(ProxyUserInfo),
                                        "\r\n"])
    end,
    ok = gen_tcp:send(Socket, "\r\n"),
    {next_state, wait_for_proxy_response, Data#data{remotesocket=Socket}}.

wait_for_proxy_response(enter, _OldState, Data) ->
    inet:setopts(Data#data.remotesocket, [{active, once}, binary, {packet, raw}]),
    keep_state_and_data;
wait_for_proxy_response(info, {tcp_closed, _}, _Data) ->
    stop;
wait_for_proxy_response(info, {tcp, RemoteSocket, Pkt}, Data=#data{remotesocket=RemoteSocket}) ->
    NewPkt = <<(Data#data.remotedata)/binary, Pkt/binary>>,
    case erlang:decode_packet(http, NewPkt, []) of
        {ok, {http_response, _HttpVersion, 200, _Message}, Rest} ->
            {next_state, read_resp_headers, Data#data{remotedata=(<<>>)},
             {next_event, info, {tcp, RemoteSocket, Rest}}};
        {ok, {http_response, _HttpVersion, Status, Message}, _Rest} ->
            {stop, {proxy_connect_error, Status, Message}};
        {more, _Length} ->
            inet:setopts(RemoteSocket, [{active, once}, {packet, raw}]),
            {keep_state, Data#data{remotedata=NewPkt}};
        {error, Reason} ->
            {stop, Reason}
    end.

read_resp_headers(enter, _OldState, _Data) ->
    keep_state_and_data;
read_resp_headers(info, {tcp_closed, _}, _Data) ->
    stop;
read_resp_headers(info, {tcp, RemoteSocket, Pkt}, Data=#data{remotesocket=RemoteSocket}) ->
    NewPkt = <<(Data#data.remotedata)/binary, Pkt/binary>>,
    case erlang:decode_packet(httph, NewPkt, []) of
        {ok, http_eoh, Rest} ->
            {next_state, forward_data, Data#data{remotedata=(<<>>)},
             {next_event, info, {tcp, RemoteSocket, Rest}}};
        {ok, _Hdr, Rest} ->
            {keep_state, Data#data{remotedata=Rest}};
        {more, _Length} ->
            inet:setopts(RemoteSocket, [{active, once}, {packet, raw}]),
            {keep_state, Data#data{remotedata=NewPkt}};
        {error, Reason} ->
            {stop, Reason}
    end.

forward_data(enter, _, #data{localsocket=CS, remotesocket=DS}) ->
    inet:setopts(CS, [{active, once}]),
    inet:setopts(DS, [{active, once}]),
    keep_state_and_data;
forward_data(info, {tcp, CS, Pkt}, #data{localsocket=CS, remotesocket=DS}) ->
    ok = gen_tcp:send(DS, Pkt),
    repeat_state_and_data;
forward_data(info, {tcp, DS, Pkt}, #data{localsocket=CS, remotesocket=DS}) ->
    ok = gen_tcp:send(CS, Pkt),
    repeat_state_and_data;
forward_data(info, {tcp_closed, _}, _Data) ->
    stop.

terminate(_Reason, _State, Data) ->
    gen_tcp:close(Data#data.localsocket),
    case Data#data.remotesocket of
        undefined -> ok;
        DS -> gen_tcp:close(DS)
    end.
